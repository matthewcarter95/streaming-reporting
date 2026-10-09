import { createRemoteJWKSet, jwtVerify, decodeJwt } from 'jose';
import {
  SecretsManagerClient,
  CreateSecretCommand,
  GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';
import { DynamoDBClient, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { EventBridgeClient, PutEventsCommand } from '@aws-sdk/client-eventbridge';

const TRUSTED_ISSUERS        = (process.env.TRUSTED_ISSUERS ?? '').split(',').filter(Boolean);
const TEAMS_SLUG              = process.env.TEAMS_SLUG!;
const TEAMS_API_KEY_SECRET_ARN = process.env.TEAMS_API_KEY_SECRET_ARN!;
const DEFAULT_LOCALITY        = process.env.DEFAULT_LOCALITY ?? 'US-3';
const TEAMS_BASE              = `https://${TEAMS_SLUG}.teams.auth0.com`;

// Teams API requires admin_email to be an existing member of the team.
// Phone-only signups have no email claim, so we use a fixed team admin for now.
const TEAMS_ADMIN_EMAIL = 'matthew.keith.carter@gmail.com';

const region = process.env.AWS_REGION ?? 'us-east-1';
const secretsClient  = new SecretsManagerClient({ region });
const dynamoClient   = new DynamoDBClient({ region });
const ebClient       = new EventBridgeClient({ region });
const TENANT_TABLE   = process.env.TENANT_TABLE ?? 'auth0-provisioned-tenants';

// Full scope list confirmed working against strategic-teams-poc1
const ELEVATED_SCOPES = [
  'read:client_grants',  'update:client_grants',
  'read:clients',        'create:clients',        'update:clients',        'delete:clients',
  'read:client_keys',    'create:client_keys',    'update:client_keys',
  'read:connections',    'create:connections',    'update:connections',    'delete:connections',
  'read:connections_options', 'update:connections_options',
  'read:resource_servers','create:resource_servers','update:resource_servers',
  'read:actions',        'create:actions',        'update:actions',        'delete:actions',
  'read:triggers',       'update:triggers',
  'read:rules',          'create:rules',          'update:rules',          'delete:rules',
  'read:hooks',          'create:hooks',          'update:hooks',
  'read:logs',           'read:users',
  'read:tenant_settings', 'update:tenant_settings',
  'read:prompts',        'update:prompts',
  'read:branding',       'update:branding',
  'read:email_templates','update:email_templates',
  'read:email_provider', 'update:email_provider',
  'read:organizations',  'create:organizations',  'update:organizations',
  'read:log_streams',    'create:log_streams',    'update:log_streams',    'delete:log_streams',
  'read:portals',        'create:portals',        'update:portals',        'delete:portals',
  'read:forms',          'create:forms',          'update:forms',
];

// Cached across warm Lambda invocations — fetched once per cold start
let cachedApiKey: string | null = null;

async function getTeamsApiKey(): Promise<string> {
  if (cachedApiKey) return cachedApiKey;
  const res = await secretsClient.send(new GetSecretValueCommand({
    SecretId: TEAMS_API_KEY_SECRET_ARN,
  }));
  cachedApiKey = res.SecretString!;
  return cachedApiKey;
}

// JWKS cache — reused across warm invocations
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function getJwks(issuer: string) {
  if (!jwksCache.has(issuer)) {
    jwksCache.set(issuer, createRemoteJWKSet(new URL('.well-known/jwks.json', issuer)));
  }
  return jwksCache.get(issuer)!;
}

async function teamsAuth() {
  const apiKey = await getTeamsApiKey();
  return { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' };
}

interface TenantRequest {
  tenant_name?:     string;
  locality?:        string;
  environment_tag?: string;
}

interface ManagementClient {
  client_id:     string;
  client_secret: string;
}

interface CreatedTenant {
  tenant_id:         string;
  tenant_name:       string;
  domain:            string;
  management_client: ManagementClient;
}

async function createTenant(payload: {
  tenant_name?:     string;
  admin_email:      string;
  locality:         string;
  environment_tag:  string;
}): Promise<CreatedTenant> {
  const res = await fetch(`${TEAMS_BASE}/api/tenants`, {
    method: 'POST',
    headers: await teamsAuth(),
    body: JSON.stringify(payload),
  });
  const body = await res.json() as CreatedTenant & { status?: number; title?: string };
  if (res.status === 409) {
    const err = new Error(`Tenant name already exists`) as Error & { statusCode: number };
    err.statusCode = 409;
    throw err;
  }
  if (!res.ok) {
    throw new Error(`Create tenant failed ${res.status}: ${JSON.stringify(body)}`);
  }
  return body;
}

async function elevateManagementClient(domain: string, clientId: string, clientSecret: string) {
  // Bootstrap exchange with the two scopes Auth0 grants by default
  const tokenRes = await fetch(`https://${domain}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id:     clientId,
      client_secret: clientSecret,
      audience:      `https://${domain}/api/v2/`,
      grant_type:    'client_credentials',
    }),
  });
  const { access_token } = await tokenRes.json() as { access_token: string };

  // Find the client-grant to patch
  const grantsRes = await fetch(
    `https://${domain}/api/v2/client-grants?client_id=${encodeURIComponent(clientId)}`,
    { headers: { Authorization: `Bearer ${access_token}` } },
  );
  const grants = await grantsRes.json() as Array<{ id: string }>;
  if (!grants.length) throw new Error('No client-grant found to elevate');

  // Patch to full scope list
  const patchRes = await fetch(`https://${domain}/api/v2/client-grants/${grants[0].id}`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${access_token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ scope: ELEVATED_SCOPES }),
  });
  if (!patchRes.ok) {
    const body = await patchRes.text();
    throw new Error(`Grant elevation failed ${patchRes.status}: ${body}`);
  }
}

async function writeProvisioningStatus(
  tenantId: string, tenantName: string, domain: string,
  createdBySub: string, createdByEmail: string, createdByPhone?: string,
) {
  await dynamoClient.send(new PutItemCommand({
    TableName: TENANT_TABLE,
    Item: {
      tenant_id:        { S: tenantId },
      tenant_name:      { S: tenantName },
      domain:           { S: domain },
      status:           { S: 'provisioning' },
      created_by_sub:   { S: createdBySub },
      created_by_email: { S: createdByEmail },
      ...(createdByPhone ? { created_by_phone: { S: createdByPhone } } : {}),
      created_at:       { S: new Date().toISOString() },
    },
  }));
}

async function publishTenantProvisioned(tenantId: string, domain: string) {
  await ebClient.send(new PutEventsCommand({
    Entries: [{
      Source:       'auth0.provisioner',
      DetailType:   'tenant.provisioned',
      Detail:       JSON.stringify({ tenant_id: tenantId, domain }),
      EventBusName: 'default',
    }],
  }));
}

async function storeManagementClient(
  tenantId: string,
  tenantName: string,
  domain: string,
  mc: ManagementClient,
  createdBySub: string,
  createdByEmail: string,
  createdByPhone?: string,
) {
  await secretsClient.send(new CreateSecretCommand({
    Name: `auth0/tenants/${tenantId}`,
    Description: `Management API credentials for Auth0 tenant ${tenantName}`,
    SecretString: JSON.stringify({
      client_id:        mc.client_id,
      client_secret:    mc.client_secret,
      domain,
      tenant_name:      tenantName,
      created_by_sub:   createdBySub,
      created_by_email: createdByEmail,
      ...(createdByPhone ? { created_by_phone: createdByPhone } : {}),
      created_at:       new Date().toISOString(),
    }),
    Tags: [
      { Key: 'auth0-tenant-id',   Value: tenantId },
      { Key: 'auth0-tenant-name', Value: tenantName },
      // AWS tag values disallow '|' and other characters that can appear in Auth0 sub claims (e.g. "github|123")
      { Key: 'created-by',        Value: createdBySub.replace(/[^\w\s.:/=+\-@]/g, '-') },
    ],
  }));
}

function response(statusCode: number, body: unknown) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    body: JSON.stringify(body),
  };
}

interface LambdaEvent {
  headers:         Record<string, string>;
  body?:           string | null;
  requestContext?: unknown;
}

export const handler = async (event: LambdaEvent) => {
  // 1. Validate JWT and extract identity
  const authHeader = event.headers['authorization'] ?? event.headers['Authorization'] ?? '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) return response(401, { error: 'Missing Authorization header' });

  let sub: string | undefined;
  let email: string | undefined;
  let phone: string | undefined;
  let tokenIss: string | undefined;

  try {
    tokenIss = decodeJwt(token).iss;
  } catch {
    return response(401, { error: 'Invalid JWT' });
  }

  let verified = false;
  for (const issuer of TRUSTED_ISSUERS) {
    try {
      const { payload } = await jwtVerify(token, getJwks(issuer), { issuer });
      sub   = payload.sub;
      email = payload.email as string | undefined;
      phone = payload.phone_number as string | undefined;
      verified = true;
      break;
    } catch {
      continue;
    }
  }

  if (!verified || !sub) {
    return response(401, { error: `Untrusted issuer: ${tokenIss}` });
  }

  // 2. Parse request body
  let req: TenantRequest = {};
  try {
    if (event.body) req = JSON.parse(event.body);
  } catch {
    return response(400, { error: 'Invalid JSON body' });
  }

  const locality       = req.locality        ?? DEFAULT_LOCALITY;
  const environment_tag = req.environment_tag ?? 'development';

  try {
    // 3. Create tenant
    const tenant = await createTenant({
      ...(req.tenant_name ? { tenant_name: req.tenant_name } : {}),
      admin_email:    TEAMS_ADMIN_EMAIL,
      locality,
      environment_tag,
    });

    // 4. Store management credentials in Secrets Manager
    await storeManagementClient(
      tenant.tenant_id, tenant.tenant_name, tenant.domain,
      tenant.management_client, sub, email ?? TEAMS_ADMIN_EMAIL, phone,
    );

    // 5. Self-elevate management_client to full Terraform-level scopes
    await elevateManagementClient(
      tenant.domain, tenant.management_client.client_id, tenant.management_client.client_secret,
    );

    // 6. Write provisioning status to DynamoDB
    await writeProvisioningStatus(
      tenant.tenant_id, tenant.tenant_name, tenant.domain, sub, email ?? TEAMS_ADMIN_EMAIL, phone,
    );

    // 7. Publish event so configure Lambda can pick up async configuration
    await publishTenantProvisioned(tenant.tenant_id, tenant.domain);

    // 8. Return 202 — configuration continues asynchronously
    return response(202, {
      tenant_id:   tenant.tenant_id,
      tenant_name: tenant.tenant_name,
      domain:      tenant.domain,
      status:      'provisioning',
    });

  } catch (err) {
    const e = err as Error & { statusCode?: number };
    console.error('Provisioning error:', e.message);
    if (e.statusCode === 409) {
      return response(409, { error: e.message });
    }
    return response(500, { error: 'Tenant provisioning failed', detail: e.message });
  }
};
