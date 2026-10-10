import { decodeJwt } from 'jose';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { ListToolsRequestSchema, CallToolRequestSchema, type CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { HANDLERS, getToolsForScopes } from '@auth0/auth0-mcp-server';
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import { DynamoDBClient, GetItemCommand } from '@aws-sdk/client-dynamodb';

// The OCI Vault reader comes from the dvly-oci-secrets Lambda layer and is
// intentionally not bundled (see externalModules in apiStack.ts). This ESM
// bundle gets a real `require` from the esbuild banner.
interface OciSecretsModule {
  configure(overrides: { privateKeyPem?: string }): void;
  getSecretByName(name: string): Promise<string>;
}
// eslint-disable-next-line @typescript-eslint/no-var-requires
const ociSecrets = require('dvly-oci-secrets') as OciSecretsModule;

const region = process.env.AWS_REGION ?? 'us-east-1';
const dynamoClient = new DynamoDBClient({ region });
const TENANT_TABLE = process.env.TENANT_TABLE ?? 'auth0-provisioned-tenants';
const OCI_KEY_SSM_NAME = process.env.OCI_KEY_SSM_NAME!;

// OCI secret name for a tenant's management_client credentials (see provision-tenant).
const tenantSecretName = (tenantId: string) => `auth0.tenants.${tenantId}`;

// Fetch the OCI signing key from SSM once per container and configure the layer.
let _ociReady: Promise<void> | null = null;
function initOci(): Promise<void> {
  if (!_ociReady) {
    _ociReady = (async () => {
      const ssm = new SSMClient({ region });
      const resp = await ssm.send(new GetParameterCommand({
        Name: OCI_KEY_SSM_NAME,
        WithDecryption: true,
      }));
      const privateKeyPem = Buffer.from(resp.Parameter?.Value ?? '', 'base64').toString('utf8');
      ociSecrets.configure({ privateKeyPem });
    })();
  }
  return _ociReady;
}

// Mirrors ELEVATED_SCOPES in provision-tenant/index.ts — every tenant's management
// client is granted exactly this scope set, so tool availability is the same for all.
const ELEVATED_SCOPES = [
  'read:client_grants', 'update:client_grants',
  'read:clients', 'create:clients', 'update:clients', 'delete:clients',
  'read:client_keys', 'create:client_keys', 'update:client_keys',
  'read:connections', 'create:connections', 'update:connections', 'delete:connections',
  'read:connections_options', 'update:connections_options',
  'read:resource_servers', 'create:resource_servers', 'update:resource_servers',
  'read:actions', 'create:actions', 'update:actions', 'delete:actions',
  'read:triggers', 'update:triggers',
  'read:rules', 'create:rules', 'update:rules', 'delete:rules',
  'read:hooks', 'create:hooks', 'update:hooks',
  'read:logs', 'read:users',
  'read:tenant_settings', 'update:tenant_settings',
  'read:prompts', 'update:prompts',
  'read:branding', 'update:branding',
  'read:email_templates', 'update:email_templates',
  'read:email_provider', 'update:email_provider',
  'read:organizations', 'create:organizations', 'update:organizations',
  'read:log_streams', 'create:log_streams', 'update:log_streams', 'delete:log_streams',
  'read:portals', 'create:portals', 'update:portals', 'delete:portals',
  'read:forms', 'create:forms', 'update:forms',
];

// Tools that write to local disk / are meaningless outside a local CLI context.
const LOCAL_ONLY_DENYLIST = new Set(['auth0_save_credentials_to_file']);

const AVAILABLE_TOOLS = getToolsForScopes(ELEVATED_SCOPES).filter(
  (tool) => !tool._meta?.localOnly && !LOCAL_ONLY_DENYLIST.has(tool.name),
);

interface ManagementClientSecret {
  client_id: string;
  client_secret: string;
  domain: string;
  tenant_name: string;
}

interface TenantRecord {
  created_by_sub?: string;
  domain?: string;
}

async function getTenantRecord(tenantId: string): Promise<TenantRecord | null> {
  const res = await dynamoClient.send(new GetItemCommand({
    TableName: TENANT_TABLE,
    Key: { tenant_id: { S: tenantId } },
  }));
  if (!res.Item) return null;
  return {
    created_by_sub: res.Item['created_by_sub']?.S,
    domain: res.Item['domain']?.S,
  };
}

async function getManagementClientSecret(tenantId: string): Promise<ManagementClientSecret> {
  await initOci();
  const value = await ociSecrets.getSecretByName(tenantSecretName(tenantId));
  return JSON.parse(value) as ManagementClientSecret;
}

// Cached per warm Lambda instance, keyed by tenant — avoids a token exchange on every call.
const tokenCache = new Map<string, { token: string; expiresAt: number }>();

async function getManagementToken(tenantId: string, mc: ManagementClientSecret): Promise<string> {
  const cached = tokenCache.get(tenantId);
  if (cached && cached.expiresAt > Date.now() + 30_000) return cached.token;

  const res = await fetch(`https://${mc.domain}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: mc.client_id,
      client_secret: mc.client_secret,
      audience: `https://${mc.domain}/api/v2/`,
      grant_type: 'client_credentials',
    }),
  });
  if (!res.ok) {
    throw new Error(`Token exchange failed ${res.status}: ${await res.text()}`);
  }
  const { access_token, expires_in } = await res.json() as { access_token: string; expires_in: number };
  tokenCache.set(tenantId, { token: access_token, expiresAt: Date.now() + expires_in * 1000 });
  return access_token;
}

function buildServer(managementToken: string, domain: string): Server {
  const server = new Server(
    { name: 'auth0-tenant-mcp', version: '1.0.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const sanitized = AVAILABLE_TOOLS.map(({ _meta, ...rest }) => rest);
    return { tools: sanitized };
  });

  // auth0-mcp-server's HandlerResponse ({content, isError}) is a valid MCP
  // CallToolResult; the installed SDK (1.32.x) resolved newer than the version
  // auth0-mcp-server (pinned to ^1.29.0) was built against, which added a
  // stricter result union (agentic-tasks support) — cast through unknown.
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const toolName = request.params.name;
    const tool = AVAILABLE_TOOLS.find((t) => t.name === toolName);
    const handler = HANDLERS[toolName];
    if (!tool || !handler) {
      throw new Error(`Unknown or restricted tool: ${toolName}`);
    }
    const result = await handler(
      { token: managementToken, parameters: request.params.arguments ?? {} },
      { domain },
    );
    return result as unknown as CallToolResult;
  });

  return server;
}

interface ApiGatewayV2Event {
  rawPath?: string;
  pathParameters?: Record<string, string>;
  headers?: Record<string, string>;
  body?: string;
  isBase64Encoded?: boolean;
}

function extractBearerToken(headers: Record<string, string>): string | undefined {
  const auth = headers['authorization'] ?? headers['Authorization'] ?? '';
  const match = auth.match(/^Bearer\s+(.+)$/i);
  return match?.[1];
}

export const handler = async (event: ApiGatewayV2Event) => {
  const tenantId = event.pathParameters?.['tenantId'];
  if (!tenantId) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Missing tenantId path parameter' }) };
  }

  const headers = event.headers ?? {};
  const bearerToken = extractBearerToken(headers);
  if (!bearerToken) {
    return { statusCode: 401, body: JSON.stringify({ error: 'Missing Authorization header' }) };
  }

  let callerSub: string | undefined;
  try {
    callerSub = decodeJwt(bearerToken).sub;
  } catch {
    return { statusCode: 401, body: JSON.stringify({ error: 'Invalid JWT' }) };
  }

  // Signature/issuer verification already happened in the shared Lambda authorizer
  // (Auth0LambdaAuthorizer) wired to this route in apiStack.ts — here we only need
  // the already-trusted token's claims to check tenant ownership.
  const tenant = await getTenantRecord(tenantId);
  if (!tenant) {
    return { statusCode: 404, body: JSON.stringify({ error: 'Tenant not found' }) };
  }
  if (!callerSub || tenant.created_by_sub !== callerSub) {
    return { statusCode: 403, body: JSON.stringify({ error: 'Not authorized for this tenant' }) };
  }

  let managementClient: ManagementClientSecret;
  let managementToken: string;
  try {
    managementClient = await getManagementClientSecret(tenantId);
    managementToken = await getManagementToken(tenantId, managementClient);
  } catch (err) {
    console.error('Failed to obtain management token:', (err as Error).message);
    return { statusCode: 502, body: JSON.stringify({ error: 'Failed to reach Auth0 Management API' }) };
  }

  const server = buildServer(managementToken, managementClient.domain);
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  await server.connect(transport);

  const bodyText = event.isBase64Encoded && event.body
    ? Buffer.from(event.body, 'base64').toString('utf-8')
    : event.body;

  // MCP's Streamable HTTP transport requires the client to accept both
  // application/json and text/event-stream — pass the caller's Accept header
  // through (falling back to both, since our own chatbot client may only send
  // application/json today).
  const accept = headers['accept'] ?? headers['Accept'] ?? 'application/json, text/event-stream';

  const request = new Request(`https://mcp.internal${event.rawPath ?? '/mcp'}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: accept },
    body: bodyText,
  });

  const response = await transport.handleRequest(request);
  const responseBody = await response.text();

  const responseHeaders: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    responseHeaders[key] = value;
  });

  return {
    statusCode: response.status,
    headers: responseHeaders,
    body: responseBody,
  };
};
