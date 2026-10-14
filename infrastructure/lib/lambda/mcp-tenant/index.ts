import { decodeJwt, createRemoteJWKSet, jwtVerify } from 'jose';
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

// Issuers trusted for the first-party (our own chatbot) path — same list the
// shared authorizer uses. Any other verified issuer is treated as third-party
// (a tenant's own Auth0 domain, reached via CIMD + enterprise federation).
const TRUSTED_ISSUERS = (process.env.TRUSTED_ISSUERS ?? '').split(',').filter(Boolean);
// Base URL of this API (e.g. https://xxxx.execute-api.us-east-1.amazonaws.com),
// used to build the canonical MCP resource URI and protected-resource metadata URL.
const API_BASE_URL = process.env.API_BASE_URL ?? '';
const MCP_ADMIN_CLAIM = 'https://auth0-tenant-mcp/mcp_admin';

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
  requestContext?: { domainName?: string; http?: { method?: string } };
}

function extractBearerToken(headers: Record<string, string>): string | undefined {
  const auth = headers['authorization'] ?? headers['Authorization'] ?? '';
  const match = auth.match(/^Bearer\s+(.+)$/i);
  return match?.[1];
}

// Function URL events share API Gateway's v2 payload shape but carry no
// pathParameters, so the tenantId is parsed from the raw path instead.
const MCP_PATH_RE = /^\/(?:\.well-known\/oauth-protected-resource\/)?mcp\/([^/]+)\/?$/;
const FUNCTION_URL_HOST_RE = /\.lambda-url\.[a-z0-9-]+\.on\.aws$/;

// Can't be an env var: a function's env can't reference its own Function URL
// (CloudFormation circular dependency), so derive it from the request.
function baseUrlFor(event: ApiGatewayV2Event, isFunctionUrl: boolean): string {
  return isFunctionUrl ? `https://${event.requestContext?.domainName}` : API_BASE_URL;
}

function wwwAuthenticateHeader(baseUrl: string, tenantId: string, error?: string): string {
  const parts = ['Bearer'];
  if (error) parts.push(`error="${error}"`);
  parts.push(`resource_metadata="${baseUrl}/.well-known/oauth-protected-resource/mcp/${tenantId}"`);
  return parts.join(' ');
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function getJwks(issuer: string) {
  if (!jwksCache.has(issuer)) {
    jwksCache.set(issuer, createRemoteJWKSet(new URL('.well-known/jwks.json', issuer)));
  }
  return jwksCache.get(issuer)!;
}

export const handler = async (event: ApiGatewayV2Event) => {
  const isFunctionUrl = FUNCTION_URL_HOST_RE.test(event.requestContext?.domainName ?? '');
  const tenantId = event.pathParameters?.['tenantId'] ?? event.rawPath?.match(MCP_PATH_RE)?.[1];
  if (!tenantId) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Missing tenantId path parameter' }) };
  }
  const baseUrl = baseUrlFor(event, isFunctionUrl);

  // Protected Resource Metadata (RFC 9728) — unauthenticated, served regardless
  // of the caller's token so OAuth/CIMD clients can discover the authorization
  // server before they have any credential.
  if (event.rawPath?.startsWith('/.well-known/oauth-protected-resource/')) {
    const tenant = await getTenantRecord(tenantId);
    if (!tenant?.domain) {
      return { statusCode: 404, body: JSON.stringify({ error: 'Tenant not found' }) };
    }
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        resource: `${baseUrl}/mcp/${tenantId}`,
        authorization_servers: [`https://${tenant.domain}/`],
      }),
    };
  }

  if (isFunctionUrl && event.requestContext?.http?.method !== 'POST') {
    return { statusCode: 405, headers: { Allow: 'POST' }, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  const headers = event.headers ?? {};
  const bearerToken = extractBearerToken(headers);
  if (!bearerToken) {
    return {
      statusCode: 401,
      headers: { 'WWW-Authenticate': wwwAuthenticateHeader(baseUrl, tenantId) },
      body: JSON.stringify({ error: 'Missing Authorization header' }),
    };
  }

  let claims: { sub?: string; iss?: string; aud?: string | string[]; [key: string]: unknown };
  try {
    claims = decodeJwt(bearerToken);
  } catch {
    return {
      statusCode: 401,
      headers: { 'WWW-Authenticate': wwwAuthenticateHeader(baseUrl, tenantId, 'invalid_token') },
      body: JSON.stringify({ error: 'Invalid JWT' }),
    };
  }

  const tenant = await getTenantRecord(tenantId);
  if (!tenant) {
    return { statusCode: 404, body: JSON.stringify({ error: 'Tenant not found' }) };
  }

  // Behind API Gateway the mcp-authorizer Lambda has already verified the token
  // signature/issuer. The Function URL has no authorizer, so verify here against
  // the tenant's own Auth0 issuer and this tenant's MCP resource audience.
  // First-party (trusted-issuer) tokens are not accepted on this path — the
  // chatbot goes through API Gateway.
  if (isFunctionUrl) {
    const tenantIssuer = `https://${tenant.domain}/`;
    try {
      await jwtVerify(bearerToken, getJwks(tenantIssuer), {
        issuer: tenantIssuer,
        audience: `${baseUrl}/mcp/${tenantId}`,
      });
    } catch (err) {
      console.error('Function URL token verification failed:', (err as Error).message);
      return {
        statusCode: 401,
        headers: { 'WWW-Authenticate': wwwAuthenticateHeader(baseUrl, tenantId, 'invalid_token') },
        body: JSON.stringify({ error: 'Invalid token' }),
      };
    }
  }

  const isFirstParty = !!claims.iss && TRUSTED_ISSUERS.includes(claims.iss);
  if (isFirstParty) {
    // First-party (our chatbot): unchanged ownership check.
    if (!claims.sub || tenant.created_by_sub !== claims.sub) {
      return { statusCode: 403, body: JSON.stringify({ error: 'Not authorized for this tenant' }) };
    }
  } else {
    // Third-party (e.g. Claude via CIMD + enterprise federation into the
    // tenant's own Auth0): require the mcp_admin custom claim set by the
    // post-login Action, and that the token was issued for this tenant's MCP
    // resource server.
    // The API identifier is the MCP URL itself: MCP clients send it as the
    // RFC 8707 `resource` parameter, taken from our protected-resource metadata.
    const resourceIdentifier = `${baseUrl}/mcp/${tenantId}`;
    const aud = claims.aud;
    const audMatches = Array.isArray(aud) ? aud.includes(resourceIdentifier) : aud === resourceIdentifier;
    if (!audMatches || claims[MCP_ADMIN_CLAIM] !== true) {
      console.warn('403 third-party token:', JSON.stringify({
        audMatches,
        expectedAud: resourceIdentifier,
        aud,
        hasMcpAdminClaim: claims[MCP_ADMIN_CLAIM] === true,
        azp: claims['azp'],
      }));
      return {
        statusCode: 403,
        headers: { 'WWW-Authenticate': wwwAuthenticateHeader(baseUrl, tenantId, 'insufficient_scope') },
        body: JSON.stringify({ error: 'Not authorized for this tenant' }),
      };
    }
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
