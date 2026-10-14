import { createRemoteJWKSet, jwtVerify, decodeJwt } from 'jose';
import { DynamoDBClient, GetItemCommand } from '@aws-sdk/client-dynamodb';

// Mirrors authorizer/index.ts's static-issuer trust list — duplicated deliberately
// (not imported) so this new authorizer carries zero coupling/regression risk to
// the shared one, which keeps serving /tenants and /reports unchanged.
const TRUSTED_ISSUERS = (process.env.TRUSTED_ISSUERS ?? '').split(',').filter(Boolean);
const TENANT_TABLE = process.env.TENANT_TABLE ?? 'auth0-provisioned-tenants';
const region = process.env.AWS_REGION ?? 'us-east-1';

const dynamoClient = new DynamoDBClient({ region });

// JWKS sets are cached per issuer across warm Lambda invocations
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function getJwks(issuer: string) {
  if (!jwksCache.has(issuer)) {
    jwksCache.set(issuer, createRemoteJWKSet(new URL('.well-known/jwks.json', issuer)));
  }
  return jwksCache.get(issuer)!;
}

// Tenant domain lookups are cached per warm invocation — avoids a DynamoDB
// round trip on every request for the same tenant.
const tenantDomainCache = new Map<string, string | null>();

async function getTenantDomain(tenantId: string): Promise<string | null> {
  if (tenantDomainCache.has(tenantId)) return tenantDomainCache.get(tenantId)!;
  const res = await dynamoClient.send(new GetItemCommand({
    TableName: TENANT_TABLE,
    Key: { tenant_id: { S: tenantId } },
  }));
  const domain = res.Item?.['domain']?.S ?? null;
  tenantDomainCache.set(tenantId, domain);
  return domain;
}

function extractTenantId(rawPath: string | undefined): string | undefined {
  // /mcp/{tenantId} or /mcp/{tenantId}/.well-known/...
  const match = rawPath?.match(/^\/mcp\/([^/]+)/);
  return match?.[1];
}

export const handler = async (event: { headers: Record<string, string>; rawPath?: string }) => {
  const authHeader = event.headers['authorization'] ?? event.headers['Authorization'] ?? '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) return { isAuthorized: false };

  let tokenIss: string | undefined;
  try {
    tokenIss = decodeJwt(token).iss;
  } catch {
    console.error('[mcp-authorizer] failed to decode JWT');
    return { isAuthorized: false };
  }
  console.log('[mcp-authorizer] token iss:', tokenIss, '| trusted:', TRUSTED_ISSUERS.join(','));

  // 1. First-party: same static trust list as the shared authorizer.
  for (const issuer of TRUSTED_ISSUERS) {
    try {
      await jwtVerify(token, getJwks(issuer), { issuer });
      console.log('[mcp-authorizer] PASS first-party issuer:', issuer);
      return { isAuthorized: true };
    } catch (err) {
      console.error('[mcp-authorizer] FAIL first-party issuer:', issuer, (err as Error).message);
    }
  }

  // 2. Third-party fallback: verify against the target tenant's own Auth0 domain.
  const tenantId = extractTenantId(event.rawPath);
  if (!tenantId) {
    console.error('[mcp-authorizer] no tenantId in path:', event.rawPath);
    return { isAuthorized: false };
  }
  const tenantDomain = await getTenantDomain(tenantId);
  if (!tenantDomain) {
    console.error('[mcp-authorizer] no domain found for tenant:', tenantId);
    return { isAuthorized: false };
  }
  const tenantIssuer = `https://${tenantDomain}/`;
  try {
    await jwtVerify(token, getJwks(tenantIssuer), { issuer: tenantIssuer });
    console.log('[mcp-authorizer] PASS third-party tenant issuer:', tenantIssuer);
    return { isAuthorized: true };
  } catch (err) {
    console.error('[mcp-authorizer] FAIL third-party tenant issuer:', tenantIssuer, (err as Error).message);
  }

  return { isAuthorized: false };
};
