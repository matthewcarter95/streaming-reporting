import { createRemoteJWKSet, jwtVerify } from 'jose';
import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb';

// ── Config from environment ───────────────────────────────────────────────────
// TRUSTED_ISSUERS: comma-separated list, e.g. "https://ciam.dvlysolutions.com/"
const TRUSTED_ISSUERS = (process.env.TRUSTED_ISSUERS ?? '').split(',').filter(Boolean);
const AUDIENCE        = process.env.AUTH0_AUDIENCE ?? 'api://metrics';
const REQUIRED_SCOPE  = 'view:usage';
const TABLE_NAME      = process.env.TENANT_MAPPING_TABLE ?? 'dvly-user-tenant-map';

// ── AWS SDK client (re-used across warm invocations) ─────────────────────────
const dynamo = new DynamoDBClient({ region: process.env.AWS_REGION ?? 'us-east-1' });

// ── JWKS cache (one RemoteJWKSet per issuer, persists across warm invocations) ─
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwks(issuer: string) {
  if (!jwksCache.has(issuer)) {
    // Auth0 JWKS endpoint lives at <issuer>.well-known/jwks.json
    // issuer always has a trailing slash, so URL resolution works correctly
    jwksCache.set(issuer, createRemoteJWKSet(new URL('.well-known/jwks.json', issuer)));
  }
  return jwksCache.get(issuer)!;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Returns true if the `scope` claim contains the required scope. */
function hasScope(claims: Record<string, unknown>, required: string): boolean {
  const scope = claims['scope'];
  if (typeof scope === 'string') return scope.split(' ').includes(required);
  if (Array.isArray(scope))     return scope.includes(required);
  return false;
}

/**
 * Returns all tenantId values for a given userId from DynamoDB.
 * First tries the Auth0 `sub` (canonical), then falls back to `email` claim.
 * This allows seeding test records by email before the real sub is known.
 * Returns an empty array when the user has no mappings.
 */
async function getTenantsForUser(userId: string, email?: string): Promise<string[]> {
  async function query(key: string): Promise<string[]> {
    const result = await dynamo.send(new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: 'userId = :uid',
      ExpressionAttributeValues: { ':uid': { S: key } },
      ProjectionExpression: 'tenantId',
    }));
    return (result.Items ?? []).map(item => item.tenantId?.S ?? '').filter(Boolean);
  }

  const bySubResult = await query(userId);
  if (bySubResult.length > 0) return bySubResult;

  // Fallback: look up by email (used during initial setup / testing)
  if (email) {
    const byEmailResult = await query(email);
    if (byEmailResult.length > 0) {
      console.log('[authorizer] resolved tenants via email fallback for sub:', userId);
      return byEmailResult;
    }
  }

  return [];
}

// ── Lambda handler ────────────────────────────────────────────────────────────

export const handler = async (event: { headers: Record<string, string> }) => {
  const authHeader = event.headers['authorization'] ?? event.headers['Authorization'] ?? '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();

  if (!token) {
    console.warn('[authorizer] no Bearer token');
    return { isAuthorized: false };
  }

  // Try each trusted issuer until one verifies the signature + audience
  let verifiedClaims: Record<string, unknown> | null = null;

  for (const issuer of TRUSTED_ISSUERS) {
    try {
      const { payload } = await jwtVerify(token, getJwks(issuer), {
        issuer,
        audience: AUDIENCE,
      });
      verifiedClaims = payload as Record<string, unknown>;
      console.log('[authorizer] PASS issuer:', issuer, 'sub:', payload.sub);
      break;
    } catch (err) {
      console.log('[authorizer] FAIL issuer:', issuer, (err as Error).message);
    }
  }

  if (!verifiedClaims) {
    console.warn('[authorizer] no issuer accepted the token');
    return { isAuthorized: false };
  }

  // ── Scope check ──────────────────────────────────────────────────────────────
  if (!hasScope(verifiedClaims, REQUIRED_SCOPE)) {
    console.warn('[authorizer] missing scope:', REQUIRED_SCOPE, '| got:', verifiedClaims['scope']);
    return { isAuthorized: false };
  }

  // ── Tenant resolution ────────────────────────────────────────────────────────
  const userId = verifiedClaims['sub'] as string;
  const email  = verifiedClaims['email'] as string | undefined;

  let tenantIds: string[];
  try {
    tenantIds = await getTenantsForUser(userId, email);
  } catch (err) {
    console.error('[authorizer] DynamoDB lookup failed:', (err as Error).message);
    return { isAuthorized: false };
  }

  if (tenantIds.length === 0) {
    console.warn('[authorizer] user has no mapped tenants:', userId);
    return { isAuthorized: false };
  }

  console.log('[authorizer] authorized userId:', userId, 'tenants:', tenantIds.join(','));

  // HTTP API Lambda authorizer SIMPLE response: context values must be strings
  return {
    isAuthorized: true,
    context: {
      userId,
      tenantIds: tenantIds.join(','), // comma-separated; reports Lambda splits this
    },
  };
};
