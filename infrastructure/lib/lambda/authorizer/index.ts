import { createRemoteJWKSet, jwtVerify, decodeJwt } from 'jose';

const TRUSTED_ISSUERS = (process.env.TRUSTED_ISSUERS ?? '').split(',').filter(Boolean);

// JWKS sets are cached per issuer across warm Lambda invocations
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwks(issuer: string) {
  if (!jwksCache.has(issuer)) {
    jwksCache.set(issuer, createRemoteJWKSet(new URL('.well-known/jwks.json', issuer)));
  }
  return jwksCache.get(issuer)!;
}

export const handler = async (event: { headers: Record<string, string> }) => {
  const authHeader = event.headers['authorization'] ?? event.headers['Authorization'] ?? '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) return { isAuthorized: false };

  let tokenIss: string | undefined;
  try {
    tokenIss = decodeJwt(token).iss;
  } catch {
    console.error('[authorizer] failed to decode JWT');
    return { isAuthorized: false };
  }
  console.log('[authorizer] token iss:', tokenIss, '| trusted:', TRUSTED_ISSUERS.join(','));

  for (const issuer of TRUSTED_ISSUERS) {
    try {
      await jwtVerify(token, getJwks(issuer), { issuer });
      console.log('[authorizer] PASS issuer:', issuer);
      return { isAuthorized: true };
    } catch (err) {
      console.error('[authorizer] FAIL issuer:', issuer, (err as Error).message);
    }
  }
  return { isAuthorized: false };
};
