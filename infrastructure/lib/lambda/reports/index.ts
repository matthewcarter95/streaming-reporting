import {
  AthenaClient,
  StartQueryExecutionCommand,
  GetQueryExecutionCommand,
  GetQueryResultsCommand,
  QueryExecutionState,
  type Datum,
  type Row,
} from '@aws-sdk/client-athena';

const athena = new AthenaClient({ region: process.env.AWS_REGION ?? 'us-east-1' });

const DATABASE   = process.env.ATHENA_DATABASE ?? 'auth0_events';
const TABLE      = process.env.ATHENA_TABLE ?? 'logs';
const WORKGROUP  = process.env.ATHENA_WORKGROUP ?? 'auth0-analytics';
const RESULTS_BUCKET = process.env.S3_RESULTS_BUCKET!;

// Only alphanumeric slugs and hyphens/underscores allowed in tenant names
// (they appear directly in SQL WHERE clauses)
const SAFE_TENANT_RE = /^[a-zA-Z0-9_-]+$/;

// ── Event shape ───────────────────────────────────────────────────────────────

interface AuthorizerContext {
  /** Comma-separated list of tenantIds the authenticated user is allowed to query */
  tenantIds?: string;
  userId?: string;
}

interface LambdaEvent {
  rawPath?: string;
  requestContext?: {
    authorizer?: {
      lambda?: AuthorizerContext;    // Lambda authorizer (new path)
      jwt?: { claims?: Record<string, string> }; // built-in JWT authorizer (legacy / test)
    };
  };
  queryStringParameters?: Record<string, string>;
}

// ── Tenant resolution ─────────────────────────────────────────────────────────

/**
 * Returns the set of tenant slugs the caller is allowed to query.
 * Source of truth is the `tenantIds` string injected by the Lambda authorizer.
 * Falls back to an empty array (which means 403) rather than a default tenant.
 */
function getAllowedTenants(event: LambdaEvent): string[] {
  const lambdaCtx = event.requestContext?.authorizer?.lambda;
  if (lambdaCtx?.tenantIds) {
    return lambdaCtx.tenantIds.split(',').map(t => t.trim()).filter(t => SAFE_TENANT_RE.test(t));
  }
  return [];
}

/**
 * Resolves the single tenant to query for this request.
 *
 * If the caller passes `?tenant=<slug>` it is validated against the allowed list.
 * If no `?tenant=` is given and the user has exactly one mapped tenant, that is used.
 * Otherwise we return a 400/403 error string (callers check `startsWith('ERROR:')`).
 */
function resolveTenant(event: LambdaEvent): { tenant: string } | { error: string; status: number } {
  const allowed = getAllowedTenants(event);

  if (allowed.length === 0) {
    return { error: 'No tenant access configured for this user', status: 403 };
  }

  const requested = event.queryStringParameters?.tenant?.trim();

  if (requested) {
    if (!SAFE_TENANT_RE.test(requested)) {
      return { error: 'Invalid tenant parameter', status: 400 };
    }
    if (!allowed.includes(requested)) {
      return { error: `Access denied to tenant: ${requested}`, status: 403 };
    }
    return { tenant: requested };
  }

  // No ?tenant= param — use the single allowed tenant or require explicit selection
  if (allowed.length === 1) return { tenant: allowed[0] };

  return {
    error: `Multiple tenants available; specify ?tenant= (one of: ${allowed.join(', ')})`,
    status: 400,
  };
}

// ── Athena helpers ────────────────────────────────────────────────────────────

async function runQuery(sql: string): Promise<Record<string, string>[]> {
  const start = await athena.send(new StartQueryExecutionCommand({
    QueryString: sql,
    WorkGroup: WORKGROUP,
    ResultConfiguration: {
      OutputLocation: `s3://${RESULTS_BUCKET}/athena-results/`,
    },
  }));

  const executionId = start.QueryExecutionId!;
  const deadline = Date.now() + 25_000;

  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 500));
    const status = await athena.send(new GetQueryExecutionCommand({ QueryExecutionId: executionId }));
    const state = status.QueryExecution?.Status?.State;

    if (state === QueryExecutionState.SUCCEEDED) break;
    if (state === QueryExecutionState.FAILED || state === QueryExecutionState.CANCELLED) {
      const reason = status.QueryExecution?.Status?.StateChangeReason ?? 'Query failed';
      throw new Error(reason);
    }
  }

  const results = await athena.send(new GetQueryResultsCommand({ QueryExecutionId: executionId }));
  const rows = results.ResultSet?.Rows ?? [];
  if (rows.length < 2) return [];

  const headers = rows[0].Data?.map((c: Datum) => c.VarCharValue ?? '') ?? [];
  return rows.slice(1).map((row: Row) => {
    const record: Record<string, string> = {};
    row.Data?.forEach((cell: Datum, i: number) => {
      record[headers[i]] = cell.VarCharValue ?? '';
    });
    return record;
  });
}

function lastNDaysRange(n: number): { yearFrom: number; monthFrom: number; dayFrom: number } {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return { yearFrom: d.getFullYear(), monthFrom: d.getMonth() + 1, dayFrom: d.getDate() };
}

// ── Report queries ────────────────────────────────────────────────────────────

async function registrationsReport(tenant: string, days = 30): Promise<Record<string, string>[]> {
  const { yearFrom, monthFrom } = lastNDaysRange(days);
  return runQuery(`
    SELECT DATE_FORMAT(from_iso8601_timestamp(event_timestamp), '%Y-%m-%d') AS date,
           COUNT(*) AS count
    FROM ${DATABASE}.${TABLE}
    WHERE tenant = '${tenant}'
      AND event_type = 'ss'
      AND (year > ${yearFrom} OR (year = ${yearFrom} AND month >= ${monthFrom}))
    GROUP BY 1
    ORDER BY 1 DESC
    LIMIT ${days}
  `);
}

async function loginsReport(tenant: string, days = 30): Promise<Record<string, string>[]> {
  const { yearFrom, monthFrom } = lastNDaysRange(days);
  return runQuery(`
    SELECT DATE_FORMAT(from_iso8601_timestamp(event_timestamp), '%Y-%m-%d') AS date,
           COUNT(CASE WHEN event_type = 's' THEN 1 END) AS success,
           COUNT(CASE WHEN event_type IN ('f', 'fu', 'fp', 'fc') THEN 1 END) AS failed
    FROM ${DATABASE}.${TABLE}
    WHERE tenant = '${tenant}'
      AND event_type IN ('s', 'f', 'fu', 'fp', 'fc')
      AND (year > ${yearFrom} OR (year = ${yearFrom} AND month >= ${monthFrom}))
    GROUP BY 1
    ORDER BY 1 DESC
    LIMIT ${days}
  `);
}

async function eventTypesReport(tenant: string, days = 30): Promise<Record<string, string>[]> {
  const { yearFrom, monthFrom } = lastNDaysRange(days);
  return runQuery(`
    SELECT event_type,
           COUNT(*) AS count
    FROM ${DATABASE}.${TABLE}
    WHERE tenant = '${tenant}'
      AND (year > ${yearFrom} OR (year = ${yearFrom} AND month >= ${monthFrom}))
    GROUP BY 1
    ORDER BY 2 DESC
    LIMIT 20
  `);
}

async function activeUsersReport(tenant: string): Promise<Record<string, string>[]> {
  const range7  = lastNDaysRange(7);
  const range30 = lastNDaysRange(30);
  return runQuery(`
    SELECT
      COUNT(DISTINCT CASE
        WHEN from_iso8601_timestamp(event_timestamp) >= DATE_ADD('day', -7, current_timestamp) THEN user_id
      END) AS active_7d,
      COUNT(DISTINCT CASE
        WHEN from_iso8601_timestamp(event_timestamp) >= DATE_ADD('day', -30, current_timestamp) THEN user_id
      END) AS active_30d
    FROM ${DATABASE}.${TABLE}
    WHERE tenant = '${tenant}'
      AND user_id <> ''
      AND (year > ${range30.yearFrom} OR (year = ${range30.yearFrom} AND month >= ${range30.monthFrom}))
      AND year >= ${range7.yearFrom}
  `);
}

// ── Response helper ───────────────────────────────────────────────────────────

function response(statusCode: number, body: unknown) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    body: JSON.stringify(body),
  };
}

// ── Handler ───────────────────────────────────────────────────────────────────

export const handler = async (event: LambdaEvent) => {
  const tenantResult = resolveTenant(event);

  if ('error' in tenantResult) {
    return response(tenantResult.status, { error: tenantResult.error });
  }

  const { tenant } = tenantResult;
  const days = Math.min(Math.max(parseInt(event.queryStringParameters?.days ?? '30', 10), 1), 365);
  const path = event.rawPath ?? '';

  try {
    if (path.endsWith('/reports/registrations')) {
      return response(200, { tenant, data: await registrationsReport(tenant, days) });
    }
    if (path.endsWith('/reports/logins')) {
      return response(200, { tenant, data: await loginsReport(tenant, days) });
    }
    if (path.endsWith('/reports/event-types')) {
      return response(200, { tenant, data: await eventTypesReport(tenant, days) });
    }
    if (path.endsWith('/reports/active-users')) {
      return response(200, { tenant, data: await activeUsersReport(tenant) });
    }
    return response(404, { error: 'Unknown report endpoint' });
  } catch (err) {
    console.error('Report error:', err);
    return response(500, { error: 'Query failed', detail: (err as Error).message });
  }
};
