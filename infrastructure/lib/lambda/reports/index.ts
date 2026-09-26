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

const DATABASE = process.env.ATHENA_DATABASE ?? 'auth0_events';
const TABLE = process.env.ATHENA_TABLE ?? 'logs';
const WORKGROUP = process.env.ATHENA_WORKGROUP ?? 'auth0-analytics';
const RESULTS_BUCKET = process.env.S3_RESULTS_BUCKET!;
const TENANT_CLAIM = process.env.TENANT_CLAIM ?? 'org_id';
const DEFAULT_TENANT = process.env.DEFAULT_TENANT ?? 'dev-cs5j6vau';

// Tenant claim must be alphanumeric slugs only — validated before use in SQL
const SAFE_TENANT_RE = /^[a-zA-Z0-9_-]+$/;

interface RequestContext {
  authorizer?: {
    jwt?: {
      claims?: Record<string, string>;
    };
  };
}

interface LambdaEvent {
  rawPath?: string;
  requestContext?: RequestContext;
  queryStringParameters?: Record<string, string>;
}

function getTenantId(event: LambdaEvent): string {
  // Lambda authorizer context (new path)
  const lambdaCtx = (event.requestContext?.authorizer as Record<string, unknown> | undefined)?.lambda as Record<string, string> | undefined;
  if (lambdaCtx?.tenantId && SAFE_TENANT_RE.test(lambdaCtx.tenantId)) return lambdaCtx.tenantId;
  // Built-in JWT authorizer claims (legacy path, kept for direct invocation testing)
  const claims = event.requestContext?.authorizer?.jwt?.claims;
  const tenant = claims?.[TENANT_CLAIM] ?? claims?.['org_id'];
  if (tenant && SAFE_TENANT_RE.test(tenant)) return tenant;
  // Default — single-tenant mode
  return DEFAULT_TENANT;
}

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
  const range7 = lastNDaysRange(7);
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

function response(statusCode: number, body: unknown) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    body: JSON.stringify(body),
  };
}

export const handler = async (event: LambdaEvent) => {
  const tenantId = getTenantId(event);

  const days = parseInt(event.queryStringParameters?.days ?? '30', 10);
  const path = event.rawPath ?? '';

  try {
    if (path.endsWith('/reports/registrations')) {
      return response(200, { data: await registrationsReport(tenantId, days) });
    }
    if (path.endsWith('/reports/logins')) {
      return response(200, { data: await loginsReport(tenantId, days) });
    }
    if (path.endsWith('/reports/event-types')) {
      return response(200, { data: await eventTypesReport(tenantId, days) });
    }
    if (path.endsWith('/reports/active-users')) {
      return response(200, { data: await activeUsersReport(tenantId) });
    }
    return response(404, { error: 'Unknown report endpoint' });
  } catch (err) {
    console.error('Report error:', err);
    return response(500, { error: 'Query failed', detail: (err as Error).message });
  }
};
