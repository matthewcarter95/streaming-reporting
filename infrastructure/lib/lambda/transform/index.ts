interface FirehoseRecord {
  recordId: string;
  approximateArrivalTimestamp: number;
  data: string;
}

interface FirehoseEvent {
  invocationId: string;
  deliveryStreamArn: string;
  region: string;
  records: FirehoseRecord[];
}

interface FirehoseResult {
  recordId: string;
  result: 'Ok' | 'Dropped' | 'ProcessingFailed';
  data: string;
  metadata?: {
    partitionKeys: Record<string, string>;
  };
}

interface Auth0EventDetail {
  data?: {
    log_id?: string;
    type?: string;
    date?: string;
    connection?: string;
    client_id?: string;
    ip?: string;
    user_agent?: string;
    user_id?: string;
    user_name?: string;
    email?: string;
    hostname?: string;
  };
}

interface EventBridgeEvent {
  source: string;
  'detail-type': string;
  time: string;
  detail: Auth0EventDetail;
}

function extractTenantSlug(source: string, hostname?: string): string {
  // Prefer hostname when present: "dev-cs5j6vau.us.auth0.com" → "dev-cs5j6vau"
  if (hostname) {
    const slug = hostname.split('.')[0];
    if (slug && slug.length > 0) return slug;
  }
  // Source: "aws.partner/auth0.com/dev-cs5j6vau-<uuid>/auth0.logs"
  //   [0] = "aws.partner"  [1] = "auth0.com"  [2] = "dev-cs5j6vau-<uuid>"  [3] = "auth0.logs"
  const segment = source.split('/')[2] ?? '';
  // Strip the trailing "-<uuid>" (36 hex chars + 4 dashes + 1 separator hyphen = 37 chars)
  if (segment.length > 37) {
    return segment.slice(0, segment.length - 37);
  }
  return segment;
}

function normalizeRecord(event: EventBridgeEvent): Record<string, string> {
  const d = event.detail?.data ?? {};
  const tenant = extractTenantSlug(event.source, d.hostname);
  return {
    tenant,
    log_id: d.log_id ?? '',
    user_id: d.user_id ?? '',
    event_type: d.type ?? '',
    event_timestamp: d.date ?? event.time ?? '',
    user_agent: d.user_agent ?? '',
    ip_address: d.ip ?? '',
    email: d.user_name ?? d.email ?? '',
    client_id: d.client_id ?? '',
    connection: d.connection ?? '',
    hostname: d.hostname ?? '',
  };
}

export const handler = async (event: FirehoseEvent): Promise<{ records: FirehoseResult[] }> => {
  const results: FirehoseResult[] = event.records.map((record) => {
    try {
      const raw = Buffer.from(record.data, 'base64').toString('utf-8');
      const ebEvent: EventBridgeEvent = JSON.parse(raw);
      const normalized = normalizeRecord(ebEvent);
      const tenant = normalized.tenant || 'unknown';

      const encoded = Buffer.from(JSON.stringify(normalized) + '\n').toString('base64');

      return {
        recordId: record.recordId,
        result: 'Ok',
        data: encoded,
        metadata: {
          partitionKeys: { tenant },
        },
      };
    } catch {
      return {
        recordId: record.recordId,
        result: 'ProcessingFailed',
        data: record.data,
      };
    }
  });

  return { records: results };
};
