import { DynamoDBClient, GetItemCommand } from '@aws-sdk/client-dynamodb';

const dynamo       = new DynamoDBClient({ region: process.env.AWS_REGION ?? 'us-east-1' });
const TENANT_TABLE = process.env.TENANT_TABLE ?? 'auth0-provisioned-tenants';

function response(statusCode: number, body: unknown) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    body: JSON.stringify(body),
  };
}

export const handler = async (event: { pathParameters?: Record<string, string> }) => {
  const tenantId = event.pathParameters?.['tenantId'];
  if (!tenantId) return response(400, { error: 'Missing tenantId path parameter' });

  const result = await dynamo.send(new GetItemCommand({
    TableName: TENANT_TABLE,
    Key: { tenant_id: { S: tenantId } },
  }));

  if (!result.Item) return response(404, { error: 'Tenant not found' });

  const item = result.Item;
  return response(200, {
    tenant_id:        item['tenant_id']?.S,
    tenant_name:      item['tenant_name']?.S,
    domain:           item['domain']?.S,
    status:           item['status']?.S,
    created_at:       item['created_at']?.S,
    created_by_sub:   item['created_by_sub']?.S,
    created_by_email: item['created_by_email']?.S,
    ...(item['created_by_phone']?.S ? { created_by_phone: item['created_by_phone'].S } : {}),
    ...(item['error']?.S ? { error: item['error'].S } : {}),
  });
};
