import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';
import { DynamoDBClient, UpdateItemCommand } from '@aws-sdk/client-dynamodb';

const region = process.env.AWS_REGION ?? 'us-east-1';
const secretsClient = new SecretsManagerClient({ region });
const dynamoClient  = new DynamoDBClient({ region });

const TENANT_TABLE                = process.env.TENANT_TABLE ?? 'auth0-provisioned-tenants';
const PERSONA_API_KEY_SECRET_ARN  = process.env.PERSONA_API_KEY_SECRET_ARN!;
const PERSONA_DOMAIN              = process.env.PERSONA_DOMAIN ?? 'withpersona.com';
const PERSONA_INQUIRY_TEMPLATE_ID = process.env.PERSONA_INQUIRY_TEMPLATE_ID!;
const EVENTBRIDGE_AWS_ACCOUNT_ID  = process.env.EVENTBRIDGE_AWS_ACCOUNT_ID ?? '223778538359';
const EVENTBRIDGE_AWS_REGION      = process.env.EVENTBRIDGE_AWS_REGION ?? 'us-east-1';

const PORTAL_APP_NAME = 'd-tenant-portal-app';
const PORTAL_NAME     = 'd-tenant-portal';
const PORTAL_SLUG     = 'd-tenant-portal';
const PASSKEY_OTP_CONNECTION_NAME = 'passkey-email-otp';

interface ManagementClientSecret {
  client_id:     string;
  client_secret: string;
  domain:        string;
  tenant_name:   string;
}

interface EventBridgeDetail {
  tenant_id: string;
  domain:    string;
}

// Cached across warm invocations — this tenant's secret never changes mid-flight
let cachedPersonaApiKey: string | null = null;

async function getPersonaApiKey(): Promise<string> {
  if (cachedPersonaApiKey) return cachedPersonaApiKey;
  const res = await secretsClient.send(new GetSecretValueCommand({
    SecretId: PERSONA_API_KEY_SECRET_ARN,
  }));
  cachedPersonaApiKey = res.SecretString!;
  return cachedPersonaApiKey;
}

async function getManagementClient(tenantId: string): Promise<ManagementClientSecret> {
  const res = await secretsClient.send(new GetSecretValueCommand({
    SecretId: `auth0/tenants/${tenantId}`,
  }));
  return JSON.parse(res.SecretString!) as ManagementClientSecret;
}

async function getAccessToken(domain: string, clientId: string, clientSecret: string): Promise<string> {
  const res = await fetch(`https://${domain}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id:     clientId,
      client_secret: clientSecret,
      audience:      `https://${domain}/api/v2/`,
      grant_type:    'client_credentials',
    }),
  });
  if (!res.ok) {
    throw new Error(`Token exchange failed ${res.status}: ${await res.text()}`);
  }
  const { access_token } = await res.json() as { access_token: string };
  return access_token;
}

function mgmtHeaders(accessToken: string) {
  return { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' };
}

async function findActionByName(domain: string, accessToken: string, name: string): Promise<string | undefined> {
  const res = await fetch(`https://${domain}/api/v2/actions/actions?triggerId=post-login`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) {
    throw new Error(`List actions failed ${res.status}: ${await res.text()}`);
  }
  const body = await res.json() as { actions: Array<{ id: string; name: string }> };
  return body.actions.find(a => a.name === name)?.id;
}

async function createAction(
  domain: string, accessToken: string,
  name: string, code: string, secrets: Array<{ name: string; value: string }>,
): Promise<string> {
  // Idempotent: a prior partial run may have already created this action.
  const existingId = await findActionByName(domain, accessToken, name);
  if (existingId) {
    await waitForActionBuilt(domain, accessToken, existingId, name);
    return existingId;
  }

  const res = await fetch(`https://${domain}/api/v2/actions/actions`, {
    method: 'POST',
    headers: mgmtHeaders(accessToken),
    body: JSON.stringify({
      name,
      supported_triggers: [{ id: 'post-login', version: 'v3' }],
      code,
      dependencies: [{ name: 'axios', version: '1.20.0' }],
      secrets,
      runtime: 'node18',
      deploy: true,
    }),
  });
  if (!res.ok) {
    throw new Error(`Create action "${name}" failed ${res.status}: ${await res.text()}`);
  }
  const body = await res.json() as { id: string };
  await waitForActionBuilt(domain, accessToken, body.id, name);
  return body.id;
}

// deploy:true on create triggers an async build — the action can't be bound
// to a trigger until its build finishes (status transitions pending/building -> built).
async function waitForActionBuilt(
  domain: string, accessToken: string, actionId: string, name: string,
): Promise<void> {
  const maxAttempts = 10;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const res = await fetch(`https://${domain}/api/v2/actions/actions/${actionId}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!res.ok) {
      throw new Error(`Check action "${name}" build status failed ${res.status}: ${await res.text()}`);
    }
    const action = await res.json() as { status: string };
    if (action.status === 'built') return;
    if (action.status === 'failed') {
      throw new Error(`Action "${name}" build failed`);
    }
    if (attempt < maxAttempts) {
      await new Promise(r => setTimeout(r, 2000));
    }
  }
  throw new Error(`Action "${name}" did not finish building in time`);
}

const PERSONA_INQUIRY_LOOKUP_CODE = `
const axios = require('axios');

exports.onExecutePostLogin = async (event, api) => {
  const inquiryId = event.user.app_metadata.personaInquiryId;
  if (!inquiryId) {
    console.log('No personaInquiryId on user; skipping Persona lookup.');
    return;
  }

  const domain = event.secrets.PERSONA_DOMAIN;
  const expectedTemplateId = event.secrets.PERSONA_INQUIRY_TEMPLATE_ID;

  const options = {
    headers: {
      'Accept': 'application/json',
      'Content-type': 'application/json',
      'Persona-Version': '2023-01-05',
      'Authorization': 'Bearer ' + event.secrets.PERSONA_API_KEY
    }
  };

  const inquiryUrl = 'https://' + domain + '/api/v1/inquiries/' + inquiryId;
  const inquiryResponse = await axios.get(inquiryUrl, options);
  const inquiry = inquiryResponse.data.data;

  const actualTemplateId = inquiry.relationships['inquiry-template']
    && inquiry.relationships['inquiry-template'].data
    && inquiry.relationships['inquiry-template'].data.id;

  if (expectedTemplateId && actualTemplateId !== expectedTemplateId) {
    console.log(
      'Inquiry template mismatch. expected=' + expectedTemplateId + ' actual=' + actualTemplateId
    );
    api.user.setAppMetadata('PersonaInquiryTemplateMismatch', true);
    return;
  }

  const verificationData = inquiry.relationships.verifications
    && inquiry.relationships.verifications.data;

  if (verificationData && verificationData.length > 0) {
    api.user.setAppMetadata('GovDataUsed', verificationData);
  } else {
    api.user.setAppMetadata('GovDataUsed', 'NONE');
  }

  const accountId = inquiry.relationships.account
    && inquiry.relationships.account.data
    && inquiry.relationships.account.data.id;

  if (accountId) {
    api.user.setAppMetadata('PersonaAccountId', accountId);
  }
};
`;

const PERSONA_ACCOUNT_SYNC_CODE = `
const axios = require('axios');

exports.onExecutePostLogin = async (event, api) => {
  const accountId = event.user.app_metadata.PersonaAccountId;
  if (!accountId) {
    console.log('No PersonaAccountId on user; skipping Persona account sync.');
    return;
  }

  const domain = event.secrets.PERSONA_DOMAIN;
  const url = 'https://' + domain + '/api/v1/accounts/' + accountId;

  const options = {
    headers: {
      'Accept': 'application/json',
      'Content-type': 'application/json',
      'Persona-Version': '2023-01-05',
      'Authorization': 'Bearer ' + event.secrets.PERSONA_API_KEY
    }
  };

  const attributes = {
    'name-first': event.user.given_name,
    'name-last': event.user.family_name,
    'email-address': event.user.email
  };

  const data = {
    data: {
      attributes: attributes
    }
  };

  await axios.patch(url, data, options);
};
`;

async function createPersonaActionsAndBind(domain: string, accessToken: string, personaApiKey: string) {
  const inquiryLookupId = await createAction(
    domain, accessToken, 'Persona Inquiry Lookup', PERSONA_INQUIRY_LOOKUP_CODE,
    [
      { name: 'PERSONA_API_KEY', value: personaApiKey },
      { name: 'PERSONA_DOMAIN', value: PERSONA_DOMAIN },
      { name: 'PERSONA_INQUIRY_TEMPLATE_ID', value: PERSONA_INQUIRY_TEMPLATE_ID },
    ],
  );

  const accountSyncId = await createAction(
    domain, accessToken, 'Persona Account Sync', PERSONA_ACCOUNT_SYNC_CODE,
    [
      { name: 'PERSONA_API_KEY', value: personaApiKey },
      { name: 'PERSONA_DOMAIN', value: PERSONA_DOMAIN },
    ],
  );

  const bindRes = await fetch(`https://${domain}/api/v2/actions/triggers/post-login/bindings`, {
    method: 'PATCH',
    headers: mgmtHeaders(accessToken),
    body: JSON.stringify({
      bindings: [
        { ref: { type: 'action_id', value: inquiryLookupId }, display_name: 'Persona Inquiry Lookup' },
        { ref: { type: 'action_id', value: accountSyncId },   display_name: 'Persona Account Sync' },
      ],
    }),
  });
  if (!bindRes.ok) {
    throw new Error(`Post-login trigger binding failed ${bindRes.status}: ${await bindRes.text()}`);
  }
}

const PASSKEY_OTP_CONNECTION_OPTIONS = {
  enabled_database_customization: false,
  brute_force_protection:         true,
  import_mode:                   false,
  disable_signup:                false,
  strategy_version:               2,

  password_policy: 'fair',
  password_complexity_options: { min_length: 15 },
  password_history:   { enable: false, size: 5 },
  password_dictionary: { enable: false },

  mfa: { active: true, return_enroll_settings: true },

  passkey_options: {
    challenge_ui:                   'both',
    local_enrollment_enabled:       true,
    progressive_enrollment_enabled: true,
  },

  // email_otp omitted: requires a tenant-level Early Access feature not
  // enabled on freshly-created tenants ("OTP authentication methods feature
  // is not supported for this connection"). Passkey + password only for now.
  authentication_methods: {
    passkey:  { enabled: true },
    password: { enabled: true, api_behavior: 'required', signup_behavior: 'allow' },
  },

  attributes: {
    email: {
      identifier: { active: true },
      profile_required:    true,
      unique:               true,
      verification_method: 'link',
      signup: {
        status: 'required',
        verification: { active: true },
      },
    },
  },
};

async function findConnectionByName(domain: string, accessToken: string, name: string): Promise<string | undefined> {
  const res = await fetch(`https://${domain}/api/v2/connections?name=${encodeURIComponent(name)}&strategy=auth0`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) {
    throw new Error(`List connections failed ${res.status}: ${await res.text()}`);
  }
  const conns = await res.json() as Array<{ id: string }>;
  return conns[0]?.id;
}

async function createPasskeyOtpConnection(domain: string, accessToken: string): Promise<string> {
  // Idempotent: a prior partial run may have already created this connection.
  const existingId = await findConnectionByName(domain, accessToken, PASSKEY_OTP_CONNECTION_NAME);
  if (existingId) return existingId;

  const body = JSON.stringify({
    name:     PASSKEY_OTP_CONNECTION_NAME,
    strategy: 'auth0',
    options:  PASSKEY_OTP_CONNECTION_OPTIONS,
  });

  const maxAttempts = 3;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const res = await fetch(`https://${domain}/api/v2/connections`, {
      method: 'POST',
      headers: mgmtHeaders(accessToken),
      body,
    });
    if (res.ok) {
      const created = await res.json() as { id: string };
      return created.id;
    }
    if (res.status === 409 && attempt < maxAttempts) {
      await new Promise(r => setTimeout(r, 3000));
      continue;
    }
    throw new Error(`Create connection failed ${res.status}: ${await res.text()}`);
  }
  throw new Error('Create connection failed: exhausted retries');
}

const LOG_STREAM_NAME = 'EventBridge - Auth Events';

async function createLogStream(domain: string, accessToken: string) {
  // Auth0 allows duplicate-named log streams, so guard against piling up
  // duplicates on retry by checking for an existing one first.
  const existingRes = await fetch(`https://${domain}/api/v2/log-streams`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!existingRes.ok) {
    throw new Error(`List log streams failed ${existingRes.status}: ${await existingRes.text()}`);
  }
  const existing = await existingRes.json() as Array<{ name: string }>;
  if (existing.some(s => s.name === LOG_STREAM_NAME)) return;

  const res = await fetch(`https://${domain}/api/v2/log-streams`, {
    method: 'POST',
    headers: mgmtHeaders(accessToken),
    body: JSON.stringify({
      name: LOG_STREAM_NAME,
      type: 'eventbridge',
      sink: {
        awsAccountId: EVENTBRIDGE_AWS_ACCOUNT_ID,
        awsRegion:    EVENTBRIDGE_AWS_REGION,
      },
      filters: [
        { type: 'category', name: 'auth.login.success' },
        { type: 'category', name: 'auth.login.fail' },
        { type: 'category', name: 'auth.signup.success' },
        { type: 'category', name: 'auth.signup.fail' },
        { type: 'category', name: 'auth.silent_auth.success' },
        { type: 'category', name: 'auth.silent_auth.fail' },
      ],
    }),
  });
  if (!res.ok) {
    throw new Error(`Create log stream failed ${res.status}: ${await res.text()}`);
  }
}

async function updatePromptSettings(domain: string, accessToken: string) {
  const res = await fetch(`https://${domain}/api/v2/prompts`, {
    method: 'PATCH',
    headers: mgmtHeaders(accessToken),
    body: JSON.stringify({
      universal_login_experience: 'new',
      identifier_first:           true,
    }),
  });
  if (!res.ok) {
    throw new Error(`Update prompt settings failed ${res.status}: ${await res.text()}`);
  }
}

async function createPortal(domain: string, accessToken: string, passkeyConnectionId: string) {
  // Backing Regular Web App client for the portal
  const clientRes = await fetch(`https://${domain}/api/v2/clients`, {
    method: 'POST',
    headers: mgmtHeaders(accessToken),
    body: JSON.stringify({
      name:     PORTAL_APP_NAME,
      app_type: 'regular_web',
      callbacks:            [`https://${domain}/portals/auth/callback`],
      allowed_logout_urls:  [`https://${domain}/portals/`],
      token_endpoint_auth_method: 'client_secret_post',
    }),
  });
  if (!clientRes.ok) {
    throw new Error(`Create portal client failed ${clientRes.status}: ${await clientRes.text()}`);
  }
  const client = await clientRes.json() as { client_id: string; client_secret?: string };

  let portalClientSecret = client.client_secret;
  if (!portalClientSecret) {
    const credsRes = await fetch(`https://${domain}/api/v2/clients/${client.client_id}/credentials`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!credsRes.ok) {
      throw new Error(`Read portal client credentials failed ${credsRes.status}: ${await credsRes.text()}`);
    }
    const creds = await credsRes.json() as Array<{ client_secret?: string }>;
    portalClientSecret = creds[0]?.client_secret;
  }
  if (!portalClientSecret) {
    throw new Error('Portal client secret unavailable after creation');
  }

  // Portal shell
  const portalRes = await fetch(`https://${domain}/api/v2/portals`, {
    method: 'POST',
    headers: mgmtHeaders(accessToken),
    body: JSON.stringify({
      name: PORTAL_NAME,
      slug: PORTAL_SLUG,
      client: {
        client_id:     client.client_id,
        client_secret: portalClientSecret,
        token_endpoint_auth_method: 'client_secret_post',
      },
    }),
  });
  if (!portalRes.ok) {
    throw new Error(`Create portal failed ${portalRes.status}: ${await portalRes.text()}`);
  }
  const portal = await portalRes.json() as { id: string };

  // Blank page
  const pageRes = await fetch(`https://${domain}/api/v2/portals/${portal.id}`, {
    method: 'PATCH',
    headers: mgmtHeaders(accessToken),
    body: JSON.stringify({
      pages: {
        default:  'blank',
        standard: [{ slug: 'blank', title: 'Blank' }],
      },
    }),
  });
  if (!pageRes.ok) {
    throw new Error(`Create portal page failed ${pageRes.status}: ${await pageRes.text()}`);
  }

  // Enable the passkey/OTP connection for the portal client
  const enableConnRes = await fetch(`https://${domain}/api/v2/connections/${passkeyConnectionId}/clients`, {
    method: 'PATCH',
    headers: mgmtHeaders(accessToken),
    body: JSON.stringify({ enabled_clients: [client.client_id] }),
  });
  if (!enableConnRes.ok) {
    throw new Error(`Enable passkey connection for portal client failed ${enableConnRes.status}: ${await enableConnRes.text()}`);
  }

  // Disable the tenant's default DB connection for the portal client only — looked up by name,
  // never hardcoded, since each fresh tenant gets a different connection ID.
  const defaultConnRes = await fetch(
    `https://${domain}/api/v2/connections?name=Username-Password-Authentication&strategy=auth0`,
    { headers: { Authorization: `Bearer ${accessToken}` } },
  );
  if (!defaultConnRes.ok) {
    throw new Error(`Lookup default connection failed ${defaultConnRes.status}: ${await defaultConnRes.text()}`);
  }
  const defaultConns = await defaultConnRes.json() as Array<{ id: string }>;
  const defaultConnId = defaultConns[0]?.id;
  if (defaultConnId) {
    const disableRes = await fetch(`https://${domain}/api/v2/clients/${client.client_id}/connections/${defaultConnId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!disableRes.ok && disableRes.status !== 404) {
      throw new Error(`Disable default connection for portal client failed ${disableRes.status}: ${await disableRes.text()}`);
    }
  }
}

async function markTenantStatus(
  tenantId: string, status: 'ready' | 'failed', error?: string, warning?: string,
) {
  const names: Record<string, string> = { '#status': 'status' };
  const values: Record<string, { S: string }> = {
    ':status':       { S: status },
    ':configuredAt': { S: new Date().toISOString() },
  };
  const setParts = ['#status = :status', 'configured_at = :configuredAt'];
  const removeParts: string[] = [];

  if (error) {
    names['#error'] = 'error';
    values[':error'] = { S: error };
    setParts.push('#error = :error');
  } else {
    names['#error'] = 'error';
    removeParts.push('#error');
  }
  if (warning) {
    names['#warning'] = 'warning';
    values[':warning'] = { S: warning };
    setParts.push('#warning = :warning');
  } else {
    names['#warning'] = 'warning';
    removeParts.push('#warning');
  }

  let updateExpr = `SET ${setParts.join(', ')}`;
  if (removeParts.length) updateExpr += ` REMOVE ${removeParts.join(', ')}`;

  await dynamoClient.send(new UpdateItemCommand({
    TableName: TENANT_TABLE,
    Key: { tenant_id: { S: tenantId } },
    UpdateExpression: updateExpr,
    ExpressionAttributeNames: names,
    ExpressionAttributeValues: values,
  }));
}

export const handler = async (event: { detail: EventBridgeDetail }) => {
  const { tenant_id: tenantId, domain } = event.detail;
  console.log(`Configuring tenant ${tenantId} (${domain})`);

  try {
    const mc = await getManagementClient(tenantId);
    const accessToken = await getAccessToken(mc.domain, mc.client_id, mc.client_secret);
    const personaApiKey = await getPersonaApiKey();

    // Must run before createPasskeyOtpConnection — Auth0 rejects email-OTP verification
    // on a connection unless the tenant already has Identifier First enabled.
    await updatePromptSettings(mc.domain, accessToken);

    await createPersonaActionsAndBind(mc.domain, accessToken, personaApiKey);
    const passkeyConnectionId = await createPasskeyOtpConnection(mc.domain, accessToken);
    await createLogStream(mc.domain, accessToken);

    let warning: string | undefined;
    try {
      await createPortal(mc.domain, accessToken, passkeyConnectionId);
    } catch (portalErr) {
      const msg = (portalErr as Error).message;
      console.error('Portal configuration failed (non-fatal):', msg);
      warning = `Portal setup failed: ${msg}`;
    }

    await markTenantStatus(tenantId, 'ready', undefined, warning);
    console.log(`Tenant ${tenantId} configured successfully${warning ? ' (with portal warning)' : ''}`);
  } catch (err) {
    const message = (err as Error).message;
    console.error('Configuration error:', message);
    await markTenantStatus(tenantId, 'failed', message);
  }
};
