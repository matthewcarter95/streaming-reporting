import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as apigatewayv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as authorizers from 'aws-cdk-lib/aws-apigatewayv2-authorizers';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import { NodejsFunction, OutputFormat } from 'aws-cdk-lib/aws-lambda-nodejs';
import { Construct } from 'constructs';
import * as path from 'path';
import { StorageStack } from './storageStack';

interface ApiStackProps extends cdk.StackProps {
  storageStack: StorageStack;
}

export class ApiStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ApiStackProps) {
    super(scope, id, props);

    const { eventsBucket, athenaWorkgroup, tenantMappingTable } = props.storageStack;

    const auth0Domain = this.node.tryGetContext('auth0Domain') as string;
    const auth0Audience = this.node.tryGetContext('auth0Audience') as string;
    const tenantClaim = (this.node.tryGetContext('tenantClaim') as string | undefined) ?? 'sub';
    const corsOrigins = ((this.node.tryGetContext('corsOrigins') as string | undefined) ?? '*').split(',');

    // The authorizer trusts tokens issued by the custom domain.
    // Auth0 custom domains issue tokens whose `iss` is the custom domain, not
    // the underlying tenant URL, so we only need the one issuer here.
    const trustedIssuers = `https://${auth0Domain}/`;

    // ── OCI Vault Secrets ──────────────────────────────────────────────────────
    // Static and per-tenant secrets live in OCI Vault (Oracle Cloud). The
    // Lambdas authenticate with OCI Signature v1 using an RSA key; the key PEM
    // is stored (base64) in AWS SSM Parameter Store and fetched at cold start.
    const ociRegion          = (this.node.tryGetContext('ociRegion')          as string | undefined) ?? 'us-ashburn-1';
    const ociTenancyOcid     = (this.node.tryGetContext('ociTenancyOcid')     as string | undefined) ?? '';
    const ociUserOcid        = (this.node.tryGetContext('ociUserOcid')        as string | undefined) ?? '';
    const ociKeyFingerprint  = (this.node.tryGetContext('ociKeyFingerprint')  as string | undefined) ?? '';
    const ociKeySsmName      = (this.node.tryGetContext('ociKeySsmName')      as string | undefined) ?? '/dvly/oci/private-key';
    const ociVaultOcid       = (this.node.tryGetContext('ociVaultOcid')       as string | undefined) ?? '';
    const ociCompartmentOcid = (this.node.tryGetContext('ociCompartmentOcid') as string | undefined) ?? '';
    const ociKeyId           = (this.node.tryGetContext('ociKeyId')           as string | undefined) ?? '';

    const teamsApiKeySecretOcid   = (this.node.tryGetContext('teamsApiKeySecretOcid')   as string | undefined) ?? '';
    const personaApiKeySecretOcid = (this.node.tryGetContext('personaApiKeySecretOcid') as string | undefined) ?? '';

    const ociEnv = {
      OCI_REGION:           ociRegion,
      OCI_TENANCY_OCID:     ociTenancyOcid,
      OCI_USER_OCID:        ociUserOcid,
      OCI_KEY_FINGERPRINT:  ociKeyFingerprint,
      OCI_KEY_SSM_NAME:     ociKeySsmName,
      OCI_VAULT_OCID:       ociVaultOcid,
      OCI_COMPARTMENT_OCID: ociCompartmentOcid,
      OCI_KEY_ID:           ociKeyId,
    };

    // Shared layer with the OCI Vault reader/writer (OCI Signature v1).
    const ociSecretsLayer = new lambda.LayerVersion(this, 'OciSecretsLayer', {
      layerVersionName: 'dvly-oci-secrets',
      code: lambda.Code.fromAsset(path.join(__dirname, '../../layers/oci-secrets')),
      compatibleRuntimes: [lambda.Runtime.NODEJS_22_X],
      description: 'Read/write secrets in OCI Vault via OCI Signature v1 (RSA-SHA256)',
    });

    // The OCI private key is fetched from SSM (SecureString) at cold start.
    const grantOciKeyRead = (fn: lambda.Function) => {
      fn.addToRolePolicy(new iam.PolicyStatement({
        actions: ['ssm:GetParameter'],
        resources: [`arn:aws:ssm:${this.region}:${this.account}:parameter${ociKeySsmName}`],
      }));
      fn.addToRolePolicy(new iam.PolicyStatement({
        actions: ['kms:Decrypt'],
        resources: [`arn:aws:kms:${this.region}:${this.account}:alias/aws/ssm`],
      }));
    };

    // Lambda authorizer — validates JWTs from any trusted issuer
    const authorizerLogGroup = new logs.LogGroup(this, 'AuthorizerLogGroup', {
      logGroupName: '/aws/lambda/auth0-analytics-authorizer',
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const authorizerFn = new NodejsFunction(this, 'AuthorizerFunction', {
      functionName: 'auth0-analytics-authorizer',
      entry: path.join(__dirname, '../lambda/authorizer/index.ts'),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(10),
      memorySize: 128,
      logGroup: authorizerLogGroup,
      environment: {
        TRUSTED_ISSUERS: trustedIssuers,
        AUTH0_AUDIENCE: auth0Audience,
        TENANT_MAPPING_TABLE: tenantMappingTable.tableName,
      },
      bundling: {
        // jose and @aws-sdk/client-dynamodb must be bundled; NOT available in the runtime layer
        externalModules: [],
        minify: true,
      },
    });

    // Grant the authorizer read access to the tenant-mapping table
    tenantMappingTable.grantReadData(authorizerFn);

    const lambdaAuthorizer = new authorizers.HttpLambdaAuthorizer(
      'Auth0LambdaAuthorizer',
      authorizerFn,
      {
        authorizerName: 'auth0-multi-issuer',
        responseTypes: [authorizers.HttpLambdaResponseType.SIMPLE],
        resultsCacheTtl: cdk.Duration.seconds(300),
        identitySource: ['$request.header.Authorization'],
      },
    );

    const reportingLogGroup = new logs.LogGroup(this, 'ReportingLogGroup', {
      logGroupName: '/aws/lambda/auth0-analytics-reports',
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const reportingFn = new NodejsFunction(this, 'ReportingFunction', {
      functionName: 'auth0-analytics-reports',
      entry: path.join(__dirname, '../lambda/reports/index.ts'),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(30),
      memorySize: 512,
      logGroup: reportingLogGroup,
      environment: {
        ATHENA_DATABASE: 'auth0_events',
        ATHENA_TABLE: 'logs',
        ATHENA_WORKGROUP: athenaWorkgroup.name,
        S3_RESULTS_BUCKET: eventsBucket.bucketName,
        TENANT_CLAIM: tenantClaim,
      },
      bundling: {
        // @aws-sdk/* is available in the Lambda Node 20 runtime
        externalModules: ['@aws-sdk/*'],
        minify: true,
      },
    });

    // Athena + Glue + S3 permissions for the reporting Lambda
    reportingFn.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'athena:StartQueryExecution',
        'athena:GetQueryExecution',
        'athena:GetQueryResults',
        'athena:StopQueryExecution',
      ],
      resources: [
        `arn:aws:athena:${this.region}:${this.account}:workgroup/${athenaWorkgroup.name}`,
      ],
    }));

    reportingFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['glue:GetDatabase', 'glue:GetTable', 'glue:GetPartitions'],
      resources: [
        `arn:aws:glue:${this.region}:${this.account}:catalog`,
        `arn:aws:glue:${this.region}:${this.account}:database/auth0_events`,
        `arn:aws:glue:${this.region}:${this.account}:table/auth0_events/logs`,
      ],
    }));

    // Read events data and write Athena results
    eventsBucket.grantRead(reportingFn);
    eventsBucket.grantPut(reportingFn, 'athena-results/*');

    const teamsSlug           = (this.node.tryGetContext('teamsSlug')          as string | undefined) ?? '';
    const defaultLocality     = (this.node.tryGetContext('defaultLocality')    as string | undefined) ?? 'US-3';

    const provisionerLogGroup = new logs.LogGroup(this, 'ProvisionerLogGroup', {
      logGroupName: '/aws/lambda/auth0-tenant-provisioner',
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const provisionFn = new NodejsFunction(this, 'TenantProvisionerFunction', {
      functionName: 'auth0-tenant-provisioner',
      entry: path.join(__dirname, '../lambda/provision-tenant/index.ts'),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(60),
      memorySize: 256,
      logGroup: provisionerLogGroup,
      environment: {
        TRUSTED_ISSUERS:            trustedIssuers,
        TEAMS_SLUG:                 teamsSlug,
        TEAMS_API_KEY_SECRET_OCID:  teamsApiKeySecretOcid,
        DEFAULT_LOCALITY:           defaultLocality,
        ...ociEnv,
      },
      layers: [ociSecretsLayer],
      bundling: {
        externalModules: ['@aws-sdk/*', 'dvly-oci-secrets'],
        minify: true,
      },
    });

    // DynamoDB table for tenant provisioning status
    const tenantTable = new dynamodb.Table(this, 'TenantTable', {
      tableName: 'auth0-provisioned-tenants',
      partitionKey: { name: 'tenant_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    // GSI: query all tenants created by a given user (by Auth0 sub)
    tenantTable.addGlobalSecondaryIndex({
      indexName: 'by-creator',
      partitionKey: { name: 'created_by_sub', type: dynamodb.AttributeType.STRING },
      sortKey:      { name: 'created_at',     type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Provision Lambda: write status + publish EventBridge event
    provisionFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['dynamodb:PutItem'],
      resources: [tenantTable.tableArn],
    }));
    provisionFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['events:PutEvents'],
      resources: [`arn:aws:events:${this.region}:${this.account}:event-bus/default`],
    }));
    provisionFn.addEnvironment('TENANT_TABLE', tenantTable.tableName);

    // Status Lambda
    const statusLogGroup = new logs.LogGroup(this, 'StatusLogGroup', {
      logGroupName: '/aws/lambda/auth0-tenant-status',
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const statusFn = new NodejsFunction(this, 'StatusFunction', {
      functionName: 'auth0-tenant-status',
      entry: path.join(__dirname, '../lambda/status-tenant/index.ts'),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(10),
      memorySize: 128,
      logGroup: statusLogGroup,
      environment: { TENANT_TABLE: tenantTable.tableName },
      bundling: { externalModules: ['@aws-sdk/*'], minify: true },
    });
    tenantTable.grantReadData(statusFn);

    // Configure Lambda — runs after tenant creation to replicate the d_tenant
    // Terraform config (Actions, connection, log stream, prompt, portal) via
    // direct Management API calls, triggered by the tenant.provisioned event.
    const personaDomain = (this.node.tryGetContext('personaDomain') as string | undefined) ?? 'withpersona.com';
    const personaInquiryTemplateId = this.node.tryGetContext('personaInquiryTemplateId') as string;

    const configureLogGroup = new logs.LogGroup(this, 'ConfigureLogGroup', {
      logGroupName: '/aws/lambda/auth0-tenant-configurer',
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const configureFn = new NodejsFunction(this, 'TenantConfigurerFunction', {
      functionName: 'auth0-tenant-configurer',
      entry: path.join(__dirname, '../lambda/configure-tenant/index.ts'),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(120),
      memorySize: 256,
      logGroup: configureLogGroup,
      environment: {
        TENANT_TABLE:                  tenantTable.tableName,
        PERSONA_API_KEY_SECRET_OCID:   personaApiKeySecretOcid,
        PERSONA_DOMAIN:                personaDomain,
        PERSONA_INQUIRY_TEMPLATE_ID:   personaInquiryTemplateId,
        EVENTBRIDGE_AWS_ACCOUNT_ID:    this.account,
        EVENTBRIDGE_AWS_REGION:        this.region,
        ...ociEnv,
      },
      layers: [ociSecretsLayer],
      bundling: { externalModules: ['@aws-sdk/*', 'dvly-oci-secrets'], minify: true },
    });

    tenantTable.grantWriteData(configureFn);
    grantOciKeyRead(configureFn);

    new events.Rule(this, 'TenantProvisionedRule', {
      eventPattern: {
        source:     ['auth0.provisioner'],
        detailType: ['tenant.provisioned'],
      },
      targets: [new targets.LambdaFunction(configureFn)],
    });

    // MCP Lambda — exposes a tenant's Management API as MCP tools (via the
    // @auth0/auth0-mcp-server library) to the chatbot user who owns that tenant.
    const mcpLogGroup = new logs.LogGroup(this, 'McpLogGroup', {
      logGroupName: '/aws/lambda/auth0-tenant-mcp',
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const mcpFn = new NodejsFunction(this, 'TenantMcpFunction', {
      functionName: 'auth0-tenant-mcp',
      entry: path.join(__dirname, '../lambda/mcp-tenant/index.ts'),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(30),
      memorySize: 512,
      logGroup: mcpLogGroup,
      environment: { TENANT_TABLE: tenantTable.tableName, ...ociEnv },
      layers: [ociSecretsLayer],
      // ESM output (not the default CJS) — @auth0/auth0-mcp-server's analytics
      // util uses createRequire(import.meta.url) to load its package.json;
      // esbuild's CJS shim for import.meta.url resolves to undefined, which
      // breaks that call. Real ESM output keeps import.meta.url valid.
      // The banner replaces esbuild's own broken `require` shim (which throws
      // "Dynamic require of ... is not supported" for CJS deps like `debug`
      // that call require('tty') at module load) with a real one.
      // @auth0/auth0-mcp-server is left out of the esbuild bundle entirely
      // (nodeModules, not externalModules) because its own package.json
      // version lookup does `require('../../package.json')` relative to its
      // *own file location* — flattening it into index.mjs breaks that
      // relative path. Installing it as a real node_modules package keeps
      // its internal directory layout (and that lookup) intact.
      bundling: {
        externalModules: ['@aws-sdk/*', 'dvly-oci-secrets'],
        nodeModules: ['@auth0/auth0-mcp-server'],
        minify: true,
        format: OutputFormat.ESM,
        banner: "import { createRequire as __cjsCompatRequire } from 'module'; const require = __cjsCompatRequire(import.meta.url);",
      },
    });

    tenantTable.grantReadData(mcpFn);
    grantOciKeyRead(mcpFn);

    // The provisioner reads the Teams key from OCI Vault and writes each
    // tenant's management_client credentials to OCI Vault too, so it only
    // needs the SSM-stored OCI signing key.
    grantOciKeyRead(provisionFn);

    const httpApi = new apigatewayv2.HttpApi(this, 'ReportingApi', {
      apiName: 'auth0-analytics-api',
      corsPreflight: {
        allowOrigins: corsOrigins,
        allowMethods: [apigatewayv2.CorsHttpMethod.GET, apigatewayv2.CorsHttpMethod.POST, apigatewayv2.CorsHttpMethod.OPTIONS],
        allowHeaders: ['Authorization', 'Content-Type'],
        maxAge: cdk.Duration.hours(1),
      },
    });

    const integration = new integrations.HttpLambdaIntegration('ReportingIntegration', reportingFn);

    httpApi.addRoutes({
      path: '/reports/{proxy+}',
      methods: [apigatewayv2.HttpMethod.GET],
      integration,
      authorizer: lambdaAuthorizer,
    });

    httpApi.addRoutes({
      path: '/tenants',
      methods: [apigatewayv2.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('TenantProvisionerIntegration', provisionFn),
      authorizer: lambdaAuthorizer,
    });

    httpApi.addRoutes({
      path: '/tenants/{tenantId}/status',
      methods: [apigatewayv2.HttpMethod.GET],
      integration: new integrations.HttpLambdaIntegration('TenantStatusIntegration', statusFn),
      authorizer: lambdaAuthorizer,
    });

    httpApi.addRoutes({
      path: '/mcp/{tenantId}',
      methods: [apigatewayv2.HttpMethod.POST],
      integration: new integrations.HttpLambdaIntegration('TenantMcpIntegration', mcpFn),
      authorizer: lambdaAuthorizer,
    });

    new cdk.CfnOutput(this, 'TenantProvisionerFunctionArn', {
      value: provisionFn.functionArn,
      exportName: 'Auth0Analytics-TenantProvisionerArn',
    });

    new cdk.CfnOutput(this, 'TenantConfigurerFunctionArn', {
      value: configureFn.functionArn,
      exportName: 'Auth0Analytics-TenantConfigurerArn',
    });

    new cdk.CfnOutput(this, 'TenantMcpFunctionArn', {
      value: mcpFn.functionArn,
      exportName: 'Auth0Analytics-TenantMcpArn',
    });

    new cdk.CfnOutput(this, 'ApiUrl', {
      value: httpApi.apiEndpoint,
      description: 'Base URL for Auth0 analytics reports API',
      exportName: 'Auth0Analytics-ApiUrl',
    });

    new cdk.CfnOutput(this, 'ReportingFunctionArn', {
      value: reportingFn.functionArn,
      exportName: 'Auth0Analytics-ReportingFunctionArn',
    });

    // Quick reference for integrating in your app
    new cdk.CfnOutput(this, 'SampleRegistrationsEndpoint', {
      value: `${httpApi.apiEndpoint}/reports/registrations?days=30`,
      description: 'Example: GET with Authorization: Bearer <auth0-jwt>',
    });
  }
}
