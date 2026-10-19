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

    const { eventsBucket, athenaWorkgroup } = props.storageStack;

    // Analytics pipeline resources created by ingestStack.ts. Their names are
    // stable, so the ARNs are constructed directly (no cross-stack reference).
    const deliveryStreamArn = (this.node.tryGetContext('deliveryStreamArn') as string | undefined)
      ?? `arn:aws:firehose:${this.region}:${this.account}:deliverystream/auth0-events-analytics`;
    const ebFirehoseRoleArn = (this.node.tryGetContext('ebFirehoseRoleArn') as string | undefined)
      ?? `arn:aws:iam::${this.account}:role/auth0-analytics-eb-firehose-role`;

    // Third-party MCP client (Claude) is registered by importing its CIMD URL.
    const claudeCimdUrl = (this.node.tryGetContext('claudeCimdUrl') as string | undefined)
      ?? 'https://claude.ai/oauth/mcp-oauth-client-metadata';

    // Enterprise OIDC connector federating each tenant to a shared upstream IdP.
    // Skipped by configure-tenant until both the client id and secret ARN are set.
    const ciamOidcDiscoveryUrl = (this.node.tryGetContext('ciamOidcDiscoveryUrl') as string | undefined)
      ?? `https://${this.node.tryGetContext('auth0Domain')}/.well-known/openid-configuration`;
    const ciamOidcClientId = (this.node.tryGetContext('ciamOidcClientId') as string | undefined) ?? '';
    const ciamOidcClientSecretArn = (this.node.tryGetContext('ciamOidcClientSecretArn') as string | undefined) ?? '';

    const auth0Domain = this.node.tryGetContext('auth0Domain') as string;
    const auth0Audience = this.node.tryGetContext('auth0Audience') as string;
    const tenantClaim = (this.node.tryGetContext('tenantClaim') as string | undefined) ?? 'org_id';
    const corsOrigins = ((this.node.tryGetContext('corsOrigins') as string | undefined) ?? '*').split(',');
    const additionalIssuers = ((this.node.tryGetContext('additionalIssuers') as string | undefined) ?? '').split(',').filter(Boolean);

    const trustedIssuers = [
      `https://${auth0Domain}/`,
      ...additionalIssuers,
    ].join(',');

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
      },
      bundling: {
        externalModules: [],
        minify: true,
      },
    });

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
        DEFAULT_TENANT: auth0Domain.split('.')[0], // e.g. dev-cs5j6vau
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
    const teamsApiKeySecretArn = (this.node.tryGetContext('teamsApiKeySecretArn') as string | undefined)
      ?? `arn:aws:secretsmanager:${this.region}:${this.account}:secret:auth0/teams/api-key`;
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
      timeout: cdk.Duration.seconds(30),
      memorySize: 256,
      logGroup: provisionerLogGroup,
      environment: {
        TRUSTED_ISSUERS:         trustedIssuers,
        TEAMS_SLUG:              teamsSlug,
        TEAMS_API_KEY_SECRET_ARN: teamsApiKeySecretArn,
        DEFAULT_LOCALITY:        defaultLocality,
      },
      bundling: {
        externalModules: ['@aws-sdk/*'],
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
    const personaApiKeySecretArn = (this.node.tryGetContext('personaApiKeySecretArn') as string | undefined)
      ?? 'arn:aws:secretsmanager:us-east-1:204352680806:secret:dvly/idv/persona/apikey-lwVEYE';
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
        PERSONA_API_KEY_SECRET_ARN:    personaApiKeySecretArn,
        PERSONA_DOMAIN:                personaDomain,
        PERSONA_INQUIRY_TEMPLATE_ID:   personaInquiryTemplateId,
        EVENTBRIDGE_AWS_ACCOUNT_ID:    this.account,
        EVENTBRIDGE_AWS_REGION:        this.region,
        // Analytics pipeline sink (see ingestStack.ts) — used to wire each new
        // tenant's partner event bus to Firehose on provision.
        DELIVERY_STREAM_ARN:           deliveryStreamArn,
        EB_FIREHOSE_ROLE_ARN:          ebFirehoseRoleArn,
        // MCP / third-party federation config (see configure-tenant/index.ts).
        // MCP_RESOURCE_BASE_URL is added below once the HttpApi exists.
        CLAUDE_CIMD_URL:               claudeCimdUrl,
        CIAM_OIDC_DISCOVERY_URL:       ciamOidcDiscoveryUrl,
        CIAM_OIDC_CLIENT_ID:           ciamOidcClientId,
        CIAM_OIDC_CLIENT_SECRET_ARN:   ciamOidcClientSecretArn,
      },
      bundling: { externalModules: ['@aws-sdk/*'], minify: true },
    });

    // Wire each new tenant's Auth0 partner event bus to the analytics Firehose:
    // associate the pending partner event source and create the routing rule.
    configureFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['events:ListEventSources'],
      resources: ['*'],
    }));
    configureFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['events:CreateEventBus', 'events:DescribeEventBus'],
      resources: [
        `arn:aws:events:${this.region}:${this.account}:event-bus/aws.partner/auth0.com/*`,
      ],
    }));
    configureFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['events:PutRule', 'events:PutTargets', 'events:DescribeRule', 'events:EnableRule'],
      resources: [
        `arn:aws:events:${this.region}:${this.account}:rule/aws.partner/auth0.com/*`,
        `arn:aws:events:${this.region}:${this.account}:event-bus/aws.partner/auth0.com/*`,
      ],
    }));
    configureFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['iam:PassRole'],
      resources: [ebFirehoseRoleArn],
      conditions: { StringEquals: { 'iam:PassedToService': 'events.amazonaws.com' } },
    }));

    tenantTable.grantWriteData(configureFn);
    configureFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue'],
      resources: [
        `arn:aws:secretsmanager:${this.region}:${this.account}:secret:auth0/tenants/*`,
        personaApiKeySecretArn,
        ...(ciamOidcClientSecretArn ? [ciamOidcClientSecretArn] : []),
      ],
    }));

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
      environment: { TENANT_TABLE: tenantTable.tableName },
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
        externalModules: ['@aws-sdk/*'],
        nodeModules: ['@auth0/auth0-mcp-server'],
        minify: true,
        format: OutputFormat.ESM,
        banner: "import { createRequire as __cjsCompatRequire } from 'module'; const require = __cjsCompatRequire(import.meta.url);",
      },
    });

    tenantTable.grantReadData(mcpFn);
    mcpFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue'],
      resources: [`arn:aws:secretsmanager:${this.region}:${this.account}:secret:auth0/tenants/*`],
    }));
    mcpFn.addEnvironment('TRUSTED_ISSUERS', trustedIssuers);

    // Dedicated authorizer for /mcp/{tenantId} — additive, does not touch the
    // shared Auth0LambdaAuthorizer used by /tenants and /reports. Trusts the
    // same static issuer list first, then falls back to verifying against a
    // tenant's own Auth0 domain (for 3rd-party MCP clients federated into that
    // tenant via CIMD + enterprise connection).
    const mcpAuthorizerLogGroup = new logs.LogGroup(this, 'McpAuthorizerLogGroup', {
      logGroupName: '/aws/lambda/auth0-tenant-mcp-authorizer',
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const mcpAuthorizerFn = new NodejsFunction(this, 'McpAuthorizerFunction', {
      functionName: 'auth0-tenant-mcp-authorizer',
      entry: path.join(__dirname, '../lambda/mcp-authorizer/index.ts'),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(10),
      memorySize: 128,
      logGroup: mcpAuthorizerLogGroup,
      environment: {
        TRUSTED_ISSUERS: trustedIssuers,
        TENANT_TABLE: tenantTable.tableName,
      },
      bundling: { externalModules: ['@aws-sdk/*'], minify: true },
    });
    tenantTable.grantReadData(mcpAuthorizerFn);

    const mcpLambdaAuthorizer = new authorizers.HttpLambdaAuthorizer(
      'McpAuthorizer',
      mcpAuthorizerFn,
      {
        authorizerName: 'auth0-mcp-multi-tenant',
        responseTypes: [authorizers.HttpLambdaResponseType.SIMPLE],
        resultsCacheTtl: cdk.Duration.seconds(300),
        identitySource: ['$request.header.Authorization'],
      },
    );

    // Read the Teams API key at runtime (never in env vars or CloudFormation)
    provisionFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue'],
      resources: [teamsApiKeySecretArn],
    }));

    // Write management_client credentials for each provisioned tenant
    provisionFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:CreateSecret', 'secretsmanager:TagResource'],
      resources: [`arn:aws:secretsmanager:${this.region}:${this.account}:secret:auth0/tenants/*`],
    }));

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

    const mcpIntegration = new integrations.HttpLambdaIntegration('TenantMcpIntegration', mcpFn);

    httpApi.addRoutes({
      path: '/mcp/{tenantId}',
      methods: [apigatewayv2.HttpMethod.POST],
      integration: mcpIntegration,
      authorizer: mcpLambdaAuthorizer,
    });

    // Protected Resource Metadata (RFC 9728) — unauthenticated by design;
    // OAuth/CIMD clients fetch this before they have any credential.
    // Per the MCP spec's well-known URI convention, the resource path is
    // APPENDED after /.well-known/oauth-protected-resource (not nested under
    // the resource path) — e.g. a resource at /mcp/{tenantId} publishes its
    // metadata at /.well-known/oauth-protected-resource/mcp/{tenantId}.
    httpApi.addRoutes({
      path: '/.well-known/oauth-protected-resource/mcp/{tenantId}',
      methods: [apigatewayv2.HttpMethod.GET],
      integration: mcpIntegration,
    });

    mcpFn.addEnvironment('API_BASE_URL', httpApi.apiEndpoint);
    // The tenant's OAuth resource identifier is `${base}/mcp/${tenantId}`, which
    // must equal what mcp-tenant expects as `aud` (API_BASE_URL above).
    configureFn.addEnvironment('MCP_RESOURCE_BASE_URL', httpApi.apiEndpoint);

    // Function URL for third-party MCP clients (e.g. Claude). API Gateway's
    // Lambda authorizer rejects a missing Authorization header with a bare 401
    // before any code runs, so it can never emit the WWW-Authenticate header
    // that OAuth discovery (RFC 9728) depends on. The Function URL has no
    // authorizer: the Lambda itself returns the 401 + WWW-Authenticate and
    // verifies the JWT. The first-party chatbot keeps using /mcp/{tenantId}
    // through API Gateway.
    const mcpFnUrl = mcpFn.addFunctionUrl({
      authType: lambda.FunctionUrlAuthType.NONE,
      cors: {
        allowedOrigins: ['*'],
        allowedMethods: [lambda.HttpMethod.GET, lambda.HttpMethod.POST],
        allowedHeaders: ['Authorization', 'Content-Type', 'Accept', 'Mcp-Protocol-Version'],
        exposedHeaders: ['WWW-Authenticate'],
      },
    });

    new cdk.CfnOutput(this, 'TenantMcpFunctionUrl', {
      value: mcpFnUrl.url,
      description: 'MCP endpoint for 3rd-party clients: <url>mcp/{tenantId}',
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
