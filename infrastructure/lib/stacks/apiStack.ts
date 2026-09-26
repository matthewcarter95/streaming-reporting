import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as apigatewayv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as authorizers from 'aws-cdk-lib/aws-apigatewayv2-authorizers';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
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

    const httpApi = new apigatewayv2.HttpApi(this, 'ReportingApi', {
      apiName: 'auth0-analytics-api',
      corsPreflight: {
        allowOrigins: corsOrigins,
        allowMethods: [apigatewayv2.CorsHttpMethod.GET, apigatewayv2.CorsHttpMethod.OPTIONS],
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
