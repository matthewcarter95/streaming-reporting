import * as cdk from 'aws-cdk-lib';
import * as firehose from 'aws-cdk-lib/aws-kinesisfirehose';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as events from 'aws-cdk-lib/aws-events';
import * as logs from 'aws-cdk-lib/aws-logs';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import { Construct } from 'constructs';
import * as path from 'path';
import { StorageStack } from './storageStack';

// Auth0 partner event buses in us-east-1.
//
// Static tenants are always deployed.  Additional tenants can be injected at
// deploy time via CDK context without touching source:
//
//   cdk deploy Auth0AnalyticsIngest \
//     --context 'extraTenants=[{"label":"dvly-cust2","arn":"arn:aws:events:us-east-1:223778538359:event-bus/aws.partner/auth0.com/dvly-cust2-<uuid>/auth0.logs"}]'
//
// Or add them permanently to cdk.json under the "context" key:
//   "extraTenants": [{ "label": "dvly-cust2", "arn": "arn:aws:events:..." }]
interface TenantBus {
  label: string;
  arn: string;
}

const STATIC_BUS_ARNS: TenantBus[] = [
  {
    arn: 'arn:aws:events:us-east-1:223778538359:event-bus/aws.partner/auth0.com/dvly-cust1-fe2ce53a-2357-418a-af66-db7d56c2d09e/auth0.logs',
    label: 'dvly-cust1',
  },
];

interface IngestStackProps extends cdk.StackProps {
  storageStack: StorageStack;
}

export class IngestStack extends cdk.Stack {
  public readonly deliveryStream: firehose.CfnDeliveryStream;

  constructor(scope: Construct, id: string, props: IngestStackProps) {
    super(scope, id, props);

    const { eventsBucket } = props.storageStack;

    const transformLogGroup = new logs.LogGroup(this, 'TransformLogGroup', {
      logGroupName: '/aws/lambda/auth0-analytics-transform',
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const transformFn = new NodejsFunction(this, 'TransformFunction', {
      functionName: 'auth0-analytics-transform',
      entry: path.join(__dirname, '../lambda/transform/index.ts'),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(60),
      memorySize: 256,
      logGroup: transformLogGroup,
      bundling: {
        externalModules: [],
        minify: true,
      },
    });

    // Firehose service role
    const firehoseRole = new iam.Role(this, 'FirehoseRole', {
      roleName: 'auth0-analytics-firehose-role',
      assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com'),
    });

    eventsBucket.grantReadWrite(firehoseRole);
    transformFn.grantInvoke(firehoseRole);

    firehoseRole.addToPolicy(new iam.PolicyStatement({
      actions: ['logs:PutLogEvents', 'logs:CreateLogStream'],
      resources: ['*'],
    }));

    this.deliveryStream = new firehose.CfnDeliveryStream(this, 'DeliveryStream', {
      deliveryStreamName: 'auth0-events-analytics',
      deliveryStreamType: 'DirectPut',
      extendedS3DestinationConfiguration: {
        bucketArn: eventsBucket.bucketArn,
        roleArn: firehoseRole.roleArn,
        // Lambda returns metadata.partitionKeys.tenant → partitionKeyFromLambda namespace
        prefix: 'tenant=!{partitionKeyFromLambda:tenant}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/',
        errorOutputPrefix: 'errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/',
        bufferingHints: { intervalInSeconds: 60, sizeInMBs: 64 }, // dynamic partitioning requires >= 64 MB
        compressionFormat: 'GZIP',
        dynamicPartitioningConfiguration: {
          enabled: true,
          retryOptions: { durationInSeconds: 300 },
        },
        processingConfiguration: {
          enabled: true,
          processors: [
            {
              // Transform Lambda runs first; returns metadata.partitionKeys.tenant
              type: 'Lambda',
              parameters: [
                { parameterName: 'LambdaArn', parameterValue: transformFn.functionArn },
                { parameterName: 'NumberOfRetries', parameterValue: '3' },
                { parameterName: 'BufferSizeInMBs', parameterValue: '3' },
                { parameterName: 'BufferIntervalInSeconds', parameterValue: '60' },
              ],
            },
          ],
        },
        s3BackupMode: 'Disabled',
      },
    });

    // EventBridge role to put records into Firehose
    const ebRole = new iam.Role(this, 'EventBridgeFirehoseRole', {
      roleName: 'auth0-analytics-eb-firehose-role',
      assumedBy: new iam.ServicePrincipal('events.amazonaws.com'),
    });

    ebRole.addToPolicy(new iam.PolicyStatement({
      actions: ['firehose:PutRecord', 'firehose:PutRecordBatch'],
      resources: [this.deliveryStream.attrArn],
    }));

    // Merge static tenants with any extras supplied via CDK context.
    // Context value must be a JSON array: [{ "label": "...", "arn": "..." }]
    const extraTenants: TenantBus[] = (() => {
      const raw = this.node.tryGetContext('extraTenants');
      if (!raw) return [];
      const parsed: unknown = typeof raw === 'string' ? JSON.parse(raw) : raw;
      if (!Array.isArray(parsed)) throw new Error('extraTenants context must be a JSON array');
      return parsed as TenantBus[];
    })();

    const AUTH0_BUS_ARNS: TenantBus[] = [...STATIC_BUS_ARNS, ...extraTenants];

    // Add an EventBridge rule on each Auth0 partner bus targeting the Firehose
    AUTH0_BUS_ARNS.forEach(({ arn, label }) => {
      new events.CfnRule(this, `AnalyticsRule-${label}`, {
        name: `Auth0Analytics-${label}`,
        description: 'Routes Auth0 events to Firehose for analytics (added by CDK)',
        eventBusName: arn,
        eventPattern: {
          source: [{ prefix: 'aws.partner/auth0.com' }],
        },
        state: 'ENABLED',
        targets: [{
          id: 'FirehoseDelivery',
          arn: this.deliveryStream.attrArn,
          roleArn: ebRole.roleArn,
        }],
      });
    });

    new cdk.CfnOutput(this, 'DeliveryStreamArn', {
      value: this.deliveryStream.attrArn,
      exportName: 'Auth0Analytics-DeliveryStreamArn',
    });

    new cdk.CfnOutput(this, 'TransformFunctionArn', {
      value: transformFn.functionArn,
      exportName: 'Auth0Analytics-TransformFunctionArn',
    });
  }
}
