import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as glue from 'aws-cdk-lib/aws-glue';
import * as athena from 'aws-cdk-lib/aws-athena';
import { Construct } from 'constructs';

export class StorageStack extends cdk.Stack {
  public readonly eventsBucket: s3.Bucket;
  public readonly glueDatabase: glue.CfnDatabase;
  public readonly glueTable: glue.CfnTable;
  public readonly athenaWorkgroup: athena.CfnWorkGroup;

  constructor(scope: Construct, id: string, props: cdk.StackProps) {
    super(scope, id, props);

    this.eventsBucket = new s3.Bucket(this, 'EventsBucket', {
      bucketName: `auth0-events-analytics-${this.account}-${this.region}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: false,
      lifecycleRules: [
        {
          id: 'archive-events',
          prefix: 'tenant=',
          transitions: [{
            storageClass: s3.StorageClass.GLACIER,
            transitionAfter: cdk.Duration.days(90),
          }],
        },
        {
          id: 'expire-athena-results',
          prefix: 'athena-results/',
          expiration: cdk.Duration.days(30),
        },
      ],
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.glueDatabase = new glue.CfnDatabase(this, 'GlueDatabase', {
      catalogId: this.account,
      databaseInput: {
        name: 'auth0_events',
        description: 'Auth0 event logs from EventBridge streaming pipeline',
      },
    });

    this.glueTable = new glue.CfnTable(this, 'LogsTable', {
      catalogId: this.account,
      databaseName: this.glueDatabase.ref,
      tableInput: {
        name: 'logs',
        description: 'Auth0 event logs partitioned by tenant/year/month/day',
        tableType: 'EXTERNAL_TABLE',
        storageDescriptor: {
          location: `s3://${this.eventsBucket.bucketName}/`,
          inputFormat: 'org.apache.hadoop.mapred.TextInputFormat',
          outputFormat: 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
          serdeInfo: {
            serializationLibrary: 'org.openx.data.jsonserde.JsonSerDe',
            parameters: {
              'ignore.malformed.json': 'true',
              'dots.in.keys': 'false',
              'case.insensitive': 'true',
            },
          },
          columns: [
            { name: 'log_id', type: 'string' },
            { name: 'user_id', type: 'string' },
            { name: 'event_type', type: 'string' },
            { name: 'event_timestamp', type: 'string' },
            { name: 'user_agent', type: 'string' },
            { name: 'ip_address', type: 'string' },
            { name: 'email', type: 'string' },
            { name: 'client_id', type: 'string' },
            { name: 'connection', type: 'string' },
            { name: 'hostname', type: 'string' },
          ],
        },
        partitionKeys: [
          { name: 'tenant', type: 'string' },
          { name: 'year', type: 'int' },
          { name: 'month', type: 'int' },
          { name: 'day', type: 'int' },
        ],
        parameters: {
          'projection.enabled': 'true',
          'projection.tenant.type': 'injected',
          'projection.year.type': 'integer',
          'projection.year.range': '2024,2030',
          'projection.month.type': 'integer',
          'projection.month.range': '1,12',
          'projection.month.digits': '2',
          'projection.day.type': 'integer',
          'projection.day.range': '1,31',
          'projection.day.digits': '2',
          'storage.location.template':
            `s3://${this.eventsBucket.bucketName}/tenant=\${tenant}/year=\${year}/month=\${month}/day=\${day}`,
          'classification': 'json',
          'compressionType': 'gzip',
        },
      },
    });
    // Dependency is implicit via glueDatabase.ref reference above

    this.athenaWorkgroup = new athena.CfnWorkGroup(this, 'AthenaWorkgroup', {
      name: 'auth0-analytics',
      description: 'Workgroup for Auth0 event analytics queries',
      workGroupConfiguration: {
        resultConfiguration: {
          outputLocation: `s3://${this.eventsBucket.bucketName}/athena-results/`,
          encryptionConfiguration: {
            encryptionOption: 'SSE_S3',
          },
        },
        enforceWorkGroupConfiguration: true,
        bytesScannedCutoffPerQuery: 100 * 1024 * 1024, // 100MB safety limit
        publishCloudWatchMetricsEnabled: false,
        engineVersion: {
          selectedEngineVersion: 'Athena engine version 3',
        },
      },
    });

    new cdk.CfnOutput(this, 'EventsBucketName', {
      value: this.eventsBucket.bucketName,
      exportName: 'Auth0Analytics-EventsBucketName',
    });

    new cdk.CfnOutput(this, 'AthenaDatabaseName', {
      value: 'auth0_events',
      exportName: 'Auth0Analytics-AthenaDatabaseName',
    });

    new cdk.CfnOutput(this, 'AthenaWorkgroupName', {
      value: this.athenaWorkgroup.name,
      exportName: 'Auth0Analytics-AthenaWorkgroupName',
    });
  }
}
