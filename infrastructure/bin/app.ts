#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { StorageStack } from '../lib/stacks/storageStack';
import { IngestStack } from '../lib/stacks/ingestStack';
import { ApiStack } from '../lib/stacks/apiStack';

const app = new cdk.App();

// Auth0 partner event buses exist in us-east-1; all stacks must deploy there
const env = {
  account: '223778538359',
  region: 'us-east-1',
};

const storageStack = new StorageStack(app, 'Auth0AnalyticsStorage', {
  env,
  description: 'S3, Glue catalog, and Athena workgroup for Auth0 event analytics',
});

const ingestStack = new IngestStack(app, 'Auth0AnalyticsIngest', {
  env,
  storageStack,
  description: 'Firehose delivery stream and EventBridge rules for Auth0 event ingestion',
});

const apiStack = new ApiStack(app, 'Auth0AnalyticsApi', {
  env,
  storageStack,
  description: 'Reporting Lambda and HTTP API Gateway with Auth0 JWT authorization',
});

ingestStack.addStackDependency(storageStack);
apiStack.addStackDependency(storageStack);

cdk.Tags.of(app).add('Project', 'Auth0-Analytics');
cdk.Tags.of(app).add('ManagedBy', 'CDK');
