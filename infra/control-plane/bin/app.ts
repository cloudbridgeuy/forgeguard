import * as cdk from "aws-cdk-lib";
import { DynamoDbStack } from "../lib/dynamodb-stack";
import { LambdaStack } from "../lib/lambda-stack";
import { CognitoStack } from "../lib/cognito-stack";
import { VerifiedPermissionsStack } from "../lib/verified-permissions-stack";

type ForgeguardEnv = "dev" | "prod";

const VALID_ENVS: ReadonlySet<string> = new Set(["dev", "prod"]);

function parseForgeguardEnv(raw: string | undefined): ForgeguardEnv {
  if (raw === undefined) {
    return "prod";
  }
  if (!VALID_ENVS.has(raw)) {
    throw new Error(
      `Invalid FORGEGUARD_ENV: "${raw}". Must be one of: dev, prod`,
    );
  }
  return raw as ForgeguardEnv;
}

const app = new cdk.App();

const env = {
  account: process.env.AWS_ACCOUNT_ID,
  region: process.env.AWS_REGION,
};

const environment = parseForgeguardEnv(process.env.FORGEGUARD_ENV);

const dynamoStack = new DynamoDbStack(app, `forgeguard-${environment}-dynamodb`, {
  env,
  environment,
});

const cognitoStack = new CognitoStack(app, `forgeguard-${environment}-cognito`, {
  env,
  environment,
});

const vpStack = new VerifiedPermissionsStack(app, `forgeguard-${environment}-vp`, {
  env,
  environment,
  userPoolArn: cognitoStack.userPool.userPoolArn,
  appClientId: cognitoStack.appClient.userPoolClientId,
});

new LambdaStack(app, `forgeguard-${environment}-lambda`, {
  env,
  environment,
  table: dynamoStack.table,
  userPoolId: cognitoStack.userPool.userPoolId,
  appClientId: cognitoStack.appClient.userPoolClientId,
  policyStoreId: vpStack.policyStoreId,
  policyStoreArn: vpStack.policyStoreArn,
});
