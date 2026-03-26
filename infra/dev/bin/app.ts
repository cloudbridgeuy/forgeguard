import * as cdk from "aws-cdk-lib";
import { CognitoStack } from "../lib/cognito-stack";

function parseGroups(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw.split(",").map((g) => g.trim());
}

const app = new cdk.App();
const stackPrefix = (app.node.tryGetContext("stackPrefix") as string) ?? "forgeguard-dev";
const groups = parseGroups(app.node.tryGetContext("groups") as string | undefined);

new CognitoStack(app, `${stackPrefix}-cognito`, {
  groups,
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
});
