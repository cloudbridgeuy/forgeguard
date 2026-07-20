import * as path from "path";
import * as cdk from "aws-cdk-lib";
import {
  aws_lambda as lambda,
  aws_iam as iam,
  aws_dynamodb as dynamodb,
} from "aws-cdk-lib";
import { Construct } from "constructs";

interface LambdaStackProps extends cdk.StackProps {
  environment: string;
  table: dynamodb.ITableV2;
  userPoolId: string;
  appClientId: string;
  policyStoreId: string;
  policyStoreArn: string;
}

export class LambdaStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: LambdaStackProps) {
    super(scope, id, props);

    const {
      environment,
      table,
      userPoolId,
      appClientId,
      policyStoreId,
      policyStoreArn,
    } = props;
    const placeholderCode = lambda.Code.fromAsset(
      path.join(__dirname, "../assets/placeholder"),
    );

    // --- Control-plane function ---

    const controlPlane = new lambda.Function(this, "ControlPlane", {
      functionName: `forgeguard-control-plane-${environment}`,
      runtime: lambda.Runtime.PROVIDED_AL2023,
      architecture: lambda.Architecture.ARM_64,
      handler: "bootstrap",
      code: placeholderCode,
      memorySize: 256,
      timeout: cdk.Duration.seconds(30),
      environment: {
        TABLE_NAME: table.tableName,
        FORGEGUARD_CP_JWKS_URL: `https://cognito-idp.${this.region}.amazonaws.com/${userPoolId}/.well-known/jwks.json`,
        FORGEGUARD_CP_ISSUER: `https://cognito-idp.${this.region}.amazonaws.com/${userPoolId}`,
        FORGEGUARD_CP_AUDIENCE: appClientId,
        FORGEGUARD_CP_POLICY_STORE_ID: policyStoreId,
        FORGEGUARD_CP_COGNITO_POOL_ID: userPoolId,
      },
    });

    const controlPlaneUrl = controlPlane.addFunctionUrl({
      authType: lambda.FunctionUrlAuthType.NONE,
    });

    table.grantReadWriteData(controlPlane);

    controlPlane.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["verifiedpermissions:IsAuthorized"],
        resources: [policyStoreArn],
      }),
    );

    // V3 Active-org group writes materialise Cedar permits into each org's
    // dedicated VP store. Per-org store ARNs are created at runtime and are
    // unknowable to CDK, so the write actions cannot be ARN-scoped here.
    controlPlane.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "verifiedpermissions:CreatePolicy",
          "verifiedpermissions:DeletePolicy",
          "verifiedpermissions:ListPolicies",
          "verifiedpermissions:GetPolicy",
        ],
        resources: ["*"],
      }),
    );

    // --- Tags ---

    cdk.Tags.of(this).add("project", "forgeguard");
    cdk.Tags.of(this).add("environment", environment);

    // --- Outputs ---

    new cdk.CfnOutput(this, "ControlPlaneFunctionArn", {
      value: controlPlane.functionArn,
    });

    new cdk.CfnOutput(this, "ControlPlaneFunctionUrl", {
      value: controlPlaneUrl.url,
    });
  }
}
