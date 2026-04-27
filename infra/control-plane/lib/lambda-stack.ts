import * as path from "path";
import * as cdk from "aws-cdk-lib";
import {
  aws_lambda as lambda,
  aws_sqs as sqs,
  aws_cloudwatch as cloudwatch,
  aws_iam as iam,
  aws_dynamodb as dynamodb,
} from "aws-cdk-lib";
import { DynamoEventSource, SqsDlq } from "aws-cdk-lib/aws-lambda-event-sources";
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

    // --- Dead-letter queue ---

    const dlq = new sqs.Queue(this, "SagaTriggerDlq", {
      queueName: `forgeguard-${environment}-saga-trigger-dlq`,
      retentionPeriod: cdk.Duration.days(14),
    });

    // --- Saga-trigger function ---

    const sagaTrigger = new lambda.Function(this, "SagaTrigger", {
      functionName: `forgeguard-saga-trigger-${environment}`,
      runtime: lambda.Runtime.PROVIDED_AL2023,
      architecture: lambda.Architecture.ARM_64,
      handler: "bootstrap",
      code: placeholderCode,
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      environment: {
        TABLE_NAME: table.tableName,
        STATE_MACHINE_ARN: "", // Set by #46
      },
    });

    // DynamoDB Streams event source
    sagaTrigger.addEventSource(
      new DynamoEventSource(table, {
        startingPosition: lambda.StartingPosition.TRIM_HORIZON,
        batchSize: 1,
        retryAttempts: 3,
        onFailure: new SqsDlq(dlq),
      }),
    );

    // IAM: Streams read is granted by addEventSource. Add sfn:StartExecution.
    sagaTrigger.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["states:StartExecution"],
        resources: ["*"], // Scoped to specific state machine by #46
      }),
    );

    // --- CloudWatch alarm on DLQ depth ---

    new cloudwatch.Alarm(this, "DlqAlarm", {
      alarmName: `forgeguard-${environment}-saga-trigger-dlq-depth`,
      metric: dlq.metricApproximateNumberOfMessagesVisible({
        period: cdk.Duration.minutes(1),
      }),
      threshold: 0,
      comparisonOperator:
        cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

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

    new cdk.CfnOutput(this, "SagaTriggerFunctionArn", {
      value: sagaTrigger.functionArn,
    });

    new cdk.CfnOutput(this, "DlqArn", {
      value: dlq.queueArn,
    });

    new cdk.CfnOutput(this, "DlqUrl", {
      value: dlq.queueUrl,
    });
  }
}
