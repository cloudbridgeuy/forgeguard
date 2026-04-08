import * as cdk from "aws-cdk-lib";
import { aws_dynamodb as dynamodb } from "aws-cdk-lib";
import { Construct } from "constructs";

interface DynamoDbStackProps extends cdk.StackProps {
  environment: string;
}

export class DynamoDbStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: DynamoDbStackProps) {
    super(scope, id, props);

    // Exclude the primary region from the replica list to avoid CDK errors.
    const primaryRegion = cdk.Stack.of(this).region;
    const allReplicaRegions = ["us-east-1", "us-east-2", "us-west-2"];
    const replicas = allReplicaRegions
      .filter((r) => r !== primaryRegion)
      .map((region) => ({ region }));

    const table = new dynamodb.TableV2(this, "OrgsTable", {
      tableName: `forgeguard-${props.environment}-orgs`,
      partitionKey: { name: "PK", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "SK", type: dynamodb.AttributeType.STRING },
      billing: dynamodb.Billing.onDemand(),
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      replicas,
    });

    cdk.Tags.of(this).add("project", "forgeguard");
    cdk.Tags.of(this).add("environment", props.environment);

    new cdk.CfnOutput(this, "TableName", {
      value: table.tableName,
    });

    new cdk.CfnOutput(this, "TableArn", {
      value: table.tableArn,
    });
  }
}
