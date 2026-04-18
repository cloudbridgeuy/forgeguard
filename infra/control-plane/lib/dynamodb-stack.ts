import * as cdk from "aws-cdk-lib";
import { aws_dynamodb as dynamodb } from "aws-cdk-lib";
import { Construct } from "constructs";
import schema from "../schema/forgeguard-orgs.json";

interface DynamoDbStackProps extends cdk.StackProps {
  environment: string;
}

export class DynamoDbStack extends cdk.Stack {
  public readonly table!: dynamodb.TableV2;

  constructor(scope: Construct, id: string, props: DynamoDbStackProps) {
    super(scope, id, props);

    const GSI1_INDEX_NAME = "GSI1";

    // Exclude the primary region from the replica list to avoid CDK errors.
    const primaryRegion = cdk.Stack.of(this).region;
    const allReplicaRegions = ["us-east-1", "us-east-2", "us-west-2"];
    const replicas = allReplicaRegions
      .filter((r) => r !== primaryRegion)
      .map((region) => ({ region }));

    this.table = new dynamodb.TableV2(this, "OrgsTable", {
      tableName: `forgeguard-${props.environment}-orgs`,
      partitionKey: { name: schema.partitionKey, type: dynamodb.AttributeType.STRING },
      sortKey: { name: schema.sortKey, type: dynamodb.AttributeType.STRING },
      billing: dynamodb.Billing.onDemand(),
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      dynamoStream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
      globalSecondaryIndexes: [
        {
          indexName: GSI1_INDEX_NAME,
          partitionKey: { name: schema.sortKey, type: dynamodb.AttributeType.STRING },
          sortKey: { name: schema.partitionKey, type: dynamodb.AttributeType.STRING },
        },
      ],
      replicas,
    });

    cdk.Tags.of(this).add("project", "forgeguard");
    cdk.Tags.of(this).add("environment", props.environment);

    new cdk.CfnOutput(this, "TableName", {
      value: this.table.tableName,
    });

    new cdk.CfnOutput(this, "TableArn", {
      value: this.table.tableArn,
    });

    new cdk.CfnOutput(this, "GSI1Name", {
      value: GSI1_INDEX_NAME,
    });
  }
}
