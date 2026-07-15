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

    // Two-phase GSI1 migration (dense PK/SK inversion -> sparse GSI1PK/GSI1SK):
    // CloudFormation refuses to change an existing GSI's KeySchema in place
    // ("Cannot update a GSI's KeySchema or Projection. You can create a new
    // GSI with a different name."). Phase 1 removed the old GSI1 entirely;
    // this is phase 2, re-adding it with the sparse schema below.
    //
    // Sparse (D10): only items that explicitly carry GSI1PK/GSI1SK — today
    // just `membership` — appear in this index. The append-spine's `seq`
    // counter and `event`/`principal` items never set these attributes, so
    // they stay out of it entirely, instead of the old full-table PK/SK
    // inversion where every item was indexed.
    //
    // Replicas are pinned to the live us-west-2/us-east-1 set as an interim
    // step so this deploy changes only the GSI, not the replica count too --
    // CloudFormation also rejects removing more than one replica per update
    // ("You can only add or remove a single replica in each update
    // operation."). The replica count drops to zero extras in a later,
    // separate deploy, one region at a time.
    this.table = new dynamodb.TableV2(this, "OrgsTable", {
      tableName: `forgeguard-${props.environment}-orgs`,
      partitionKey: { name: schema.partitionKey, type: dynamodb.AttributeType.STRING },
      sortKey: { name: schema.sortKey, type: dynamodb.AttributeType.STRING },
      billing: dynamodb.Billing.onDemand(),
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      dynamoStream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
      replicas: [{ region: "us-west-2" }, { region: "us-east-1" }],
      globalSecondaryIndexes: [
        {
          indexName: GSI1_INDEX_NAME,
          partitionKey: { name: "GSI1PK", type: dynamodb.AttributeType.STRING },
          sortKey: { name: "GSI1SK", type: dynamodb.AttributeType.STRING },
        },
      ],
    });

    cdk.Tags.of(this).add("project", "forgeguard");
    cdk.Tags.of(this).add("environment", props.environment);

    new cdk.CfnOutput(this, "TableName", {
      value: this.table.tableName,
    });

    new cdk.CfnOutput(this, "TableArn", {
      value: this.table.tableArn,
    });
  }
}
