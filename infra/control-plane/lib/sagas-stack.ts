import * as cdk from "aws-cdk-lib";
import { aws_dynamodb as dynamodb } from "aws-cdk-lib";
import { Construct } from "constructs";

interface SagasStackProps extends cdk.StackProps {
  environment: string;
}

/**
 * Dedicated DynamoDB table for saga tickets.
 *
 * Layout follows `.claude/plans/2026-05-15-issue-100-v3-post-users-saga.md`
 * §7 (DDB Serialization Layout):
 * - PK = ORG#{org_id}
 * - SK = SAGA#USER_CREATE#{ticket_id}
 * - gsi_in_flight (sparse) — projects only items where gsi_pk + gsi_sk are
 *   present, which is true exactly while the saga is non-terminal. Terminal
 *   transitions REMOVE both attributes so the entry drops from the index.
 *
 * DynamoDB Streams (NEW_AND_OLD_IMAGES) are enabled so issue #103 can attach
 * a drain Lambda via the exported stream ARN.
 */
export class SagasStack extends cdk.Stack {
  public readonly sagasTable: dynamodb.TableV2;

  constructor(scope: Construct, id: string, props: SagasStackProps) {
    super(scope, id, props);

    const GSI_IN_FLIGHT = "gsi_in_flight";

    this.sagasTable = new dynamodb.TableV2(this, "SagasTable", {
      tableName: `forgeguard-${props.environment}-sagas`,
      partitionKey: { name: "PK", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "SK", type: dynamodb.AttributeType.STRING },
      billing: dynamodb.Billing.onDemand(),
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      dynamoStream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
      globalSecondaryIndexes: [
        {
          indexName: GSI_IN_FLIGHT,
          partitionKey: { name: "gsi_pk", type: dynamodb.AttributeType.STRING },
          sortKey: { name: "gsi_sk", type: dynamodb.AttributeType.STRING },
        },
      ],
    });

    cdk.Tags.of(this).add("project", "forgeguard");
    cdk.Tags.of(this).add("environment", props.environment);

    new cdk.CfnOutput(this, "SagasTableName", {
      value: this.sagasTable.tableName,
    });

    new cdk.CfnOutput(this, "SagasTableArn", {
      value: this.sagasTable.tableArn,
    });

    // Empty string fallback: TableV2.tableStreamArn is typed as
    // `string | undefined`. The stream is always enabled above, so this is
    // defensive only — issue #103 reads this output to attach the drain
    // Lambda's event-source mapping.
    new cdk.CfnOutput(this, "SagasTableStreamArn", {
      value: this.sagasTable.tableStreamArn ?? "",
    });
  }
}
