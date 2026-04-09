import * as cdk from "aws-cdk-lib";
import { aws_verifiedpermissions as vp } from "aws-cdk-lib";
import { Construct } from "constructs";

interface VerifiedPermissionsStackProps extends cdk.StackProps {
  environment: string;
}

export class VerifiedPermissionsStack extends cdk.Stack {
  constructor(
    scope: Construct,
    id: string,
    props: VerifiedPermissionsStackProps,
  ) {
    super(scope, id, props);

    const policyStore = new vp.CfnPolicyStore(this, "PolicyStore", {
      validationSettings: { mode: "OFF" },
    });

    cdk.Tags.of(this).add("project", "forgeguard");
    cdk.Tags.of(this).add("environment", props.environment);

    new cdk.CfnOutput(this, "PolicyStoreId", {
      value: policyStore.attrPolicyStoreId,
    });
  }
}
