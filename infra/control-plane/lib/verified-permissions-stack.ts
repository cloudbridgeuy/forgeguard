import * as cdk from "aws-cdk-lib";
import { aws_verifiedpermissions as vp } from "aws-cdk-lib";
import { Construct } from "constructs";

interface VerifiedPermissionsStackProps extends cdk.StackProps {
  environment: string;
  userPoolArn?: string;
  appClientId?: string;
}

export class VerifiedPermissionsStack extends cdk.Stack {
  public readonly policyStoreId: string;
  public readonly policyStoreArn: string;

  constructor(
    scope: Construct,
    id: string,
    props: VerifiedPermissionsStackProps,
  ) {
    super(scope, id, props);

    const policyStore = new vp.CfnPolicyStore(this, "PolicyStore", {
      validationSettings: { mode: "OFF" },
    });

    this.policyStoreId = policyStore.attrPolicyStoreId;
    // Verified Permissions is a region-less service: ARNs use an empty
    // region segment (`arn:aws:verifiedpermissions::<account>:policy-store/<id>`).
    this.policyStoreArn = cdk.Stack.of(this).formatArn({
      service: "verifiedpermissions",
      region: "",
      resource: "policy-store",
      resourceName: policyStore.attrPolicyStoreId,
      arnFormat: cdk.ArnFormat.SLASH_RESOURCE_NAME,
    });

    if (props.userPoolArn && props.appClientId) {
      new vp.CfnIdentitySource(this, "CognitoIdentitySource", {
        policyStoreId: policyStore.attrPolicyStoreId,
        configuration: {
          cognitoUserPoolConfiguration: {
            userPoolArn: props.userPoolArn,
            clientIds: [props.appClientId],
          },
        },
      });
    }

    cdk.Tags.of(this).add("project", "forgeguard");
    cdk.Tags.of(this).add("environment", props.environment);

    new cdk.CfnOutput(this, "PolicyStoreId", {
      value: policyStore.attrPolicyStoreId,
    });

    new cdk.CfnOutput(this, "PolicyStoreArn", {
      value: this.policyStoreArn,
    });
  }
}
