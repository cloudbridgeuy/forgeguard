import * as cdk from "aws-cdk-lib";
import * as verifiedpermissions from "aws-cdk-lib/aws-verifiedpermissions";
import { Construct } from "constructs";

interface VerifiedPermissionsStackProps extends cdk.StackProps {
  userPoolId: string;
  userPoolArn: string;
}

export class VerifiedPermissionsStack extends cdk.Stack {
  constructor(
    scope: Construct,
    id: string,
    props: VerifiedPermissionsStackProps,
  ) {
    super(scope, id, props);

    const policyStore = new verifiedpermissions.CfnPolicyStore(
      this,
      "PolicyStore",
      {
        // Validation is OFF because no schema is provided at stack creation
        // time. The schema is pushed later via `forgeguard policies sync`.
        validationSettings: {
          mode: "OFF",
        },
      },
    );

    new verifiedpermissions.CfnIdentitySource(this, "CognitoIdentitySource", {
      policyStoreId: policyStore.attrPolicyStoreId,
      configuration: {
        cognitoUserPoolConfiguration: {
          userPoolArn: props.userPoolArn,
          clientIds: [],
          groupConfiguration: {
            groupEntityType: "group",
          },
        },
      },
      principalEntityType: "user",
    });

    new cdk.CfnOutput(this, "PolicyStoreId", {
      value: policyStore.attrPolicyStoreId,
    });
  }
}
