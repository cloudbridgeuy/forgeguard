import * as cdk from "aws-cdk-lib";
import * as cognito from "aws-cdk-lib/aws-cognito";
import { Construct } from "constructs";

interface CognitoStackProps extends cdk.StackProps {
  groups: string[];
}

export class CognitoStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: CognitoStackProps) {
    super(scope, id, props);

    const userPool = new cognito.UserPool(this, "UserPool", {
      userPoolName: `${id}-user-pool`,
      selfSignUpEnabled: false,
      signInAliases: { username: true, email: true },
      autoVerify: { email: true },
      standardAttributes: {
        email: { required: true, mutable: true },
      },
      customAttributes: {
        org_id: new cognito.StringAttribute({ mutable: true }),
      },
      passwordPolicy: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const appClient = userPool.addClient("AppClient", {
      userPoolClientName: `${id}-app-client`,
      authFlows: {
        userPassword: true,
        userSrp: true,
      },
      generateSecret: false,
    });

    for (const groupName of props.groups) {
      new cognito.CfnUserPoolGroup(this, `Group-${groupName}`, {
        userPoolId: userPool.userPoolId,
        groupName,
      });
    }

    const region = cdk.Stack.of(this).region;
    const issuerUrl = `https://cognito-idp.${region}.amazonaws.com/${userPool.userPoolId}`;

    new cdk.CfnOutput(this, "UserPoolId", {
      value: userPool.userPoolId,
    });

    new cdk.CfnOutput(this, "AppClientId", {
      value: appClient.userPoolClientId,
    });

    new cdk.CfnOutput(this, "JwksUrl", {
      value: `${issuerUrl}/.well-known/jwks.json`,
    });

    new cdk.CfnOutput(this, "Issuer", {
      value: issuerUrl,
    });
  }
}
