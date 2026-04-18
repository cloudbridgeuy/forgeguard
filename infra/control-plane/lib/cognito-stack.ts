import * as cdk from "aws-cdk-lib";
import { aws_cognito as cognito } from "aws-cdk-lib";
import { Construct } from "constructs";

interface CognitoStackProps extends cdk.StackProps {
  environment: string;
}

export class CognitoStack extends cdk.Stack {
  public readonly userPool: cognito.UserPool;
  public readonly appClient: cognito.UserPoolClient;

  constructor(scope: Construct, id: string, props: CognitoStackProps) {
    super(scope, id, props);

    this.userPool = new cognito.UserPool(this, "DashboardUserPool", {
      userPoolName: `forgeguard-${props.environment}-dashboard-users`,
      selfSignUpEnabled: false,
      signInAliases: { username: true, email: true },
      passwordPolicy: {
        minLength: 12,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      mfa: cognito.Mfa.OPTIONAL,
      mfaSecondFactor: { sms: false, otp: true },
      customAttributes: {
        org_id: new cognito.StringAttribute({ mutable: false }),
      },
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.appClient = this.userPool.addClient("DashboardClient", {
      userPoolClientName: `forgeguard-${props.environment}-dashboard`,
      generateSecret: false,
      authFlows: { userSrp: true, adminUserPassword: true },
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.PROFILE,
        ],
        callbackUrls: ["http://localhost:5173/callback"],
        logoutUrls: ["http://localhost:5173/"],
      },
    });

    this.userPool.addDomain("DashboardDomain", {
      cognitoDomain: {
        domainPrefix: `forgeguard-${props.environment}`,
      },
    });

    new cognito.CfnUserPoolGroup(this, "AdminGroup", {
      userPoolId: this.userPool.userPoolId,
      groupName: "admin",
      description: "Full control plane access",
      precedence: 0,
    });

    new cognito.CfnUserPoolGroup(this, "OwnerGroup", {
      userPoolId: this.userPool.userPoolId,
      groupName: "owner",
      description: "Organization owner access",
      precedence: 10,
    });

    new cognito.CfnUserPoolGroup(this, "MemberGroup", {
      userPoolId: this.userPool.userPoolId,
      groupName: "member",
      description: "Organization member access",
      precedence: 20,
    });

    cdk.Tags.of(this).add("project", "forgeguard");
    cdk.Tags.of(this).add("environment", props.environment);

    new cdk.CfnOutput(this, "UserPoolId", {
      value: this.userPool.userPoolId,
    });

    new cdk.CfnOutput(this, "UserPoolArn", {
      value: this.userPool.userPoolArn,
    });

    new cdk.CfnOutput(this, "AppClientId", {
      value: this.appClient.userPoolClientId,
    });

    new cdk.CfnOutput(this, "JwksUrl", {
      value: `https://cognito-idp.${cdk.Stack.of(this).region}.amazonaws.com/${this.userPool.userPoolId}/.well-known/jwks.json`,
    });

    new cdk.CfnOutput(this, "Issuer", {
      value: `https://cognito-idp.${cdk.Stack.of(this).region}.amazonaws.com/${this.userPool.userPoolId}`,
    });
  }
}
