# AWS ARN Formats — Gotchas

A running list of AWS ARN formats that have caused production breakage. The pattern: ARN segments differ per service (region present/empty, account present/empty, resource separator `/` vs `:`), and getting it wrong silently breaks IAM scoping or breaks resource lookup.

## The Rule

**Prefer CDK CFN attribute getters (`construct.attrArn`, `resource.functionArn`, etc.) over `cdk.Stack.formatArn` whenever the ARN comes from a resource we own.** The attribute getter resolves to a CloudFormation `Fn::GetAtt` at synth time and gives us the canonical ARN the service itself produced — no segment-by-segment guesswork.

Only reach for `cdk.Stack.formatArn` when:
- The ARN belongs to a resource not modeled in CDK (cross-account refs, manually provisioned).
- The construct genuinely doesn't expose an ARN attribute.

## Service-Specific Notes

### AWS Verified Permissions

| Aspect | Value |
| ------ | ----- |
| ARN template | `arn:${Partition}:verifiedpermissions::${Account}:policy-store/${PolicyStoreId}` |
| Region segment | **Empty** (`::` between service and account) |
| CDK attribute | `vp.CfnPolicyStore.attrArn` (CFN `Fn::GetAtt PolicyStore.Arn`) |
| IAM action | `verifiedpermissions:IsAuthorized` (and `IsAuthorizedWithToken` if using Cognito identity sources) — `policy-store` resource scope is required (no `*`). |
| Source | [Service Authorization Reference — VerifiedPermissions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonverifiedpermissions.html) |

**The trap:** Constructing the ARN with `cdk.Stack.formatArn({ service: 'verifiedpermissions', resource: 'policy-store', resourceName: id })` may default `region` to the stack's region, producing `arn:aws:verifiedpermissions:us-east-2:<account>:policy-store/<id>`. IAM will silently reject this against the service's canonical ARN (which has an empty region segment). Lambda calls then fail with `AccessDeniedException` despite the policy "looking right."

**The fix:** `policyStore.attrArn` directly. Bit us during issue #85 cold-start triage.

---

## Adding to This Doc

When an ARN-format mismatch causes an outage or PR rework, add the service here with:
1. The canonical ARN template (verbatim from AWS docs)
2. The CDK attribute getter that returns it
3. A one-line "the trap" describing what went wrong before
