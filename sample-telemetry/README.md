# Sample telemetry

Synthetic breach dataset that lets `ir-agent investigate --sample` run end
to end without any live cloud credentials. Mirrors the leaked-key →
data-exfil narrative walked in the briefing deck.

```
aws/
  cloudtrail.json     – 5 events: 2x S3 GetObject burst → PutUserPolicy
                        (privilege esc) → CreateDBSnapshot → ModifySnapshotAttribute
                        (exfil share to external account 999988887777)
  guardduty.json      – the originating UnauthorizedAccess finding
  vpcflow.json        – one egress flow to 198.51.100.7
  iam_principals.json – the over-permissive `web-prod-ec2` role
  config.json         – AWS Config history showing the policy widened on 2026-05-18

azure/
  signinlogs.json     – AiTM token replay (interactive sign-in then SPN auth from new IP)
  auditlogs.json      – password credential added to a privileged SPN
  activity.json       – storage account SAS issued by the compromised SPN
  graph_activity.json – the SPN mass-reading /users/alice/messages
  officeactivity.json – placeholder (empty)
```

These files contain only fabricated identifiers (RFC 5737 IPs, AROA****X,
example AccessKeyIds). Replace with live telemetry sinks via the boto3 /
Microsoft Graph paths when you remove `--sample`.
