# IAM Policy Auditor

A read-only AWS IAM security scanner that checks an account against common
least-privilege and credential-hygiene best practices, and outputs a clean,
severity-ranked report.

## Why I built this

Misconfigured IAM permissions are one of the most common root causes of
real-world cloud breaches — overly broad policies, stale credentials, and
unused roles quietly expand an account's attack surface over time. This tool
automates the kind of manual review a cloud security engineer would otherwise
do by hand: pulling every user, role, and policy in an account and flagging
patterns that violate the principle of least privilege.

## What it checks

| Check | Severity | Why it matters |
|---|---|---|
| Wildcard policies (`Action:*`, `Resource:*`) | High | Grants effectively unrestricted access — the single most dangerous IAM misconfiguration. |
| Users without MFA | High | Single-factor credentials are the easiest entry point for account compromise. |
| Stale access keys (>90 days) | Medium | Long-lived, unrotated keys increase the blast radius of a leaked credential. |
| Unused / orphaned roles | Medium | Unused permissions are attack surface with no offsetting benefit. |
| Inline policies | Low | Harder to audit, version, and reuse than managed policies — a hygiene issue, not an active risk. |

## How it works

1. `iam_auditor.py` connects to AWS via `boto3` (read-only calls only —
   `get_account_authorization_details`, `list_mfa_devices`,
   `list_access_keys`, `get_role`) and runs each check against the account.
2. Findings are written to `iam_audit_findings.json` and `.csv`.
3. `report_generator.py` turns the JSON into a polished, shareable HTML
   report with a severity summary and clear remediation guidance per finding.

## Usage

```bash
pip install boto3

# Configure AWS credentials with READ-ONLY IAM permissions first
# (see "Required permissions" below)

python iam_auditor.py
python report_generator.py iam_audit_findings.json report.html
```

## Required IAM permissions

This tool only needs read access. Attach a policy like this to the
credentials you run it with — never use admin credentials to run a security
scanner:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountAuthorizationDetails",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetRole"
      ],
      "Resource": "*"
    }
  ]
}
```

## Safety notes

- This tool is **read-only** — it never modifies, deletes, or creates IAM
  resources.
- Only run it against AWS accounts you own or have explicit written
  permission to audit. Scanning IAM configuration on an account you don't
  control, even read-only, can look like reconnaissance and may violate
  acceptable use policies.
- Recommended: test first in a free-tier sandbox account with a few
  deliberately misconfigured test users/roles, so you can verify each check
  fires correctly before running against anything real.

## Possible extensions

- Add CIS AWS Foundations Benchmark mapping to each finding
- Support Azure (via `azure-mgmt-authorization`) for multi-cloud coverage
- Scheduled scanning + Slack/email alerting on new High findings
- Historical trend tracking (is the account's posture improving over time?)

## Author

Built by Meo as a cloud security portfolio project.
