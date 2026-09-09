
import boto3
import json
import csv
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import List


# Data model

@dataclass
class Finding:
    severity: str          # High / Medium / Low
    category: str          # e.g. "Wildcard Policy", "Stale Access Key"
    resource_type: str     # User / Role / Policy
    resource_name: str
    description: str
    recommendation: str


# Auditor

class IAMAuditor:
    def __init__(self, session: boto3.Session = None):
        self.iam = (session or boto3.Session()).client("iam")
        self.findings: List[Finding] = []

    def run_all_checks(self):
        print("[*] Pulling account authorization details...")
        auth_details = self._get_account_authorization_details()

        print("[*] Checking for wildcard (overly permissive) policies...")
        self._check_wildcard_policies(auth_details)

        print("[*] Checking for inline policies...")
        self._check_inline_policies(auth_details)

        print("[*] Checking for orphaned / unused roles...")
        self._check_unused_roles(auth_details)

        print("[*] Checking user credential hygiene (MFA, key age)...")
        self._check_user_credentials()

        print(f"[*] Scan complete. {len(self.findings)} finding(s).")
        return self.findings

    # -- data pull 

    def _get_account_authorization_details(self):
        """Single efficient call that returns users, roles, groups, and
        their attached/inline policies in one shot."""
        paginator = self.iam.get_paginator("get_account_authorization_details")
        users, roles, groups, policies = [], [], [], []
        for page in paginator.paginate():
            users.extend(page.get("UserDetailList", []))
            roles.extend(page.get("RoleDetailList", []))
            groups.extend(page.get("GroupDetailList", []))
            policies.extend(page.get("Policies", []))
        return {"users": users, "roles": roles, "groups": groups, "policies": policies}

    # -- checks 

    def _policy_has_wildcard(self, policy_document) -> bool:
        statements = policy_document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            if "*" in actions and "*" in resources:
                return True
        return False

    def _check_wildcard_policies(self, auth_details):
        for policy in auth_details["policies"]:
            # Get the default version's document
            default_version_id = policy["DefaultVersionId"]
            versions = policy.get("PolicyVersionList", [])
            doc = next(
                (v["Document"] for v in versions if v["VersionId"] == default_version_id),
                None,
            )
            if doc and self._policy_has_wildcard(doc):
                self.findings.append(Finding(
                    severity="High",
                    category="Wildcard Policy",
                    resource_type="Policy",
                    resource_name=policy["PolicyName"],
                    description=(
                        f"Managed policy '{policy['PolicyName']}' grants "
                        f"Action:* on Resource:* (full administrative access)."
                    ),
                    recommendation=(
                        "Replace wildcard actions/resources with the specific "
                        "services, actions, and ARNs the attached identities "
                        "actually need. Use IAM Access Analyzer's policy "
                        "generator to derive a least-privilege policy from "
                        "observed activity."
                    ),
                ))

        # Also check inline policies on users and roles for wildcards
        for user in auth_details["users"]:
            for inline in user.get("UserPolicyList", []):
                if self._policy_has_wildcard(inline["PolicyDocument"]):
                    self.findings.append(Finding(
                        severity="High",
                        category="Wildcard Policy",
                        resource_type="User (inline)",
                        resource_name=f"{user['UserName']} / {inline['PolicyName']}",
                        description=(
                            f"Inline policy '{inline['PolicyName']}' on user "
                            f"'{user['UserName']}' grants Action:* on Resource:*."
                        ),
                        recommendation=(
                            "Scope this policy down to specific actions/resources "
                            "and consider moving it to a managed policy for auditability."
                        ),
                    ))

        for role in auth_details["roles"]:
            for inline in role.get("RolePolicyList", []):
                if self._policy_has_wildcard(inline["PolicyDocument"]):
                    self.findings.append(Finding(
                        severity="High",
                        category="Wildcard Policy",
                        resource_type="Role (inline)",
                        resource_name=f"{role['RoleName']} / {inline['PolicyName']}",
                        description=(
                            f"Inline policy '{inline['PolicyName']}' on role "
                            f"'{role['RoleName']}' grants Action:* on Resource:*."
                        ),
                        recommendation=(
                            "Scope this policy down to specific actions/resources "
                            "needed for the role's actual workload."
                        ),
                    ))

    def _check_inline_policies(self, auth_details):
        """Inline policies (as opposed to managed) are harder to audit,
        version, and reuse — flag their mere presence as Medium/Low."""
        for user in auth_details["users"]:
            for inline in user.get("UserPolicyList", []):
                self.findings.append(Finding(
                    severity="Low",
                    category="Inline Policy",
                    resource_type="User",
                    resource_name=f"{user['UserName']} / {inline['PolicyName']}",
                    description=(
                        f"User '{user['UserName']}' has inline policy "
                        f"'{inline['PolicyName']}' attached directly, rather "
                        f"than a managed policy."
                    ),
                    recommendation=(
                        "Convert to a customer-managed policy. Inline policies "
                        "can't be versioned, reused, or centrally audited, which "
                        "makes drift harder to detect over time."
                    ),
                ))

        for role in auth_details["roles"]:
            for inline in role.get("RolePolicyList", []):
                self.findings.append(Finding(
                    severity="Low",
                    category="Inline Policy",
                    resource_type="Role",
                    resource_name=f"{role['RoleName']} / {inline['PolicyName']}",
                    description=(
                        f"Role '{role['RoleName']}' has inline policy "
                        f"'{inline['PolicyName']}' attached directly, rather "
                        f"than a managed policy."
                    ),
                    recommendation=(
                        "Convert to a customer-managed policy for versioning "
                        "and centralized review."
                    ),
                ))

    def _check_unused_roles(self, auth_details, stale_days: int = 90):
        now = datetime.now(timezone.utc)
        for role in auth_details["roles"]:
            role_name = role["RoleName"]
            # Skip AWS service-linked roles — these are managed by AWS itself
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            try:
                resp = self.iam.get_role(RoleName=role_name)
                role_last_used = resp["Role"].get("RoleLastUsed", {})
                last_used_date = role_last_used.get("LastUsedDate")
            except Exception:
                last_used_date = None

            if last_used_date is None:
                self.findings.append(Finding(
                    severity="Medium",
                    category="Unused Role",
                    resource_type="Role",
                    resource_name=role_name,
                    description=(
                        f"Role '{role_name}' has no recorded usage "
                        f"(never assumed, or usage data unavailable)."
                    ),
                    recommendation=(
                        "Confirm whether this role is still needed. If not, "
                        "remove it — unused roles with attached permissions "
                        "are unnecessary attack surface."
                    ),
                ))
            else:
                age_days = (now - last_used_date).days
                if age_days > stale_days:
                    self.findings.append(Finding(
                        severity="Medium",
                        category="Stale Role",
                        resource_type="Role",
                        resource_name=role_name,
                        description=(
                            f"Role '{role_name}' was last used {age_days} days ago "
                            f"(threshold: {stale_days} days)."
                        ),
                        recommendation=(
                            "Review whether this role is still required. "
                            "Consider deactivating or deleting it if it's no "
                            "longer part of an active workflow."
                        ),
                    ))

    def _check_user_credentials(self, key_age_days: int = 90):
        now = datetime.now(timezone.utc)
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]

                # MFA check
                mfa_devices = self.iam.list_mfa_devices(UserName=username)["MFADevices"]
                if not mfa_devices:
                    self.findings.append(Finding(
                        severity="High",
                        category="No MFA",
                        resource_type="User",
                        resource_name=username,
                        description=f"User '{username}' does not have MFA enabled.",
                        recommendation=(
                            "Require MFA for all IAM users, especially any with "
                            "console access or elevated permissions. Enforce via "
                            "an IAM policy condition (aws:MultiFactorAuthPresent)."
                        ),
                    ))

                # Access key age check
                keys = self.iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                for key in keys:
                    if key["Status"] != "Active":
                        continue
                    age_days = (now - key["CreateDate"]).days
                    if age_days > key_age_days:
                        self.findings.append(Finding(
                            severity="Medium",
                            category="Stale Access Key",
                            resource_type="User",
                            resource_name=f"{username} / {key['AccessKeyId']}",
                            description=(
                                f"Access key for '{username}' is {age_days} days old "
                                f"(threshold: {key_age_days} days)."
                            ),
                            recommendation=(
                                "Rotate access keys regularly. Where possible, "
                                "replace long-lived access keys with temporary "
                                "credentials via IAM roles or AWS SSO."
                            ),
                        ))


# Report output


def export_json(findings: List[Finding], path: str):
    with open(path, "w") as f:
        json.dump([asdict(f) for f in findings], f, indent=2)


def export_csv(findings: List[Finding], path: str):
    fieldnames = ["severity", "category", "resource_type", "resource_name",
                  "description", "recommendation"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            writer.writerow(asdict(finding))


def print_summary(findings: List[Finding]):
    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    findings_sorted = sorted(findings, key=lambda f: severity_order.get(f.severity, 3))

    counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print("\n" + "=" * 60)
    print("IAM AUDIT SUMMARY")
    print("=" * 60)
    print(f"High:   {counts.get('High', 0)}")
    print(f"Medium: {counts.get('Medium', 0)}")
    print(f"Low:    {counts.get('Low', 0)}")
    print("=" * 60)
    for f in findings_sorted:
        print(f"[{f.severity:6}] {f.category:20} {f.resource_type:15} {f.resource_name}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    auditor = IAMAuditor()
    findings = auditor.run_all_checks()
    print_summary(findings)
    export_json(findings, "iam_audit_findings.json")
    export_csv(findings, "iam_audit_findings.csv")
    print("[*] Reports written: iam_audit_findings.json, iam_audit_findings.csv")
