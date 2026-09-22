
import boto3
import json
import time

iam = boto3.client("iam")

WILDCARD_POLICY_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"}
    ],
}

INLINE_TEMP_ACCESS_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": "*",
        }
    ],
}

EC2_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def create_wildcard_managed_policy():
    print("[*] Creating managed policy 'AdminAccessPolicy' (wildcard)...")
    try:
        resp = iam.create_policy(
            PolicyName="AdminAccessPolicy",
            PolicyDocument=json.dumps(WILDCARD_POLICY_DOC),
            Description="TEST RESOURCE - intentionally overpermissive for auditor testing",
        )
        print(f"    Created: {resp['Policy']['Arn']}")
    except iam.exceptions.EntityAlreadyExistsException:
        print("    Already exists, skipping.")


def create_dev_user_1():
    """User with: no MFA, an access key, and a wildcard inline policy."""
    username = "dev-user-1"
    print(f"[*] Creating user '{username}'...")
    try:
        iam.create_user(UserName=username)
    except iam.exceptions.EntityAlreadyExistsException:
        print("    User already exists, skipping creation.")

    print(f"    Attaching wildcard inline policy to '{username}'...")
    iam.put_user_policy(
        UserName=username,
        PolicyName="wildcard-inline-policy",
        PolicyDocument=json.dumps(WILDCARD_POLICY_DOC),
    )

    print(f"    Creating access key for '{username}'...")
    try:
        key_resp = iam.create_access_key(UserName=username)
        print(f"    Access Key ID: {key_resp['AccessKey']['AccessKeyId']}")
        print("    (Store or discard this — it's a test credential, not a real one to keep.)")
    except iam.exceptions.LimitExceededException:
        print("    User already has max access keys, skipping.")

    # Deliberately NOT enabling MFA — that's the point of this test user.


def create_dev_user_2():
    """User with an inline policy (non-wildcard, but still inline)."""
    username = "dev-user-2"
    print(f"[*] Creating user '{username}'...")
    try:
        iam.create_user(UserName=username)
    except iam.exceptions.EntityAlreadyExistsException:
        print("    User already exists, skipping creation.")

    print(f"    Attaching scoped inline policy 'temp-access' to '{username}'...")
    iam.put_user_policy(
        UserName=username,
        PolicyName="temp-access",
        PolicyDocument=json.dumps(INLINE_TEMP_ACCESS_DOC),
    )


def create_unused_role():
    role_name = "legacy-migration-role"
    print(f"[*] Creating role '{role_name}' (will remain unused)...")
    try:
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(EC2_TRUST_POLICY),
            Description="TEST RESOURCE - intentionally unused for auditor testing",
        )
    except iam.exceptions.EntityAlreadyExistsException:
        print("    Role already exists, skipping.")

    print("    Attaching a basic read-only policy so it has real permissions to flag...")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3-read-only",
        PolicyDocument=json.dumps(INLINE_TEMP_ACCESS_DOC),
    )
    # This role is never assumed by anything — that's intentional.


if __name__ == "__main__":
    print("=" * 60)
    print("SANDBOX SETUP - creating intentionally misconfigured IAM resources")
    print("Only run this against a personal sandbox AWS account.")
    print("=" * 60)

    confirm = input("\nType 'yes' to confirm this is a sandbox account: ")
    if confirm.strip().lower() != "yes":
        print("Aborted.")
        exit(0)

    create_wildcard_managed_policy()
    create_dev_user_1()
    create_dev_user_2()
    create_unused_role()

    print("\n[*] Done. Wait a few seconds for IAM to propagate, then run:")
    print("    python iam_auditor.py")
    print("\n[*] When you're finished testing, run teardown.py to clean up.")
