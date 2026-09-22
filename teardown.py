
import boto3

iam = boto3.client("iam")


def delete_user_completely(username):
    """IAM won't delete a user that still has policies/keys attached,
    so this cleans those up first."""
    print(f"[*] Cleaning up user '{username}'...")

    # Delete inline policies
    try:
        policy_names = iam.list_user_policies(UserName=username)["PolicyNames"]
        for name in policy_names:
            iam.delete_user_policy(UserName=username, PolicyName=name)
            print(f"    Deleted inline policy: {name}")
    except iam.exceptions.NoSuchEntityException:
        print(f"    User '{username}' doesn't exist, skipping.")
        return

    # Detach managed policies
    attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
    for policy in attached:
        iam.detach_user_policy(UserName=username, PolicyArn=policy["PolicyArn"])
        print(f"    Detached managed policy: {policy['PolicyName']}")

    # Delete access keys
    keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
    for key in keys:
        iam.delete_access_key(UserName=username, AccessKeyId=key["AccessKeyId"])
        print(f"    Deleted access key: {key['AccessKeyId']}")

    # Delete MFA devices, if any were added
    mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
    for device in mfa_devices:
        iam.deactivate_mfa_device(UserName=username, SerialNumber=device["SerialNumber"])
        print(f"    Deactivated MFA device: {device['SerialNumber']}")

    # Finally, delete the user
    iam.delete_user(UserName=username)
    print(f"    Deleted user: {username}")


def delete_role_completely(role_name):
    print(f"[*] Cleaning up role '{role_name}'...")
    try:
        policy_names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        for name in policy_names:
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
            print(f"    Deleted inline policy: {name}")
    except iam.exceptions.NoSuchEntityException:
        print(f"    Role '{role_name}' doesn't exist, skipping.")
        return

    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    for policy in attached:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy["PolicyArn"])
        print(f"    Detached managed policy: {policy['PolicyName']}")

    iam.delete_role(RoleName=role_name)
    print(f"    Deleted role: {role_name}")


def delete_managed_policy(policy_name):
    print(f"[*] Cleaning up managed policy '{policy_name}'...")
    account_id = boto3.client("sts").get_caller_identity()["Account"]
    policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"

    try:
        # Detach from any entities first (shouldn't be any in this test setup,
        # but check to be safe)
        entities = iam.list_entities_for_policy(PolicyArn=policy_arn)
        for user in entities.get("PolicyUsers", []):
            iam.detach_user_policy(UserName=user["UserName"], PolicyArn=policy_arn)
        for role in entities.get("PolicyRoles", []):
            iam.detach_role_policy(RoleName=role["RoleName"], PolicyArn=policy_arn)

        iam.delete_policy(PolicyArn=policy_arn)
        print(f"    Deleted policy: {policy_name}")
    except iam.exceptions.NoSuchEntityException:
        print(f"    Policy '{policy_name}' doesn't exist, skipping.")


if __name__ == "__main__":
    print("=" * 60)
    print("SANDBOX TEARDOWN — removing test IAM resources")
    print("=" * 60)

    confirm = input("\nType 'yes' to remove all sandbox test resources: ")
    if confirm.strip().lower() != "yes":
        print("Aborted.")
        exit(0)

    delete_user_completely("dev-user-1")
    delete_user_completely("dev-user-2")
    delete_role_completely("legacy-migration-role")
    delete_managed_policy("AdminAccessPolicy")

    print("\n[*] Teardown complete. Sandbox account is clean.")
