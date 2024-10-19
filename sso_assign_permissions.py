#! /usr/bin/env python

import argparse
import functools

import boto3


def main(args):
    """
    Assign permissions to a principal for one or more accounts.
    """
    # Look up principal ID.
    principal = args.principal
    if args.group:
        principal_id = lookup_group_principal(principal)
        principal_type = "GROUP"
    else:
        principal_id = lookup_user_principal(principal)
        principal_type = "USER"
    account_ids = None
    if args.accounts_file:
        account_ids = parse_accounts(args.accounts_file)
    if args.delete:
        remove_permissions(
            args.perm_arn, principal_id, principal_type, account_ids=account_ids
        )
    else:
        assign_permissions(
            args.perm_arn, principal_id, principal_type, account_ids=account_ids
        )


def parse_accounts(f):
    """
    Parse account IDs.
    """
    account_ids = set([])
    for line in f:
        row = line.strip()
        if row.startswith("#"):
            continue
        account_ids.add(row)
    return account_ids


def assign_permissions(perm_arn, principal_id, principal_type, account_ids=None):
    """
    Assign permissions to principal.
    """
    client = boto3.client("sso-admin")
    iam_id_center_arn, identity_store_id = get_identity_center()
    for account_id, account_name in generate_accounts():
        if account_ids is not None:
            if account_id not in account_ids:
                continue
        response = client.create_account_assignment(
            InstanceArn=iam_id_center_arn,
            PermissionSetArn=perm_arn,
            PrincipalId=principal_id,
            PrincipalType=principal_type,
            TargetId=account_id,
            TargetType="AWS_ACCOUNT",
        )
        result = response["AccountAssignmentCreationStatus"]
        failure_reason = result.get("FailureReason")
        if failure_reason:
            print(f"FAILURE: {account_id} - {account_name} : {failure_reason}")
        else:
            print(f"SUCCESS: {account_id} - {account_name}")


def remove_permissions(perm_arn, principal_id, principal_type, account_ids=None):
    """
    Removes permissions from a principal.
    """
    client = boto3.client("sso-admin")
    iam_id_center_arn, identity_store_id = get_identity_center()
    for account_id, account_name in generate_accounts():
        if account_ids is not None:
            if account_id not in account_ids:
                continue
        response = client.delete_account_assignment(
            InstanceArn=iam_id_center_arn,
            PermissionSetArn=perm_arn,
            PrincipalId=principal_id,
            PrincipalType=principal_type,
            TargetId=account_id,
            TargetType="AWS_ACCOUNT",
        )
        result = response["AccountAssignmentDeletionStatus"]
        failure_reason = result.get("FailureReason")
        if failure_reason:
            print(f"FAILURE: {account_id} - {account_name} : {failure_reason}")
        else:
            print(f"SUCCESS: {account_id} - {account_name}")


def lookup_user_principal(principal):
    """
    Lookup a principal ID for a user.
    """
    iam_id_center_arn, identity_store_id = get_identity_center()
    client = boto3.client("identitystore")
    resp = client.get_user_id(
        IdentityStoreId=identity_store_id,
        AlternateIdentifier={
            "UniqueAttribute": {
                "AttributePath": "userName",
                "AttributeValue": principal,
            }
        },
    )
    group_id = resp["UserId"]
    return group_id


def lookup_group_principal(principal):
    """
    Lookup a principal ID for a group.
    """
    iam_id_center_arn, identity_store_id = get_identity_center()
    client = boto3.client("identitystore")
    resp = client.get_group_id(
        IdentityStoreId=identity_store_id,
        AlternateIdentifier={
            "UniqueAttribute": {
                "AttributePath": "displayName",
                "AttributeValue": principal,
            }
        },
    )
    group_id = resp["GroupId"]
    return group_id


@functools.lru_cache
def get_identity_center():
    """
    Get the identity center.
    """
    client = boto3.client("sso-admin")
    response = client.list_instances()
    instances = response["Instances"]
    instance = instances[0]
    identity_store_id = instance["IdentityStoreId"]
    iam_id_center_arn = instance["InstanceArn"]
    return iam_id_center_arn, identity_store_id


def generate_accounts():
    """
    Generates accounts.
    """
    client = boto3.client("organizations")
    paginator = client.get_paginator("list_accounts")
    page_iterator = paginator.paginate()
    for page in page_iterator:
        for account in page["Accounts"]:
            yield account["Id"], account["Name"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        "Assign SSO permssions to a principal for AWS account(s)."
    )
    parser.add_argument("perm_arn", action="store", help="Permission set ARN.")
    parser.add_argument(
        "principal",
        action="store",
        help="The principal that permissions are assigned to.",
    )
    parser.add_argument(
        "-g", "--group", action="store_true", help="Principal is a group."
    )
    parser.add_argument("--delete", action="store_true", help="Remove the permission.")
    parser.add_argument(
        "-a",
        "--accounts-file",
        action="store",
        type=argparse.FileType("r"),
        help="File of AWS account IDs, one per line.",
    )
    args = parser.parse_args()
    main(args)
