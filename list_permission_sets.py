#! /usr/bin/env python

import argparse
import functools
import json
from datetime import date, datetime
from enum import IntEnum

import boto3
from rich.console import Console
from rich.table import Table


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


class OutputFormat(IntEnum):
    JSON = 0
    TABLE = 1


def main(args):
    """
    List permission sets.
    """
    arn_prefix = "arn:aws:sso:::permissionSet/"
    arn_prefix_size = len(arn_prefix)
    output_format = args.output
    if args.output == OutputFormat.JSON:
        print("[")
    if output_format == OutputFormat.TABLE:
        table = create_output_table()
    id_center_arn, id_store_id = get_identity_center()
    client = boto3.client("sso-admin")
    for n, perm_set_arn in enumerate(generate_permission_sets()):
        response = client.describe_permission_set(
            InstanceArn=id_center_arn, PermissionSetArn=perm_set_arn
        )
        perm_set = response["PermissionSet"]
        if output_format == OutputFormat.JSON:
            if n != 0:
                print(",")
            print(json.dumps(perm_set, indent=4, default=json_serial), end="")
        if output_format == OutputFormat.TABLE:
            name = perm_set["Name"]
            created = perm_set["CreatedDate"].strftime("%Y-%m-%d")
            # duration = perm_set.get("SessionDuration", "")
            desc = perm_set.get("Description", "")
            arn = perm_set_arn[arn_prefix_size:]
            table.add_row(name, created, arn, desc)
    if output_format == OutputFormat.JSON:
        print("")
        print("]")
    if output_format == OutputFormat.TABLE:
        console = Console()
        console.print(table)


def create_output_table():
    """
    Create output table.
    """
    table = Table(title="Permission Sets")
    table.add_column("Name", justify="right", style="green")
    table.add_column("Created", justify="right", style="cyan")
    table.add_column("ARN suffix", justify="right", style="cyan")
    # table.add_column("Duration", justify="right", style="cyan")
    table.add_column("Description", justify="left", style="green")
    return table


def generate_permission_sets():
    """
    Generate permission sets.
    """
    id_center_arn, id_store_id = get_identity_center()
    client = boto3.client("sso-admin")
    paginator = client.get_paginator("list_permission_sets")
    page_iterator = paginator.paginate(InstanceArn=id_center_arn)
    for page in page_iterator:
        for perm_set in page["PermissionSets"]:
            yield perm_set


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


if __name__ == "__main__":
    parser = argparse.ArgumentParser("List permission sets")
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "-j",
        "--json",
        action="store_const",
        dest="output",
        const=OutputFormat.JSON,
        help="Output in JSON format.",
    )
    output_group.add_argument(
        "-t",
        "--table",
        action="store_const",
        dest="output",
        const=OutputFormat.TABLE,
        help="Output in tabular format.",
    )
    parser.set_defaults(output=OutputFormat.JSON)
    args = parser.parse_args()
    main(args)
