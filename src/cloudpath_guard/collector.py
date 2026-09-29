"""Read-only AWS SDK calls; partial failures remain visible in the snapshot."""
from datetime import datetime, timezone
from urllib.parse import unquote
import json


def collect(region, profile=None, session=None):
    client_options = {}
    if session is None:
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("Install the AWS extra: pip install -e '.[aws]'") from exc
        from botocore.config import Config
        session = boto3.Session(profile_name=profile, region_name=region)
        client_options["config"] = Config(connect_timeout=5, read_timeout=20, retries={"max_attempts": 2, "mode": "standard"})
    ec2, iam, sts = [session.client(service, region_name=region, **client_options) for service in ("ec2", "iam", "sts")]
    snapshot = {"schema_version": 1, "account": "unknown", "region": region,
                "collected_at": datetime.now(timezone.utc).isoformat(), "instances": [],
                "security_groups": [], "route_tables": [], "profiles": {}, "roles": {},
                "errors": [], "collection_complete": False}

    def failure(operation, exc):
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
        snapshot["errors"].append({"operation": operation, "code": str(code)})

    def call(client, operation, **kwargs):
        try:
            return getattr(client, operation)(**kwargs)
        except Exception as exc:
            failure(operation, exc)
            return None

    def pages(client, operation, key, **kwargs):
        items = []
        try:
            for page in client.get_paginator(operation).paginate(**kwargs):
                items.extend(page.get(key, []))
        except Exception as exc:
            failure(operation, exc)
        return items

    caller = call(sts, "get_caller_identity")
    if caller:
        snapshot["account"] = caller["Account"]
    reservations = pages(ec2, "describe_instances", "Reservations")
    snapshot["instances"] = [i for r in reservations for i in r.get("Instances", [])]
    snapshot["security_groups"] = pages(ec2, "describe_security_groups", "SecurityGroups")
    snapshot["route_tables"] = pages(ec2, "describe_route_tables", "RouteTables")
    policy_cache = {}

    def document(doc):
        return json.loads(unquote(doc)) if isinstance(doc, str) else doc

    for arn in sorted({i["IamInstanceProfile"]["Arn"] for i in snapshot["instances"] if i.get("IamInstanceProfile")}):
        response = call(iam, "get_instance_profile", InstanceProfileName=arn.rsplit("/", 1)[-1])
        if not response:
            continue
        roles = response["InstanceProfile"]["Roles"]
        snapshot["profiles"][arn] = [r["Arn"] for r in roles]
        for role in roles:
            if role["Arn"] in snapshot["roles"]:
                continue
            name = role["RoleName"]
            docs = []
            details = call(iam, "get_role", RoleName=name)
            for pname in pages(iam, "list_role_policies", "PolicyNames", RoleName=name):
                inline = call(iam, "get_role_policy", RoleName=name, PolicyName=pname)
                if inline:
                    docs.append(document(inline["PolicyDocument"]))
            for attached in pages(iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name):
                parn = attached["PolicyArn"]
                if parn not in policy_cache:
                    policy = call(iam, "get_policy", PolicyArn=parn)
                    version = call(iam, "get_policy_version", PolicyArn=parn, VersionId=policy["Policy"]["DefaultVersionId"]) if policy else None
                    if version:
                        policy_cache[parn] = document(version["PolicyVersion"]["Document"])
                if parn in policy_cache:
                    docs.append(policy_cache[parn])
            snapshot["roles"][role["Arn"]] = {"policy_documents": docs,
                "permissions_boundary": (details or {}).get("Role", {}).get("PermissionsBoundary")}
    snapshot["collection_complete"] = not snapshot["errors"]
    return snapshot
