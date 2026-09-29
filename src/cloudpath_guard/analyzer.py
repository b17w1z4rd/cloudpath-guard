from __future__ import annotations
import fnmatch
import hashlib
import json
from collections import Counter

SENSITIVE = ("iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:AttachRolePolicy",
             "iam:PutRolePolicy", "iam:PassRole", "secretsmanager:GetSecretValue", "kms:Decrypt",
             "s3:GetObject", "lambda:CreateFunction", "ec2:RunInstances")
LIMITATIONS = [
    "Candidate paths are configuration correlations, not proof of exploitability.",
    "Network analysis covers IPv4, the primary interface and direct internet-gateway routes; NACLs, listeners, host firewalls, load balancers and IPv6 are not evaluated.",
    "IAM checks cover selected sensitive identity-policy grants on Resource '*'; conditions, NotAction, NotResource, boundaries, SCPs, RCPs, session and resource policies are not fully evaluated.",
    "IMDSv1 requires a separate host compromise or suitable SSRF primitive before credentials could be exposed.",
]


def many(value):
    return value if isinstance(value, list) else [value]


def validate(snapshot):
    if not isinstance(snapshot, dict) or snapshot.get("schema_version") != 1:
        raise ValueError("Expected snapshot schema_version 1")
    for key in ("account", "region", "collected_at"):
        if not isinstance(snapshot.get(key), str) or not snapshot[key]:
            raise ValueError("Missing snapshot metadata: " + key)
    for key in ("instances", "security_groups", "route_tables", "errors"):
        if not isinstance(snapshot.get(key), list):
            raise ValueError("Missing snapshot list: " + key)
    for key in ("profiles", "roles"):
        if not isinstance(snapshot.get(key), dict):
            raise ValueError("Missing snapshot map: " + key)
    if not isinstance(snapshot.get("collection_complete"), bool):
        raise ValueError("collection_complete must be boolean")


def broad_grants(role):
    """Only characterize identity statements, never claim effective AWS access."""
    statements = []
    unsupported = False
    for doc in role.get("policy_documents", []):
        statements += many(doc.get("Statement", []))
    unsupported = any("NotAction" in s or "NotResource" in s for s in statements)
    result = []
    for action in SENSITIVE:
        allowed, denied, conditional = False, False, False
        for s in statements:
            if any(k in s for k in ("NotAction", "NotResource")):
                continue
            if not any(fnmatch.fnmatchcase(action.lower(), str(p).lower()) for p in many(s.get("Action", []))):
                continue
            # Resource-specific and conditional denies remain unmodeled constraints.
            if "*" not in many(s.get("Resource", [])):
                if s.get("Effect") == "Deny":
                    conditional = True
                continue
            if s.get("Effect") == "Allow":
                allowed = True
                conditional |= bool(s.get("Condition"))
            elif s.get("Effect") == "Deny":
                if s.get("Condition"):
                    conditional = True
                else:
                    denied = True
        if allowed and not denied:
            result.append({"action": action, "conditions_or_unmodeled_statements": conditional or unsupported,
                           "boundary_present": bool(role.get("permissions_boundary"))})
    return result


def public_tcp_permissions(group):
    rules = []
    for perm in group.get("IpPermissions", []):
        if not any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])):
            continue
        protocol = str(perm.get("IpProtocol", ""))
        if protocol == "-1":
            lo, hi = 0, 65535
        elif protocol in ("tcp", "6"):
            lo, hi = perm.get("FromPort", -1), perm.get("ToPort", -1)
            if not 0 <= lo <= hi <= 65535:
                continue
        else:
            continue
        rules.append({"group": group["GroupId"], "from_port": lo, "to_port": hi})
    return rules


def internet_route(instance, tables):
    # Explicit subnet association takes precedence over the VPC main table.
    explicit = [t for t in tables if any(a.get("SubnetId") == instance.get("SubnetId")
                                        for a in t.get("Associations", []))]
    choices = explicit or [t for t in tables if t.get("VpcId") == instance.get("VpcId")
                           and any(a.get("Main") for a in t.get("Associations", []))]
    return next((t["RouteTableId"] for t in choices
                 if any(r.get("DestinationCidrBlock") == "0.0.0.0/0"
                        and r.get("GatewayId", "").startswith("igw-")
                        and r.get("State") == "active" for r in t.get("Routes", []))), None)


def analyze(snapshot, baseline=None):
    validate(snapshot)
    findings, nodes, edges = [], {}, []
    groups = {g["GroupId"]: g for g in snapshot["security_groups"]}
    warnings = list(snapshot["errors"])

    def node(identifier, kind):
        nodes[identifier] = {"id": identifier, "kind": kind}

    def edge(source, target, relation):
        item = {"source": source, "target": target, "relation": relation}
        if item not in edges:
            edges.append(item)

    def finding(rule, resource, severity, title, evidence, remediation, related=None):
        identity = [snapshot["account"], snapshot["region"], rule, resource, related or ""]
        fid = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()[:24]
        findings.append({"id": fid, "rule": rule, "resource": resource, "severity": severity,
                         "title": title, "evidence": evidence, "remediation": remediation,
                         "related_resource": related})

    grant_map = {}
    for arn, role in sorted(snapshot["roles"].items()):
        node(arn, "iam_role")
        grants = broad_grants(role)
        grant_map[arn] = grants
        if grants:
            finding("CP003", arn, "high", "Sensitive identity-policy grants use Resource '*'",
                    {"grants": grants, "effective_access": "not_established"},
                    "Scope actions and resources to workload needs; evaluate conditions, boundaries and organization controls before changing access.")

    for instance in snapshot["instances"]:
        if instance.get("State", {}).get("Name") != "running":
            continue
        iid = instance["InstanceId"]
        node(iid, "ec2_instance")
        primary = next((n for n in instance.get("NetworkInterfaces", [])
                        if n.get("Attachment", {}).get("DeviceIndex") == 0), None)
        public_ip = primary.get("Association", {}).get("PublicIp") if primary else instance.get("PublicIpAddress")
        network_instance = {**instance, **({"SubnetId": primary.get("SubnetId"), "VpcId": primary.get("VpcId")} if primary else {})}
        sg_refs = primary.get("Groups", []) if primary else instance.get("SecurityGroups", [])
        permissions = []
        for ref in sg_refs:
            gid = ref["GroupId"]
            node(gid, "security_group")
            edge(gid, iid, "attached_to_primary_interface")
            if gid not in groups:
                warnings.append({"operation": "analyze", "code": "missing_security_group", "resource": gid})
            else:
                permissions += public_tcp_permissions(groups[gid])
        route = internet_route(network_instance, snapshot["route_tables"])
        candidate_public = bool(public_ip and route and permissions)
        if candidate_public:
            node("internet-ipv4", "source")
            edge("internet-ipv4", iid, "candidate_tcp_ingress")
            management = sorted({p for p in (22, 3389) if any(r["from_port"] <= p <= r["to_port"] for r in permissions)})
            finding("CP001", iid, "high" if management else "medium", "Candidate direct IPv4 internet exposure",
                    {"public_ipv4": public_ip, "route_table": route, "public_tcp_rules": permissions,
                     "management_ports": management, "reachability": "not_probed"},
                    "Restrict ingress to approved sources; review public addressing and route design. Prefer managed access for administration.")
        profile_arn = instance.get("IamInstanceProfile", {}).get("Arn")
        role_arns = snapshot["profiles"].get(profile_arn, []) if profile_arn else []
        if profile_arn and profile_arn not in snapshot["profiles"]:
            warnings.append({"operation": "analyze", "code": "missing_instance_profile", "resource": profile_arn})
        metadata = instance.get("MetadataOptions", {})
        weak_metadata = metadata.get("HttpEndpoint") == "enabled" and metadata.get("HttpTokens") == "optional"
        if weak_metadata:
            finding("CP002", iid, "high" if profile_arn else "medium", "Metadata endpoint permits requests without IMDSv2 tokens",
                    {"http_tokens": "optional", "http_endpoint": "enabled", "profile_attached": bool(profile_arn)},
                    "Confirm workload IMDSv2 compatibility, then require HttpTokens=required; disable metadata if unused.")
        for role_arn in role_arns:
            node(role_arn, "iam_role")
            edge(iid, role_arn, "instance_profile_role")
            if role_arn not in snapshot["roles"]:
                warnings.append({"operation": "analyze", "code": "missing_role", "resource": role_arn})
                continue
            if candidate_public and weak_metadata and grant_map.get(role_arn):
                finding("CP004", iid, "high", "Correlated exposure: public ingress, IMDSv1 and broad role grants",
                        {"role": role_arn, "grants": grant_map[role_arn],
                         "prerequisites": ["A listening reachable application or service", "A host compromise or SSRF primitive capable of reaching IMDS", "IAM conditions and organization controls permit the relevant action"],
                         "exploitability": "not_established"},
                        "Prioritize this workload: reduce internet ingress, require IMDSv2, and narrow the attached role's permissions.", role_arn)
    complete = snapshot["collection_complete"] and not warnings
    findings.sort(key=lambda x: (0 if x["rule"] == "CP004" else 1, x["resource"], x["rule"]))
    report = {"schema_version": 1, "tool": "cloudpath-guard", "account": snapshot["account"],
              "region": snapshot["region"], "collected_at": snapshot["collected_at"],
              "collection_complete": complete, "warnings": warnings, "limitations": LIMITATIONS,
              "summary": dict(Counter(f["severity"] for f in findings)), "findings": findings,
              "graph": {"nodes": list(nodes.values()), "edges": edges}}
    if baseline is not None:
        if baseline.get("schema_version") != 1 or baseline.get("tool") != "cloudpath-guard":
            raise ValueError("Incompatible baseline report")
        if (baseline.get("account"), baseline.get("region")) != (snapshot["account"], snapshot["region"]):
            raise ValueError("Baseline account and region must match")
        old = {f["id"]: f for f in baseline["findings"]}
        new = {f["id"]: f for f in findings}
        report["drift"] = {"new": sorted(new.keys()-old.keys()), "no_longer_observed": sorted(old.keys()-new.keys()),
                           "changed": sorted(k for k in new.keys() & old.keys() if new[k] != old[k]),
                           "unchanged": sorted(k for k in new.keys() & old.keys() if new[k] == old[k]),
                           "comparison_complete": complete and baseline.get("collection_complete", False),
                           "note": "No longer observed does not prove remediation; check collection completeness and resource lifecycle."}
    return report
