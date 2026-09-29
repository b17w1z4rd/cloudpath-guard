# CloudPath Guard

**Connect AWS EC2 exposure, metadata configuration and IAM role permissions in one evidence report.**

CloudPath Guard is a blue team CLI with a read-only AWS collector and an offline analyzer. It prioritizes configuration combinations that deserve investigation and tracks how findings change between snapshots. It never modifies AWS resources or executes an attack.

## Quick demo

Python 3.10+; the offline analyzer has no third-party dependencies.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cloudpath-guard demo --out reports/demo
cat reports/demo/before/report.md
cat reports/demo/after/report.md
```

The synthetic fixture has an internet-facing EC2 instance permitting IMDSv1 and using a role with broad grants. The first scan produces four high-priority findings. A second synthetic snapshot requires IMDSv2, narrows the IAM policy and restricts SSH. Three findings are no longer observed; the remaining public HTTPS finding changes to medium priority. No AWS credentials or cloud resources are needed for this demo.

## What it checks

| Rule | Signal | Evidence |
| --- | --- | --- |
| CP001 | Candidate direct IPv4 internet ingress | Public IPv4, primary-interface security group TCP rule open to 0.0.0.0/0, active default internet-gateway route |
| CP002 | Instance metadata tokens are optional | Metadata endpoint enabled and HttpTokens=optional |
| CP003 | Selected sensitive identity-policy grants cover all resources | Matching Action and Resource='*', with supported global unconditional denies applied |
| CP004 | Correlation of CP001, CP002 and CP003 through an instance profile | Instance-to-role relationship, contributing grants, and prerequisites that still need verification |

Findings include stable IDs, evidence, suggested remediation and explicit uncertainty. CP004 is ordered first for triage. High priority is a tool heuristic, not CVSS scoring or proof of a working compromise path.

## Collect from your AWS account

Install the optional SDK support and use your existing AWS credentials/profile:

```bash
pip install -e '.[aws]'
cloudpath-guard collect --profile security-audit --region us-east-1 --out snapshots/first.json
cloudpath-guard analyze snapshots/first.json --out reports/first
```

The collector scans **one account and one region per invocation**. IAM roles are collected only for profiles attached to the region's instances. It uses paginators for EC2 lists and IAM role policy lists, retrieves inline and attached managed-policy documents, and caches shared managed-policy documents. It records per-operation failures and produces a partial snapshot when possible. A partial scan must not be treated as a clean account.

`examples/collector-policy.json` lists the read operations used. It is a starter policy for an audit identity, not a policy to attach to your application roles. Further constrain IAM resource scope for your environment if needed. AWS credentials stay in the SDK's credential provider chain; no credential file is created by this tool.

## Compare scans

```bash
cloudpath-guard collect --profile security-audit --region us-east-1 --out snapshots/second.json
cloudpath-guard analyze snapshots/second.json \
  --baseline reports/first/report.json --out reports/second
```

Drift reports list new, changed, unchanged and no-longer-observed findings. The account and region must match. Changing collection timestamps does not create finding churn. `comparison_complete` is false if either report was incomplete. A disappearing resource or missing permissions can also make a finding disappear; the tool does not label that as confirmed remediation.

Exit codes:

- `collect`: 0 for complete capture, 2 for failure or partial capture.
- `analyze`: 0 for no findings in a complete capture, 1 for findings, 2 for incomplete capture or an error.
- `demo`: 0 when the synthetic demonstration completes, even though the fixture contains findings.

## Outputs

Each report directory contains:

- `report.json`: findings, evidence, graph, limits, collection errors and optional drift.
- `report.md`: human-readable triage and remediation summary.
- `graph.dot`: a directed resource relationship graph for Graphviz.

Optional rendering, if Graphviz is installed:

```bash
dot -Tsvg reports/first/graph.dot -o reports/first/graph.svg
```

Snapshots and reports contain infrastructure identifiers, IPs, configuration and potentially sensitive policy/tag information. The output directories are ignored by Git. New output files are created with owner-only permissions on Unix. Review artifacts before sharing them.

## Coverage and interpretation

This is a focused EC2/IAM configuration analyzer, not a complete AWS security platform.

Network checks cover IPv4, primary interfaces and direct internet-gateway default routes. They do not evaluate NACLs, host firewalls, application listeners, load balancers, IPv6, transit paths or all routing edge cases. A CP001 finding is a candidate exposure, not a reachability test. No CP001 finding does not prove an instance is private.

IAM checks inspect a fixed set of sensitive actions with Resource='*'. They support case-insensitive Action wildcards and unconditional explicit Deny on all resources. They expose conditional/resource-specific denies and permissions boundary presence as constraints, but do not solve their semantics. NotAction, NotResource, boundaries, SCPs, RCPs, session policies, resource policies, policy variables and trust-policy transitions are not fully evaluated. A CP003 finding describes an identity-policy grant, not effective AWS authorization or a confirmed privilege escalation. Absence of CP003 does not establish least privilege.

IMDSv1 support is a configuration weakness. Internet access does not itself make IMDS reachable: a host compromise or suitable SSRF primitive would be a separate prerequisite. CP004 preserves that distinction in its evidence.

## Tests and architecture

```bash
python -m unittest discover -s tests -v
```

The suite covers route precedence, NAT exclusions, metadata settings, explicit/conditional IAM denies, resource scoping, stable IDs, baseline mismatches, partial collection and mocked AWS pagination/policy retrieval. CI runs on Python 3.10 and 3.12. AWS collection has been tested with mocked SDK responses; a live-account integration run has not been performed in this environment.

- `collector.py`: AWS snapshot acquisition.
- `analyzer.py`: rule evaluation, correlation graph and scan comparison.
- `report.py`: JSON, Markdown and Graphviz outputs.
- `demo.py`: reproducible before/after fixtures.
- `cli.py`: collect, analyze and demo commands.

## AWS references

- [EC2 metadata options](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html)
- [IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)

MIT licensed. See LICENSE.
