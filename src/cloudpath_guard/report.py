import json
import os
from pathlib import Path


def save_json(value, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
        json.dump(value, f, indent=2, default=str)
        f.write("\n")


def markdown(report):
    def safe(text):
        return str(text).replace("|", "\\|").replace("\n", " ").replace("`", "'")
    lines = ["# CloudPath Guard", "", "Account: " + safe(report["account"]),
             "Region: " + safe(report["region"]), "", "Collection complete: " + str(report["collection_complete"]),
             "", "| Rule | Severity | Resource | Finding |", "| --- | --- | --- | --- |"]
    for finding in report["findings"]:
        lines.append("| " + " | ".join(safe(finding[k]) for k in ("rule", "severity", "resource", "title")) + " |")
    for finding in report["findings"]:
        lines.extend(["", "## " + safe(finding["rule"]) + ": " + safe(finding["resource"]), "", finding["remediation"]])
    if "drift" in report:
        lines.extend(["", "## Changes from baseline", "", report["drift"]["note"]])
        for category in ("new", "changed", "no_longer_observed", "unchanged"):
            lines.append(f"- {category}: {len(report['drift'][category])}")
    lines.extend(["", "## Coverage limits", "", *["- " + s for s in report["limitations"]], ""])
    return "\n".join(lines)


def dot(report):
    # JSON string quoting is compatible with the identifiers used by Graphviz.
    quote = json.dumps
    lines = ["digraph CloudPath {", "  rankdir=LR;"]
    for node in report["graph"]["nodes"]:
        lines.append("  " + quote(node["id"]) + " [label=" + quote(node["id"] + "\n" + node["kind"]) + "];")
    for edge in report["graph"]["edges"]:
        lines.append("  " + quote(edge["source"]) + " -> " + quote(edge["target"]) + " [label=" + quote(edge["relation"]) + "];")
    return "\n".join(lines + ["}", ""])


def write(report, directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    save_json(report, directory / "report.json")
    for name, content in (("report.md", markdown(report)), ("graph.dot", dot(report))):
        with os.fdopen(os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            f.write(content)
