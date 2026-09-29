import argparse
import json
import sys
from pathlib import Path
from .analyzer import analyze
from .report import save_json, write


def main():
    parser = argparse.ArgumentParser(description="AWS EC2/IAM risk correlation and drift analysis")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="Run synthetic before/after analysis without AWS credentials")
    demo.add_argument("--out", default="reports/demo")
    scan = sub.add_parser("analyze", help="Analyze a captured snapshot offline")
    scan.add_argument("snapshot")
    scan.add_argument("--baseline")
    scan.add_argument("--out", default="reports/latest")
    capture = sub.add_parser("collect", help="Read AWS configuration for one account and region")
    capture.add_argument("--region", required=True)
    capture.add_argument("--profile")
    capture.add_argument("--out", default="snapshots/aws.json")
    args = parser.parse_args()
    try:
        if args.command == "collect":
            from .collector import collect
            snapshot = collect(args.region, args.profile)
            save_json(snapshot, args.out)
            print(json.dumps({"account": snapshot["account"], "region": snapshot["region"],
                              "complete": snapshot["collection_complete"], "errors": snapshot["errors"]}, indent=2))
            return 0 if snapshot["collection_complete"] else 2
        if args.command == "demo":
            from .demo import snapshot, hardened
            before = analyze(snapshot())
            after = analyze(hardened(), before)
            root = Path(args.out)
            save_json(snapshot(), root / "snapshot-before.json")
            save_json(hardened(), root / "snapshot-after.json")
            write(before, root / "before")
            write(after, root / "after")
            print(json.dumps({"before": before["summary"], "after": after["summary"], "drift": after["drift"]}, indent=2))
            return 0
        snapshot = json.loads(Path(args.snapshot).read_text())
        baseline = json.loads(Path(args.baseline).read_text()) if args.baseline else None
        report = analyze(snapshot, baseline)
        write(report, args.out)
        print(json.dumps({"summary": report["summary"], "collection_complete": report["collection_complete"]}, indent=2))
        if not report["collection_complete"]:
            return 2
        return 1 if report["findings"] else 0
    except (ValueError, KeyError, TypeError, OSError, RuntimeError, ImportError) as exc:
        print("Unable to complete operation: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
