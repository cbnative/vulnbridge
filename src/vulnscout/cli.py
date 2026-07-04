"""CLI: vulnscout normalize --tool trivy report.json -o findings.json"""
import argparse
import json
import sys

from .parsers import PARSERS


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="vulnscout")
    sub = parser.add_subparsers(dest="command", required=True)

    norm = sub.add_parser("normalize", help="normalize a scanner report")
    norm.add_argument("report", help="path to the scanner's JSON report")
    norm.add_argument("--tool", required=True, choices=sorted(PARSERS))
    norm.add_argument("-o", "--output", help="output path (default: stdout)")

    args = parser.parse_args(argv)

    with open(args.report) as fh:
        report = json.load(fh)

    findings = PARSERS[args.tool](report)
    payload = json.dumps([f.to_dict() for f in findings], indent=2)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(payload + "\n")
        print(f"{len(findings)} findings -> {args.output}", file=sys.stderr)
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
