"""
Command line entry point.

Basic usage:
    vulnbridge normalize --tool trivy report.json -o findings.json
    vulnbridge merge --dir security-reports -o findings.json --dashboard dashboard.html
    vulnbridge dashboard findings.json -o dashboard.html
"""
import argparse
import json
import os
import sys

from .dashboard import render as render_dashboard
from .parsers import DEFAULT_FILENAMES, PARSERS, TEXT_TOOLS
from .schema import SEVERITIES, dedupe_key


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="vulnbridge")
    sub = parser.add_subparsers(dest="command", required=True)

    norm = sub.add_parser("normalize", help="normalize one scanner report")
    norm.add_argument("report", help="path to the scanner's report")
    norm.add_argument("--tool", required=True, choices=sorted(PARSERS))
    norm.add_argument("-o", "--output", help="output path (default: stdout)")

    merge = sub.add_parser("merge", help="normalize and combine reports from several tools into one findings.json")
    merge.add_argument("reports", nargs="*", metavar="TOOL:PATH",
                        help='one report per tool, e.g. trivy:trivy.json grype:grype.json')
    merge.add_argument("--dir", help="folder to auto-discover reports in, by their conventional filename "
                                      "(trivy.json, grype.json, gitleaks.json...), missing files are skipped")
    merge.add_argument("-o", "--output", required=True, help="combined findings.json path")
    merge.add_argument("--dashboard", help="also write an HTML dashboard to this path")

    dash = sub.add_parser("dashboard", help="render an HTML dashboard from an existing findings.json")
    dash.add_argument("findings", help="path to a findings.json produced by normalize/merge")
    dash.add_argument("-o", "--output", required=True, help="dashboard HTML output path")

    args = parser.parse_args(argv)

    if args.command == "normalize":
        return _cmd_normalize(args)
    if args.command == "merge":
        return _cmd_merge(args)
    if args.command == "dashboard":
        return _cmd_dashboard(args)
    return 1


def _load_report(tool: str, path: str):
    with open(path) as fh:
        return fh.read() if tool in TEXT_TOOLS else json.load(fh)


def _cmd_normalize(args) -> int:
    report = _load_report(args.tool, args.report)
    findings = PARSERS[args.tool](report)
    _write_findings(findings, args.output)
    return 0


def _cmd_merge(args) -> int:
    pairs: list[tuple[str, str]] = []
    for item in args.reports:
        tool, _, path = item.partition(":")
        if not path:
            print(f"vulnbridge merge: expected TOOL:PATH, got '{item}'", file=sys.stderr)
            return 1
        pairs.append((tool, path))

    if args.dir:
        for tool, filename in DEFAULT_FILENAMES.items():
            path = os.path.join(args.dir, filename)
            if os.path.exists(path):
                pairs.append((tool, path))

    if not pairs:
        print("vulnbridge merge: nothing to merge, pass TOOL:PATH arguments or --dir", file=sys.stderr)
        return 1

    all_findings = []
    for tool, path in pairs:
        if tool not in PARSERS:
            print(f"vulnbridge merge: unknown tool '{tool}'", file=sys.stderr)
            return 1
        report = _load_report(tool, path)
        found = PARSERS[tool](report)
        print(f"{tool}: {len(found)} finding(s) from {path}", file=sys.stderr)
        all_findings.extend(found)

    deduped = {}
    for f in all_findings:
        deduped.setdefault(dedupe_key(f), f)
    findings = _sort_by_severity(list(deduped.values()))

    dropped = len(all_findings) - len(findings)
    print(f"{len(findings)} finding(s) total ({dropped} duplicate(s) dropped) -> {args.output}", file=sys.stderr)
    _write_findings(findings, args.output)

    if args.dashboard:
        _write_dashboard(findings, args.dashboard)
    return 0


def _cmd_dashboard(args) -> int:
    with open(args.findings) as fh:
        rows = json.load(fh)
    _write_dashboard_html(rows, args.output)
    return 0


def _sort_by_severity(findings):
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    return sorted(findings, key=lambda f: rank.get(f.severity, len(SEVERITIES)))


def _write_findings(findings, output) -> None:
    payload = json.dumps([f.to_dict() for f in findings], indent=2)
    if output:
        with open(output, "w") as fh:
            fh.write(payload + "\n")
        print(f"{len(findings)} findings -> {output}", file=sys.stderr)
    else:
        print(payload)


def _write_dashboard(findings, output: str) -> None:
    _write_dashboard_html([f.to_dict() for f in findings], output)


def _write_dashboard_html(rows: list[dict], output: str) -> None:
    with open(output, "w") as fh:
        fh.write(render_dashboard(rows))
    print(f"dashboard -> {output}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
