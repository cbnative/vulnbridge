"""
Reads a `gitleaks detect --report-format json` report and turns each
leak into a Finding. Unlike the other parsers, the report itself is a
plain JSON list, not an object.

Shape of the input, showing only the fields this parser reads:

    [
      {
        "RuleID": "generic-api-key",              -> vuln_id
        "Description": "Detected a Generic...",   -> title
        "File": "src/config/secrets.yml",         -> target, location
        "StartLine": 88                           -> location
      }
    ]

A leaked credential has no CVSS score and no package, it is always
treated as CRITICAL: whatever it is, it is already exposed.
"""
from ..schema import Finding


def parse(report: list) -> list[Finding]:
    findings: list[Finding] = []
    for leak in report or []:
        file_path = leak.get("File", "")
        line = leak.get("StartLine", "")
        findings.append(Finding(
            vuln_id=leak.get("RuleID", ""),
            source_tool="gitleaks",
            target=file_path,
            location=f"{file_path}:{line}" if file_path else "",
            severity="CRITICAL",
            title=f"Possible hardcoded secret: {leak.get('Description', '')}"[:160],
        ))
    return findings
