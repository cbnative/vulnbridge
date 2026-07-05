"""
Reads a `semgrep scan --config auto --json` report and turns each
result into a Finding. Semgrep reports code patterns, not CVEs, so
there is no package or CVSS score here, just a rule id and a location.

Shape of the input, showing only the fields this parser reads:

    {
      "results": [
        {
          "check_id": "python.lang.security...",   -> vuln_id
          "path": "src/app.py",                     -> target, location
          "start": {"line": 42},                    -> location
          "extra": {
            "message": "...",                       -> title
            "severity": "ERROR"                     -> severity
          }
        }
      ]
    }

Semgrep's classic severities (ERROR / WARNING / INFO) don't match the
unified scale, so map them the same way the Jenkins shared library
does: ERROR is the only level serious enough to call HIGH. Newer rule
packs (mostly supply-chain ones) sometimes set severity to a standard
word like "MEDIUM" directly, those pass straight through instead of
being mapped.
"""
from ..schema import Finding

_SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def parse(report: dict) -> list[Finding]:
    findings: list[Finding] = []
    for r in report.get("results") or []:
        path = r.get("path", "")
        line = (r.get("start") or {}).get("line", "")
        extra = r.get("extra") or {}
        raw_severity = (extra.get("severity") or "").upper()
        severity = raw_severity if raw_severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") \
            else _SEVERITY_MAP.get(raw_severity, "UNKNOWN")
        findings.append(Finding(
            vuln_id=r.get("check_id", ""),
            source_tool="semgrep",
            target=path,
            location=f"{path}:{line}" if path else "",
            severity=severity,
            title=(extra.get("message") or "")[:160],
        ))
    return findings
