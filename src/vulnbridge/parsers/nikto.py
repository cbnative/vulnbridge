"""
Reads a `nikto -Format json` report and turns each finding into a
Finding. Depending on the Nikto build, the report is either one host
object or a JSON list of host objects, both are handled here.

Shape of the input, showing only the fields this parser reads:

    {
      "host": "demo-app.internal",                  -> target, location fallback
      "vulnerabilities": [
        {
          "id": "999986",                            -> vuln_id
          "url": "/admin/",                           -> location
          "msg": "Retrieved x-powered-by header..."   -> title
        }
      ]
    }

Nikto does not rate its own findings, so like the Jenkins shared
library, everything lands as LOW: worth reviewing, not a build-breaker
by itself.
"""
from ..schema import Finding


def parse(report) -> list[Finding]:
    hosts = report if isinstance(report, list) else [report]
    findings: list[Finding] = []
    for h in hosts:
        host = h.get("host", "")
        for v in h.get("vulnerabilities") or []:
            findings.append(Finding(
                vuln_id=v.get("id", ""),
                source_tool="nikto",
                target=host,
                location=v.get("url") or host,
                severity="LOW",
                title=(v.get("msg") or "")[:160],
            ))
    return findings
