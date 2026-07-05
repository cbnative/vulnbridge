"""
Reads a ZAP baseline scan report (`zap-baseline.py ... -J zap.json`)
and turns each alert into a Finding. ZAP scans a running site, not a
package or an image, so target is the site itself and there is no
version or CVSS score.

Shape of the input, showing only the fields this parser reads:

    {
      "site": [
        {
          "@name": "https://demo-app.internal/",   -> target
          "alerts": [
            {
              "pluginid": "10038",                  -> vuln_id
              "name": "CSP Header Not Set",          -> title
              "riskcode": "2"                        -> severity
            }
          ]
        }
      ]
    }

ZAP's riskcode is 0-3, mapped the same way the Jenkins shared library
does: 3 is HIGH, 2 is MEDIUM, 1 is LOW, anything else is UNKNOWN.
"""
from ..schema import Finding

_RISK_MAP = {"3": "HIGH", "2": "MEDIUM", "1": "LOW"}


def parse(report: dict) -> list[Finding]:
    findings: list[Finding] = []
    for site in report.get("site") or []:
        target = site.get("@name", "")
        for a in site.get("alerts") or []:
            findings.append(Finding(
                vuln_id=a.get("pluginid", ""),
                source_tool="zap",
                target=target,
                location=target,
                severity=_RISK_MAP.get(str(a.get("riskcode", "")), "UNKNOWN"),
                title=(a.get("name") or "")[:160],
            ))
    return findings
