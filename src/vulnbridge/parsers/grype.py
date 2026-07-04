"""
Reads a `grype -o json` report and turns each match into a Finding.

Shape of the input, showing only the fields this parser reads:

    {
      "source": {
        "target": {"userInput": "alpine:3.18.0"}   -> target
      },
      "matches": [
        {
          "vulnerability": {
            "id": "CVE-2024-6119",                 -> vuln_id
            "severity": "High",                    -> severity
            "description": "...",                  -> title (first 120 chars)
            "urls": ["https://..."],               -> references
            "fix": {"versions": ["3.1.7-r0"]},     -> fixed_version (first)
            "cvss": [
              {"metrics": {"baseScore": 7.5}}      -> cvss (highest)
            ]
          },
          "relatedVulnerabilities": [ ... ],       -> title/references fallback
          "artifact": {
            "name": "libcrypto3",                  -> package
            "version": "3.1.0-r4"                  -> installed_version
          }
        }
      ]
    }
"""
from ..schema import Finding


def parse(report: dict) -> list[Finding]:
    target_name = (report.get("source") or {}).get("target", "unknown")
    if isinstance(target_name, dict):
        target_name = target_name.get("userInput", "unknown")
    findings: list[Finding] = []
    for match in report.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        related = match.get("relatedVulnerabilities") or [{}]
        artifact = match.get("artifact") or {}
        fix_versions = (vuln.get("fix") or {}).get("versions") or []
        # Distro-database matches (Alpine, Debian...) often have no description
        # or urls of their own, so fall back to the linked NVD record.
        description = vuln.get("description") or related[0].get("description") or ""
        findings.append(Finding(
            vuln_id=vuln.get("id", ""),
            source_tool="grype",
            target=str(target_name),
            package=artifact.get("name", ""),
            installed_version=artifact.get("version", ""),
            fixed_version=fix_versions[0] if fix_versions else "",
            severity=vuln.get("severity", "UNKNOWN"),
            cvss=_best_cvss(vuln.get("cvss") or []),
            title=description[:120],
            references=vuln.get("urls") or related[0].get("urls") or [],
        ))
    return findings


def _best_cvss(cvss_list: list) -> float | None:
    # Grype lists one entry per CVSS source and version; take the highest
    # base score rather than guessing which source is authoritative.
    scores = [c.get("metrics", {}).get("baseScore") for c in cvss_list]
    scores = [s for s in scores if isinstance(s, (int, float))]
    return max(scores) if scores else None
