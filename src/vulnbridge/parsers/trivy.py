"""
Reads a `trivy --format json` report and turns each vulnerability it
found into a Finding. Trivy uses the same report shape whether it
scanned a container image, a filesystem, or a git repo.

Shape of the input, showing only the fields this parser reads:

    {
      "ArtifactName": "alpine:3.18.0",          -> target
      "Results": [
        {
          "Vulnerabilities": [
            {
              "VulnerabilityID": "CVE-2022-48174",   -> vuln_id
              "PkgName": "busybox",                  -> package
              "InstalledVersion": "1.36.0-r9",       -> installed_version
              "FixedVersion": "1.36.1-r1",           -> fixed_version
              "Severity": "CRITICAL",                -> severity
              "Title": "busybox: stack overflow...", -> title
              "References": ["https://..."],         -> references
              "CVSS": {
                "nvd":    {"V3Score": 9.8},          -> cvss (NVD preferred)
                "redhat": {"V3Score": 8.1}
              }
            }
          ]
        }
      ]
    }
"""
from ..schema import Finding


def parse(report: dict) -> list[Finding]:
    target_name = report.get("ArtifactName", "unknown")
    findings: list[Finding] = []
    for result in report.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            findings.append(Finding(
                vuln_id=v.get("VulnerabilityID", ""),
                source_tool="trivy",
                target=target_name,
                package=v.get("PkgName", ""),
                installed_version=v.get("InstalledVersion", ""),
                fixed_version=v.get("FixedVersion", ""),
                severity=v.get("Severity", "UNKNOWN"),
                cvss=_best_cvss(v.get("CVSS") or {}),
                title=v.get("Title", ""),
                references=v.get("References") or [],
            ))
    return findings


def _best_cvss(cvss_block: dict) -> float | None:
    # Trivy nests one score block per source. Prefer NVD so the same CVE gets
    # the same score regardless of which distro's advisory Trivy used, then
    # fall back to the other sources in alphabetical order.
    for source in ("nvd", *sorted(cvss_block)):
        score = (cvss_block.get(source) or {}).get("V3Score")
        if isinstance(score, (int, float)):
            return float(score)
    return None
