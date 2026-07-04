"""
Reads a `dependency-check --format JSON` report and turns each
vulnerability it found into a Finding.

Shape of the input, showing only the fields this parser reads:

    {
      "projectInfo": {"name": "juice-shop"},       -> target
      "dependencies": [
        {
          "fileName": "express-jwt:0.1.3",         -> package fallback
          "packages": [
            {"id": "pkg:npm/express-jwt@0.1.3"}    -> package, installed_version
          ],
          "vulnerabilities": [
            {
              "name": "CVE-2020-15084",            -> vuln_id
              "severity": "CRITICAL",              -> severity
              "description": "...",                -> title (first 120 chars)
              "references": [{"url": "https://..."}],  -> references
              "cvssv3": {"baseScore": 9.1},        -> cvss (preferred)
              "cvssv2": {"score": 4.3}             -> cvss (fallback)
            }
          ]
        }
      ]
    }

Not every finding here is a CVE. The RetireJS analyzer that ships with
dependency-check reports things like "Regular Expression Denial of Service
(ReDoS)" instead, with a lowercase severity and no CVSS block at all. The
Finding schema takes care of the severity casing for us, and cvss just ends
up None.
"""
from urllib.parse import unquote

from ..schema import Finding


def parse(report: dict) -> list[Finding]:
    target = (report.get("projectInfo") or {}).get("name", "unknown")
    findings: list[Finding] = []
    for dep in report.get("dependencies") or []:
        package, version = _package_name_version(dep)
        for v in dep.get("vulnerabilities") or []:
            findings.append(Finding(
                vuln_id=v.get("name", ""),
                source_tool="dependency-check",
                target=target,
                package=package,
                installed_version=version,
                severity=v.get("severity", "UNKNOWN"),
                cvss=_best_cvss(v),
                title=v.get("description", "")[:120],
                references=[r["url"] for r in v.get("references") or [] if r.get("url")],
            ))
    return findings


def _package_name_version(dep: dict) -> tuple[str, str]:
    packages = dep.get("packages") or []
    if not packages:
        return dep.get("fileName", ""), ""
    # purl: pkg:npm/file-type@16.5.4 -> ("file-type", "16.5.4")
    body = packages[0].get("id", "").split("/", 1)[-1]
    name, _, version = body.rpartition("@")
    return unquote(name or body), version


def _best_cvss(v: dict) -> float | None:
    # Old CVEs can carry both a v2 and a backfilled v3 score; prefer v3.
    for block, key in (("cvssv3", "baseScore"), ("cvssv2", "score")):
        score = (v.get(block) or {}).get(key)
        if isinstance(score, (int, float)):
            return float(score)
    return None
