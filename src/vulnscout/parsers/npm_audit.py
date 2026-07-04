"""Parser for `npm audit --json` reports (auditReportVersion 2).

Shape of the input, showing only the fields this parser reads:

    {
      "vulnerabilities": {
        "crypto-js": {                             -> package (the dict key)
          "via": [
            {
              "url": "https://github.com/advisories/GHSA-xwcq-pm8m-c4vf",
                                                   -> vuln_id (last segment)
                                                   -> references
              "title": "crypto-js PBKDF2 ...",     -> title
              "severity": "critical",              -> severity
              "cvss": {
                "score": 9.1,                      -> cvss
                "vectorString": "CVSS:3.1/..."
              }
            }
          ],
          "fixAvailable": {"version": "0.19.1"}    -> fixed_version
        },
        "cacache": {
          "via": ["tar"],   <- bare string: no finding produced, see below
          ...
        }
      }
    }

An entry in "via" is either an advisory object (a real finding) or a bare
string naming another package in this same report. The string form means
"cacache is vulnerable because it depends on tar": tar's own entry carries
the actual advisory, so producing a finding for the string too would count
the same advisory twice.

npm audit does not report the installed version of the affected package, so
installed_version stays empty. "fixAvailable" can also be `true`/`false`
instead of an object, in which case there is no version to extract.
"""
from ..schema import Finding

# npm says "moderate" where the unified schema says "MEDIUM".
_SEVERITY_MAP = {"moderate": "medium"}


def parse(report: dict) -> list[Finding]:
    findings: list[Finding] = []
    for pkg_name, entry in (report.get("vulnerabilities") or {}).items():
        for via in entry.get("via") or []:
            if not isinstance(via, dict):
                continue  # transitive pointer, the advisory lives elsewhere
            findings.append(Finding(
                vuln_id=_advisory_id(via),
                source_tool="npm-audit",
                target="package.json",
                package=pkg_name,
                fixed_version=_fixed_version(entry.get("fixAvailable")),
                severity=_SEVERITY_MAP.get(via.get("severity", ""), via.get("severity", "UNKNOWN")),
                cvss=_cvss(via.get("cvss") or {}),
                title=via.get("title", ""),
                references=[via["url"]] if via.get("url") else [],
            ))
    return findings


def _advisory_id(via: dict) -> str:
    # The GHSA id is the last path segment of the advisory URL. If there is
    # no URL, fall back to npm's numeric advisory id ("source").
    url = via.get("url", "")
    if url:
        return url.rsplit("/", 1)[-1]
    source = via.get("source")
    return str(source) if source else ""


def _fixed_version(fix_available) -> str:
    if isinstance(fix_available, dict):
        return fix_available.get("version", "")
    return ""


def _cvss(cvss_block: dict) -> float | None:
    # npm audit reports score 0 with a null vectorString when it has no real
    # score; treat that as "no score" instead of a 0.0.
    if not cvss_block.get("vectorString"):
        return None
    score = cvss_block.get("score")
    return float(score) if isinstance(score, (int, float)) else None
