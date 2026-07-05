"""
Every scanner has its own JSON format for reporting a vulnerability.
Before we can compare or merge results from different tools, we need
everything in the same shape. That shape is the Finding class below.
"""
from dataclasses import dataclass, field, asdict

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


@dataclass
class Finding:
    vuln_id: str                 # CVE-..., GHSA-..., or tool-native rule/id
    source_tool: str             # trivy | grype | dependency-check | ...
    target: str                  # image ref, repo path, host...
    package: str = ""            # dependency name, empty for non-package findings
    installed_version: str = ""
    fixed_version: str = ""
    location: str = ""           # file:line, for findings with no package (secrets, SAST, malware)
    severity: str = "UNKNOWN"    # normalized, one of SEVERITIES
    cvss: float | None = None
    title: str = ""
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        sev = self.severity.upper()
        self.severity = sev if sev in SEVERITIES else "UNKNOWN"

    def to_dict(self) -> dict:
        return asdict(self)


def dedupe_key(f: Finding) -> tuple[str, str]:
    """Two tools reporting the same CVE on the same package = one finding.

    Findings with no package (a secret, a SAST hit, a malware match) fall
    back to location, so two different findings sharing the same rule id
    don't collide just because both have an empty package.
    """
    return (f.vuln_id, f.package or f.location)
