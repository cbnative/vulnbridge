"""The unified finding schema: every scanner's output maps into this."""
from dataclasses import dataclass, field, asdict

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


@dataclass
class Finding:
    vuln_id: str                 # CVE-..., GHSA-..., or tool-native id
    source_tool: str             # trivy | grype | dependency-check | ...
    target: str                  # image ref, repo path, host...
    package: str
    installed_version: str = ""
    fixed_version: str = ""
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
    """Two tools reporting the same CVE on the same package = one finding."""
    return (f.vuln_id, f.package)
