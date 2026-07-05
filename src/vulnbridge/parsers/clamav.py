"""
Reads a `clamscan -i --no-summary` report and turns each infected file
into a Finding. Unlike every other parser here, ClamAV's report is
plain text, not JSON, one line per infected file:

    /var/app/uploads/evil.php: Win.Trojan.Agent-12345 FOUND

    "/var/app/uploads/evil.php"   -> target, location
    "Win.Trojan.Agent-12345"      -> vuln_id

Clean files produce no output at all, clamscan only prints infections
(-i), so every line here is already something to report on. A found
match is always CRITICAL: this is live malware, not a theoretical risk.
"""
from ..schema import Finding


def parse(report: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in (report or "").splitlines():
        line = line.strip()
        if not line.endswith("FOUND"):
            continue
        cut = line.rfind(": ")
        if cut < 0:
            continue
        file_path = line[:cut]
        signature = line[cut + 2:].replace("FOUND", "").strip()
        findings.append(Finding(
            vuln_id=signature,
            source_tool="clamav",
            target=file_path,
            location=file_path,
            severity="CRITICAL",
            title=f"Infected file: {file_path}"[:160],
        ))
    return findings
