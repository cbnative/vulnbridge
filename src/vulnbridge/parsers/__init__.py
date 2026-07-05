from . import trivy, grype, npm_audit, dependency_check, gitleaks, semgrep, zap, nikto, clamav

PARSERS = {
    "trivy": trivy.parse,
    "grype": grype.parse,
    "npm-audit": npm_audit.parse,
    "dependency-check": dependency_check.parse,
    "gitleaks": gitleaks.parse,
    "semgrep": semgrep.parse,
    "zap": zap.parse,
    "nikto": nikto.parse,
    "clamav": clamav.parse,
}

# Every tool reports JSON except ClamAV, which is plain text
# (`clamscan -i --no-summary`). The CLI checks this before deciding
# whether to json.load() a report or hand it over as raw text.
TEXT_TOOLS = {"clamav"}

# The conventional filename each tool's Jenkinsfile stage writes its
# report to, inside a shared security-reports/ folder. Used by
# `vulnbridge merge --dir`, which mirrors this to auto-discover reports
# without the caller having to name each tool explicitly.
DEFAULT_FILENAMES = {
    "trivy": "trivy.json",
    "grype": "grype.json",
    "dependency-check": "dependency-check-report.json",
    "gitleaks": "gitleaks.json",
    "semgrep": "semgrep.json",
    "zap": "zap.json",
    "nikto": "nikto.json",
    "clamav": "clamav.txt",
}
