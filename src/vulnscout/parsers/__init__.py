from . import trivy, grype, npm_audit, dependency_check

PARSERS = {
    "trivy": trivy.parse,
    "grype": grype.parse,
    "npm-audit": npm_audit.parse,
    "dependency-check": dependency_check.parse,
}
