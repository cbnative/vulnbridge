# Vulnbridge

A small Python tool that takes the JSON reports of different vulnerability scanners and converts them into one common format.

📝 Full walkthrough: [VulnManager: Unifying Security Scanners with NVD Normalization](https://cbnative.com/posts/vulnmanager-unified-scanner-normalization).

## The problem, concretely

Scan the same container image with two scanners and you get two files that describe the same vulnerability in completely different shapes.

Trivy says:

```json
{
  "VulnerabilityID": "CVE-2023-42363",
  "PkgName": "busybox",
  "InstalledVersion": "1.36.1-r0",
  "Severity": "MEDIUM"
}
```

Grype says:

```json
{
  "vulnerability": { "id": "CVE-2023-42363", "severity": "Medium" },
  "artifact": { "name": "busybox", "version": "1.36.1-r0" }
}
```

Same CVE, same package, two shapes. You cannot answer "how many HIGH findings across both tools?" or "what did Grype see that Trivy missed?" until both files speak the same format.

That translation is all vulnbridge does. Every finding, from any supported tool, comes out like this:

```json
{
  "vuln_id": "CVE-2023-42363",
  "source_tool": "trivy",
  "target": "alpine:3.18",
  "package": "busybox",
  "installed_version": "1.36.1-r0",
  "fixed_version": "1.36.1-r1",
  "severity": "MEDIUM",
  "cvss": 5.5,
  "title": "busybox: use-after-free in awk",
  "references": ["https://..."]
}
```

Once everything has the same fields you can count, sort, diff and deduplicate findings across tools, which is the starting point for any real vulnerability triage.

> **Clean-room notice**: this project re-implements, from scratch and in the open, the concept I described in [VulnManager: Unifying Security Scanners with NVD Normalization](https://cbnative.com/posts/vulnmanager-unified-scanner-normalization). It contains no code or data from any employer, past or present.

## Quick start

You only need Python 3.10 or newer. There is no binary to download: `pip` builds the `vulnbridge` command from this repo's source, and you can try it on the bundled example reports without installing any scanner.

**1. Clone the repo and enter it**

```bash
git clone https://github.com/cbnative/vulnbridge.git
cd vulnbridge
```

**2. Create a virtual environment and activate it**

This keeps the install isolated from your system Python. Nothing outside this folder is touched.

```bash
python3 -m venv .venv
source .venv/bin/activate     # on Windows: .venv\Scripts\activate
```

**3. Install vulnbridge into it**

```bash
pip install -e .
```

This reads `pyproject.toml` (the Python equivalent of a `package.json`) and creates the `vulnbridge` command inside `.venv`. The `-e` makes the install editable, so if you change the source the command picks it up without reinstalling.

**4. Check it worked**

```bash
vulnbridge normalize --tool grype examples/grype-alpine.json | head -14
```

You should see the start of a JSON list of normalized findings:

```json
[
  {
    "vuln_id": "CVE-2024-6119",
    "source_tool": "grype",
    "target": "alpine:3.18.0",
    "package": "libcrypto3",
    "installed_version": "3.1.0-r4",
    "fixed_version": "3.1.7-r0",
    "severity": "HIGH",
    "cvss": 7.5,
```

The [`examples/`](examples/) directory has one real captured (or, where noted, hand-built) report per supported tool, documented in [`examples/README.md`](examples/README.md). Try any of them the same way:

```bash
vulnbridge normalize --tool grype examples/grype-alpine.json
vulnbridge normalize --tool gitleaks examples/gitleaks-juiceshop.json
```

**5. Normalize your own scans**

Run any supported scanner, then hand its report to vulnbridge:

```bash
trivy image --format json --output trivy-report.json alpine:3.18
vulnbridge normalize --tool trivy trivy-report.json -o findings.json
```

Nine tools are supported: `trivy`, `grype`, `npm-audit`, `dependency-check` (dependency / image scanners), `gitleaks` (secrets), `semgrep` (SAST), `zap` and `nikto` (DAST), `clamav` (malware). The output is a JSON list of findings in the format above, written to `-o` or to stdout.

When you come back later in a new terminal, activate the environment again (`source .venv/bin/activate`) and the `vulnbridge` command is back.

## Merging reports from several tools

A single project usually runs more than one scanner. `merge` normalizes each report, drops duplicates (same CVE or rule hitting the same package/location), sorts by severity, and writes one combined `findings.json`:

```bash
vulnbridge merge trivy:trivy.json grype:grype.json gitleaks:gitleaks.json -o findings.json
```

If your reports already live in one folder under their scanner's usual output filename (`trivy.json`, `grype.json`, `gitleaks.json`, `semgrep.json`, `zap.json`, `nikto.json`, `clamav.txt`, `dependency-check-report.json`), skip naming each one:

```bash
vulnbridge merge --dir security-reports -o findings.json
```

Missing files are just skipped, so it works however many scanners you actually ran.

## Dashboard

`merge --dashboard dashboard.html` writes a second file alongside `findings.json`: one self-contained HTML page, no JavaScript, no charting library, just severity counts as colored cards and a sortable-by-eye table underneath.

```bash
vulnbridge merge --dir security-reports -o findings.json --dashboard dashboard.html
```

Already have a `findings.json` (including one produced by the [jenkins-security-pipeline](https://github.com/cbnative/jenkins-security-pipeline) shared library)? Render it directly:

```bash
vulnbridge dashboard findings.json -o dashboard.html
```

## What is in this repo

`schema.py` defines the `Finding` dataclass and `dedupe_key()`, which flags two findings as the same vulnerability when they share a CVE and a package, or the same rule and location for findings that have no package (a leaked secret, a SAST hit).

Each scanner gets its own parser file under `parsers/`: `trivy.py`, `grype.py`, `npm_audit.py`, `dependency_check.py`, `gitleaks.py`, `semgrep.py`, `zap.py`, `nikto.py`, `clamav.py`. All of them do the same job, read that tool's report, return a list of `Finding` objects, and `parsers/__init__.py` maps the `--tool` name to the right one. `dashboard.py` renders the colored HTML summary. `cli.py` wires the three subcommands (`normalize`, `merge`, `dashboard`) to all of that. To add a new scanner, write one more parser file and add it to the registry.

`examples/` has one real captured report per tool where a scanner run was available, see `examples/README.md` for exactly how each was produced. That's what the commands above run against.

## License

MIT (see [LICENSE](LICENSE)).
