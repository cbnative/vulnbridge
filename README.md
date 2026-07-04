# Vulnscout

A small Python tool that takes the JSON reports of different vulnerability scanners and converts them into one common format.

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

📝 Full walkthrough: [VulnManager: Unifying Security Scanners with NVD Normalization](https://cbnative.com/posts/vulnmanager-unified-scanner-normalization).

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

The [`examples/`](examples/) directory has one real captured report per supported tool, documented in [`examples/README.md`](examples/README.md), so you can try all four parsers the same way:

```bash
vulnbridge normalize --tool trivy examples/trivy-alpine.json
vulnbridge normalize --tool grype examples/grype-alpine.json
vulnbridge normalize --tool npm-audit examples/npm-audit-juiceshop.json
vulnbridge normalize --tool dependency-check examples/dependency-check-juiceshop.json
```

**5. Normalize your own scans**

Run any supported scanner with JSON output, then hand the file to vulnbridge:

```bash
trivy image --format json --output trivy-report.json alpine:3.18
vulnbridge normalize --tool trivy trivy-report.json -o findings.json
```

The same command works with `--tool grype` (a `grype -o json` report), `--tool npm-audit` (`npm audit --json`), or `--tool dependency-check` (`dependency-check --format JSON`). The output is a JSON list of findings in the format above, written to `-o` or to stdout.

When you come back later in a new terminal, activate the environment again (`source .venv/bin/activate`) and the `vulnbridge` command is back.

## What is in this repo

`schema.py` defines the `Finding` dataclass and `dedupe_key()`, which flags two findings as the same vulnerability when they share a CVE and a package.

Each scanner gets its own parser file: `parsers/trivy.py`, `parsers/grype.py`, `parsers/npm_audit.py`, `parsers/dependency_check.py`. All four do the same job, read that tool's JSON, return a list of `Finding` objects, and `parsers/__init__.py` just maps the `--tool` name you pass on the CLI to the right one. `cli.py` reads the report file, calls that parser, and prints or writes the result. To add a new scanner, write one more parser file and add it to that registry.

`examples/` has one real captured report per tool, see `examples/README.md` for exactly how each was produced. That's what the Quick start commands above run against.

## License

MIT (see [LICENSE](LICENSE)).
