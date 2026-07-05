# Example reports

Scanner output, kept here so you can test vulnbridge without installing a scanner. Real captures are trimmed for size, not rewritten, see the note per file below.

- `trivy-alpine.json` - `trivy image --format json ...` on `alpine:3.18.0`. Real.
- `grype-alpine.json` - `grype -o json` on the same image. Real.
- `npm-audit-juiceshop.json` - `npm audit --json` on OWASP Juice Shop. Real.
- `dependency-check-juiceshop.json` - Dependency-Check on the same Juice Shop checkout, trimmed down to just the vulnerable dependencies (original report was 12MB). Real.
- `gitleaks-juiceshop.json` - `gitleaks detect --report-format json` on a mirrored Juice Shop checkout, trimmed to one finding per rule (the secrets it flags are Juice Shop's own fake test fixtures, not real credentials). Real.
- `semgrep-juiceshop.json` - `semgrep scan --config auto --json` on the same checkout, trimmed to one finding per severity level. Real.
- `zap-juiceshop.json` - `zap-baseline.py -J zap.json` against the public `https://juice-shop.herokuapp.com/` demo instance, trimmed to one alert per risk level. Real.
- `nikto-sample.json` - Nikto's `-Format json` shape. Hand-built: no Nikto run was captured for this repo, the fields match what `parsers/nikto.py` and the companion Jenkins shared library both read.
- `clamav-sample.txt` - ClamAV's `clamscan -i --no-summary` plain-text output shape. Hand-built: the real capture behind the other examples came back clean (no infected files), so there was nothing to trim from.

Try it:

```bash
vulnbridge normalize --tool trivy examples/trivy-alpine.json
vulnbridge normalize --tool grype examples/grype-alpine.json
vulnbridge normalize --tool npm-audit examples/npm-audit-juiceshop.json
vulnbridge normalize --tool dependency-check examples/dependency-check-juiceshop.json
vulnbridge normalize --tool gitleaks examples/gitleaks-juiceshop.json
vulnbridge normalize --tool semgrep examples/semgrep-juiceshop.json
vulnbridge normalize --tool zap examples/zap-juiceshop.json
vulnbridge normalize --tool nikto examples/nikto-sample.json
vulnbridge normalize --tool clamav examples/clamav-sample.txt
```

Or merge all of them into one dashboard in one go:

```bash
vulnbridge merge \
  trivy:examples/trivy-alpine.json \
  grype:examples/grype-alpine.json \
  gitleaks:examples/gitleaks-juiceshop.json \
  semgrep:examples/semgrep-juiceshop.json \
  zap:examples/zap-juiceshop.json \
  nikto:examples/nikto-sample.json \
  clamav:examples/clamav-sample.txt \
  -o findings.json --dashboard dashboard.html
```
