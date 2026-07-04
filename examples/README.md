# Example reports

Real scanner output, kept here so you can test vulnscout without installing a scanner.

- `trivy-alpine.json` - `trivy image --format json ...` on `alpine:3.18.0`
- `grype-alpine.json` - `grype -o json` on the same image
- `npm-audit-juiceshop.json` - `npm audit --json` on OWASP Juice Shop
- `dependency-check-juiceshop.json` - Dependency-Check on the same Juice Shop checkout, trimmed down to just the vulnerable dependencies (original report was 12MB)

Try it:

```bash
vulnscout normalize --tool trivy examples/trivy-alpine.json
vulnscout normalize --tool grype examples/grype-alpine.json
vulnscout normalize --tool npm-audit examples/npm-audit-juiceshop.json
vulnscout normalize --tool dependency-check examples/dependency-check-juiceshop.json
```
