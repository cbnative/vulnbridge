# Example reports

Real scanner output, kept here so you can test vulnbridge without installing a scanner.

- `trivy-alpine.json` - `trivy image --format json ...` on `alpine:3.18.0`
- `grype-alpine.json` - `grype -o json` on the same image
- `npm-audit-juiceshop.json` - `npm audit --json` on OWASP Juice Shop
- `dependency-check-juiceshop.json` - Dependency-Check on the same Juice Shop checkout, trimmed down to just the vulnerable dependencies (original report was 12MB)

Try it:

```bash
vulnbridge normalize --tool trivy examples/trivy-alpine.json
vulnbridge normalize --tool grype examples/grype-alpine.json
vulnbridge normalize --tool npm-audit examples/npm-audit-juiceshop.json
vulnbridge normalize --tool dependency-check examples/dependency-check-juiceshop.json
```
