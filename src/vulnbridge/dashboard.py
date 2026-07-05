"""
Renders a findings.json (however it was produced: normalize, merge, or
even a Jenkins security-scan build) into one self-contained HTML page.
No charting library, no JavaScript, just a colored summary and a table,
so the file opens and reads the same in any browser with nothing to
install.

Accepts either vulnbridge's own field names (source_tool, vuln_id,
package) or the Jenkins shared library's shorter ones (tool, id), since
both are a "findings.json" someone might hand to this command.
"""
import html

from .schema import SEVERITIES

_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
    "UNKNOWN": "#6b7280",
}


def render(findings: list[dict]) -> str:
    counts = {s: 0 for s in SEVERITIES}
    by_tool: dict[str, int] = {}
    for f in findings:
        counts[f.get("severity", "UNKNOWN")] = counts.get(f.get("severity", "UNKNOWN"), 0) + 1
        tool = f.get("source_tool") or f.get("tool") or "?"
        by_tool[tool] = by_tool.get(tool, 0) + 1

    cards = "".join(_card(sev, counts[sev]) for sev in SEVERITIES if counts[sev])
    tool_line = ", ".join(f"{tool} ({n})" for tool, n in sorted(by_tool.items(), key=lambda kv: -kv[1]))
    rows = "".join(_row(f) for f in findings)

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>vulnbridge dashboard</title>
<style>
  body {{ font-family: -apple-system, Helvetica, Arial, sans-serif; margin: 2rem; color: #1a1a1a; }}
  h1 {{ margin-bottom: 0.2rem; }}
  .subtitle {{ color: #555; margin-top: 0; }}
  .cards {{ display: flex; gap: 12px; margin: 1.5rem 0; flex-wrap: wrap; }}
  .card {{ color: #fff; border-radius: 8px; padding: 10px 18px; min-width: 90px; text-align: center; }}
  .card .n {{ font-size: 1.6rem; font-weight: 700; display: block; }}
  .card .label {{ font-size: 0.8rem; letter-spacing: 0.03em; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ border: 1px solid #ddd; padding: 6px 10px; text-align: left; font-size: 13px; }}
  th {{ background: #f4f4f4; }}
  .pill {{ color: #fff; border-radius: 999px; padding: 2px 10px; font-size: 12px; font-weight: 600; }}
</style></head><body>
<h1>vulnbridge dashboard</h1>
<p class="subtitle">{len(findings)} finding(s){' &middot; by tool: ' + html.escape(tool_line) if tool_line else ''}</p>
<div class="cards">{cards}</div>
<table>
<tr><th>Severity</th><th>Tool</th><th>ID</th><th>Package / location</th><th>Title</th></tr>
{rows}
</table>
</body></html>
"""


def _card(severity: str, count: int) -> str:
    color = _COLORS.get(severity, _COLORS["UNKNOWN"])
    return (f'<div class="card" style="background:{color}">'
            f'<span class="n">{count}</span><span class="label">{severity}</span></div>')


def _row(f: dict) -> str:
    severity = f.get("severity", "UNKNOWN")
    color = _COLORS.get(severity, _COLORS["UNKNOWN"])
    tool = f.get("source_tool") or f.get("tool") or ""
    vuln_id = f.get("vuln_id") or f.get("id") or ""
    where = f.get("package") or f.get("location") or f.get("target", "")
    return (
        "<tr>"
        f'<td><span class="pill" style="background:{color}">{html.escape(severity)}</span></td>'
        f"<td>{html.escape(tool)}</td>"
        f"<td>{html.escape(vuln_id)}</td>"
        f"<td>{html.escape(str(where))}</td>"
        f"<td>{html.escape(f.get('title', ''))}</td>"
        "</tr>\n"
    )
