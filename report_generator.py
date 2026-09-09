
import json
import sys
from collections import Counter
from datetime import datetime


SEVERITY_COLOR = {
    "High": "#d93025",
    "Medium": "#e8871e",
    "Low": "#188038",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IAM Security Audit Report</title>
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    max-width: 900px;
    margin: 40px auto;
    padding: 0 20px;
    color: #1a1a1a;
    line-height: 1.5;
  }}
  h1 {{ font-size: 26px; margin-bottom: 4px; }}
  .meta {{ color: #666; font-size: 14px; margin-bottom: 30px; }}
  .summary {{
    display: flex;
    gap: 16px;
    margin-bottom: 30px;
  }}
  .summary-card {{
    flex: 1;
    padding: 16px;
    border-radius: 8px;
    text-align: center;
    color: white;
  }}
  .summary-card .count {{ font-size: 28px; font-weight: bold; }}
  .summary-card .label {{ font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }}
  .finding {{
    border: 1px solid #e0e0e0;
    border-left: 5px solid #ccc;
    border-radius: 6px;
    padding: 14px 18px;
    margin-bottom: 14px;
  }}
  .finding-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
  }}
  .badge {{
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    color: white;
    font-size: 12px;
    font-weight: 600;
  }}
  .resource {{ font-family: monospace; font-size: 13px; color: #444; }}
  .description {{ margin: 8px 0; }}
  .recommendation {{
    background: #f6f8fa;
    border-radius: 4px;
    padding: 10px 12px;
    font-size: 14px;
  }}
  .recommendation strong {{ color: #333; }}
  .no-findings {{ color: #188038; font-weight: 600; }}
</style>
</head>
<body>
  <h1>IAM Security Audit Report</h1>
  <div class="meta">Generated {timestamp}</div>

  <div class="summary">
    {summary_cards}
  </div>

  {findings_html}
</body>
</html>
"""


def build_summary_card(label, count, color):
    return f"""
    <div class="summary-card" style="background:{color};">
      <div class="count">{count}</div>
      <div class="label">{label}</div>
    </div>
    """


def build_finding_html(finding):
    color = SEVERITY_COLOR.get(finding["severity"], "#888")
    return f"""
    <div class="finding" style="border-left-color:{color};">
      <div class="finding-header">
        <span class="badge" style="background:{color};">{finding['severity']}</span>
        <span class="resource">{finding['resource_type']}: {finding['resource_name']}</span>
      </div>
      <div class="description"><strong>{finding['category']}</strong> — {finding['description']}</div>
      <div class="recommendation"><strong>Recommendation:</strong> {finding['recommendation']}</div>
    </div>
    """


def generate_report(findings_path: str, output_path: str):
    with open(findings_path) as f:
        findings = json.load(f)

    counts = Counter(f["severity"] for f in findings)
    summary_cards = "".join([
        build_summary_card("High", counts.get("High", 0), SEVERITY_COLOR["High"]),
        build_summary_card("Medium", counts.get("Medium", 0), SEVERITY_COLOR["Medium"]),
        build_summary_card("Low", counts.get("Low", 0), SEVERITY_COLOR["Low"]),
    ])

    if findings:
        severity_order = {"High": 0, "Medium": 1, "Low": 2}
        findings_sorted = sorted(findings, key=lambda f: severity_order.get(f["severity"], 3))
        findings_html = "".join(build_finding_html(f) for f in findings_sorted)
    else:
        findings_html = '<p class="no-findings">No findings — account passed all checks.</p>'

    html = HTML_TEMPLATE.format(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M"),
        summary_cards=summary_cards,
        findings_html=findings_html,
    )

    with open(output_path, "w") as f:
        f.write(html)

    print(f"[*] Report written to {output_path}")


if __name__ == "__main__":
    findings_file = sys.argv[1] if len(sys.argv) > 1 else "iam_audit_findings.json"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "report.html"
    generate_report(findings_file, output_file)
