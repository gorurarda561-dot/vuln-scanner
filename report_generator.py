"""
report_generator.py
Tarama sonuçlarını JSON ve basit bir HTML raporu olarak kaydeder.
"""

import json
from datetime import datetime
from pathlib import Path

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<title>Zafiyet Tarama Raporu - {target}</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 40px; background: #0f172a; color: #e2e8f0; }}
  h1, h2 {{ color: #38bdf8; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 30px; }}
  th, td {{ border: 1px solid #334155; padding: 8px 12px; text-align: left; }}
  th {{ background: #1e293b; }}
  .critical {{ color: #f87171; font-weight: bold; }}
  .high {{ color: #fb923c; }}
  .medium {{ color: #facc15; }}
  .low {{ color: #4ade80; }}
  .meta {{ color: #94a3b8; margin-bottom: 20px; }}
</style>
</head>
<body>
  <h1>Zafiyet Tarama Raporu</h1>
  <p class="meta">Hedef: {target} | Tarih: {date}</p>

  <h2>Açık Portlar ve Servisler</h2>
  <table>
    <tr><th>Port</th><th>Servis/Banner</th></tr>
    {ports_rows}
  </table>

  <h2>Tespit Edilen CVE'ler</h2>
  <table>
    <tr><th>Port</th><th>CVE ID</th><th>Önem Derecesi</th><th>Açıklama</th></tr>
    {cve_rows}
  </table>

  <h2>Web Güvenliği Bulguları</h2>
  <h3>Eksik Güvenlik Başlıkları</h3>
  <table>
    <tr><th>Başlık</th><th>Açıklama</th></tr>
    {headers_rows}
  </table>

  <h3>Erişilebilir Hassas Yollar</h3>
  <table>
    <tr><th>Yol</th><th>HTTP Durum Kodu</th></tr>
    {paths_rows}
  </table>
</body>
</html>
"""


def _severity_class(severity: str) -> str:
    return severity.lower() if severity.lower() in ("critical", "high", "medium", "low") else ""


def generate_html_report(target: str, services: dict, cve_findings: dict, web_results: dict, output_path: str):
    ports_rows = "".join(
        f"<tr><td>{port}</td><td>{banner}</td></tr>" for port, banner in services.items()
    ) or "<tr><td colspan='2'>Açık port bulunamadı</td></tr>"

    cve_rows = ""
    for port, cves in cve_findings.items():
        for cve in cves:
            cls = _severity_class(cve.get("severity", ""))
            cve_rows += (
                f"<tr><td>{port}</td><td>{cve['id']}</td>"
                f"<td class='{cls}'>{cve['severity']}</td><td>{cve['summary'][:150]}...</td></tr>"
            )
    if not cve_rows:
        cve_rows = "<tr><td colspan='4'>Bilinen CVE bulunamadı</td></tr>"

    headers_rows = "".join(
        f"<tr><td>{h}</td><td>{desc}</td></tr>"
        for h, desc in web_results.get("missing_headers", {}).items()
    ) or "<tr><td colspan='2'>Eksik başlık bulunamadı</td></tr>"

    paths_rows = "".join(
        f"<tr><td>{p['path']}</td><td>{p['status']}</td></tr>"
        for p in web_results.get("exposed_paths", [])
    ) or "<tr><td colspan='2'>Erişilebilir hassas yol bulunamadı</td></tr>"

    html = HTML_TEMPLATE.format(
        target=target,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ports_rows=ports_rows,
        cve_rows=cve_rows,
        headers_rows=headers_rows,
        paths_rows=paths_rows,
    )

    Path(output_path).write_text(html, encoding="utf-8")


def generate_json_report(target: str, services: dict, cve_findings: dict, web_results: dict, output_path: str):
    report = {
        "target": target,
        "date": datetime.now().isoformat(),
        "open_ports": services,
        "cve_findings": cve_findings,
        "web_results": web_results,
    }
    Path(output_path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
