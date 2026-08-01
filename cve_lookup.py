"""
cve_lookup.py
NVD (National Vulnerability Database) API'sini kullanarak
banner'dan çıkarılan ürün/versiyon bilgisine göre bilinen CVE'leri arar.

NVD API dokümantasyonu: https://nvd.nist.gov/developers/vulnerabilities
Not: API anahtarsız kullanımda istek limiti düşüktür (5 istek/30sn),
bu yüzden aramalar arasına kısa bir bekleme eklenmiştir.
"""

import re
import time
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def extract_product_version(banner: str) -> str | None:
    """
    Banner metninden 'ürün/versiyon' benzeri bir string çıkarmaya çalışır.
    Örn: 'Apache/2.4.49 (Ubuntu)' -> 'Apache 2.4.49'
    Basit bir regex yaklaşımıdır, her banner için mükemmel çalışmayabilir.
    """
    match = re.search(r"([A-Za-z][A-Za-z0-9\-]+)/(\d+(\.\d+)+)", banner)
    if match:
        product, version = match.group(1), match.group(2)
        return f"{product} {version}"
    return None


def search_cves(keyword: str, results_limit: int = 5) -> list[dict]:
    """
    Verilen anahtar kelime (ürün + versiyon) ile NVD API'sinde arama yapar.
    Dönen sonuç: [{"id": "CVE-XXXX-XXXX", "summary": "...", "severity": "..."}]
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_limit,
    }

    try:
        response = requests.get(NVD_API_URL, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError):
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "Bilinmiyor")

        descriptions = cve.get("descriptions", [])
        summary = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "Açıklama yok",
        )

        metrics = cve.get("metrics", {})
        severity = "Bilinmiyor"
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metric_key in metrics:
                severity = metrics[metric_key][0]["cvssData"].get("baseSeverity", "Bilinmiyor")
                break

        results.append({"id": cve_id, "summary": summary, "severity": severity})

    # NVD rate limit'e takılmamak için aramalar arası küçük bekleme
    time.sleep(2)
    return results


def lookup_services(services: dict[int, str]) -> dict[int, list[dict]]:
    """
    Port -> banner sözlüğünü alır, her biri için mümkünse ürün/versiyon
    çıkarıp CVE arar. Sonuç: port -> CVE listesi
    """
    findings = {}
    for port, banner in services.items():
        product_version = extract_product_version(banner)
        if product_version:
            cves = search_cves(product_version)
            if cves:
                findings[port] = cves
    return findings
