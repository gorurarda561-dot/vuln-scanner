"""
cve_lookup.py
NVD (National Vulnerability Database) API'sini kullanarak, banner'dan
çıkarılan ürün/versiyon bilgisine göre bilinen CVE'leri arar.

Eski implementasyon NVD'nin "keywordSearch" parametresini kullanıyordu.
Bu parametre gevşek/bulanık eşleştirme yapar (örn. "Apache 2.4.58" araması
sadece "Apache" kelimesi geçen alakasız ve çok eski CVE'leri de getirebilir).

Bu sürüm bunun yerine CPE (Common Platform Enumeration) tabanlı arama
kullanır: banner'dan tespit edilen ürün, bilinen bir CPE vendor/product
adına eşlenir ve NVD'ye "bu tam CPE'yi (ürün+versiyon) etkileyen CVE'ler
nedir?" diye sorulur. Bu, gerçek pentest araçlarının (örn. searchsploit,
cve-search) kullandığı yönteme çok daha yakındır ve false positive oranını
ciddi şekilde düşürür.

NVD API dokümantasyonu: https://nvd.nist.gov/developers/vulnerabilities
Not: API anahtarsız kullanımda istek limiti düşüktür (5 istek/30sn),
bu yüzden aramalar arasına kısa bir bekleme eklenmiştir.
"""

import re
import time
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Banner'da tespit edilen ürün adını NVD'nin CPE vendor:product formatına
# eşleştiren küçük bir sözlük. Gerçek dünyada en sık karşılaşılan servisleri
# kapsar; listeye kolayca yeni ürün eklenebilir.
CPE_MAP = {
    "apache": "apache:http_server",
    "nginx": "nginx:nginx",
    "openssh": "openbsd:openssh",
    "mysql": "mysql:mysql",
    "mariadb": "mariadb:mariadb",
    "postgresql": "postgresql:postgresql",
    "vsftpd": "vsftpd_project:vsftpd",
    "proftpd": "proftpd:proftpd",
    "postfix": "postfix:postfix",
    "dovecot": "dovecot:dovecot",
    "samba": "samba:samba",
    "iis": "microsoft:iis",
    "php": "php:php",
    "openssl": "openssl:openssl",
}


def extract_product_version(banner: str) -> tuple[str, str] | None:
    """
    Banner metninden (ürün_adı, versiyon) çifti çıkarmaya çalışır.
    Örn: 'Apache/2.4.58 (Ubuntu)' -> ('apache', '2.4.58')
         'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18' -> ('openssh', '9.6')

    İki farklı yaygın banner formatını dener:
      1) "Ürün/Versiyon" (Apache, nginx, vsftpd vb.)
      2) "SSH-x.x-Ürün_Versiyon" (OpenSSH)
    """
    # Format 1: Product/Version (örn. Apache/2.4.58, nginx/1.18.0)
    match = re.search(r"([A-Za-z][A-Za-z0-9\-]+)/(\d+(?:\.\d+)+)", banner)
    if match:
        return match.group(1).lower(), match.group(2)

    # Format 2: SSH banner (örn. SSH-2.0-OpenSSH_9.6p1)
    match = re.search(r"SSH-[\d.]+-([A-Za-z]+)_(\d+(?:\.\d+)*)", banner)
    if match:
        return match.group(1).lower(), match.group(2)

    return None


def build_cpe_string(product: str, version: str) -> str | None:
    """
    Ürün adını CPE_MAP'te arar, bulursa tam CPE 2.3 string'i oluşturur.
    Eşleşme yoksa None döner (bilinmeyen ürünler için tahmin yürütülmez,
    bu da yanlış eşleşme riskini ortadan kaldırır).
    """
    vendor_product = CPE_MAP.get(product)
    if not vendor_product:
        return None
    return f"cpe:2.3:a:{vendor_product}:{version}:*:*:*:*:*:*:*"


def search_cves_by_cpe(cpe_string: str, results_limit: int = 5) -> list[dict]:
    """
    Tam bir CPE string'i ile NVD API'sinde arama yapar. Bu, keywordSearch'e
    göre çok daha kesin sonuç verir çünkü tam ürün+versiyon eşleşmesi arar.
    """
    params = {
        "cpeName": cpe_string,
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

        # NVD kaydındaki "references" listesinden "Exploit" etiketli olanları
        # ayıklıyoruz. Bunlar NVD'nin kendisinin topladığı, halka açık ve
        # zaten yayınlanmış danışma/PoC sayfalarına linktir (exploit kodu
        # üretmiyoruz, sadece var olan kamuya açık kaynaklara işaret ediyoruz).
        exploit_refs = [
            ref["url"]
            for ref in cve.get("references", [])
            if "Exploit" in ref.get("tags", [])
        ][:3]  # fazla kalabalık olmasın diye en fazla 3 link

        results.append({
            "id": cve_id,
            "summary": summary,
            "severity": severity,
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "exploit_refs": exploit_refs,
            "has_public_exploit": len(exploit_refs) > 0,
        })

    # NVD rate limit'e takılmamak için aramalar arası küçük bekleme
    time.sleep(2)
    return results


def lookup_services(services: dict[int, str]) -> dict[int, list[dict]]:
    """
    Port -> banner sözlüğünü alır, her biri için mümkünse ürün/versiyon
    çıkarıp, bilinen bir CPE eşleşmesi varsa CVE arar.

    Ürün CPE_MAP'te yoksa o port için arama yapılmaz (sessizce atlanır) —
    bu, tahmini/yanlış eşleşme yapmaktan daha güvenlidir.
    """
    findings = {}
    for port, banner in services.items():
        extracted = extract_product_version(banner)
        if not extracted:
            continue

        product, version = extracted
        cpe_string = build_cpe_string(product, version)
        if not cpe_string:
            continue

        cves = search_cves_by_cpe(cpe_string)
        if cves:
            findings[port] = cves

    return findings