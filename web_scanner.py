"""
web_scanner.py
Temel web uygulaması güvenlik kontrolleri:
- Eksik güvenlik başlıkları
- Yaygın hassas dosya/dizinlerin varlığı

Yalnızca kendi sahip olduğun veya test izni aldığın sitelerde kullan.
"""

import requests

# Kontrol edilecek güvenlik başlıkları ve kısa açıklamaları
SECURITY_HEADERS = {
    "Content-Security-Policy": "XSS ve veri enjeksiyonuna karşı koruma sağlar",
    "Strict-Transport-Security": "HTTPS zorunluluğunu garanti eder (HSTS)",
    "X-Frame-Options": "Clickjacking saldırılarına karşı koruma sağlar",
    "X-Content-Type-Options": "MIME tipi sniffing saldırılarını engeller",
    "Referrer-Policy": "Referrer bilgisinin sızmasını sınırlar",
}

# Yaygın hassas dosya/dizinler (kısa liste, wordlists/ ile genişletilebilir)
COMMON_PATHS = [
    "/admin", "/.git/", "/.env", "/backup.zip", "/config.php.bak",
    "/wp-admin", "/phpmyadmin", "/.svn/", "/robots.txt", "/server-status",
]


def check_security_headers(url: str, timeout: float = 5.0) -> dict[str, str]:
    """
    Verilen URL'e istek atar, eksik güvenlik başlıklarını raporlar.
    Dönüş: {"eksik_baslik": "aciklama"}
    """
    missing = {}
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        for header, description in SECURITY_HEADERS.items():
            if header not in response.headers:
                missing[header] = description
    except requests.RequestException as e:
        missing["Hata"] = f"İstek başarısız: {e}"

    return missing


def check_common_paths(base_url: str, timeout: float = 5.0) -> list[dict]:
    """
    Yaygın hassas dosya/dizinlerin erişilebilir olup olmadığını kontrol eder.
    Dönüş: [{"path": "/admin", "status": 200}]
    """
    found = []
    base_url = base_url.rstrip("/")

    for path in COMMON_PATHS:
        url = f"{base_url}{path}"
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=False)
            if response.status_code in (200, 301, 302, 403):
                found.append({"path": path, "status": response.status_code})
        except requests.RequestException:
            continue

    return found


def run_web_scan(target_url: str) -> dict:
    """Tüm web kontrollerini çalıştırıp birleşik sonuç döner."""
    return {
        "missing_headers": check_security_headers(target_url),
        "exposed_paths": check_common_paths(target_url),
    }
