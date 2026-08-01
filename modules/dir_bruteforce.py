"""
dir_bruteforce.py
Wordlist tabanlı dizin/dosya keşif (brute-force) modülü.

web_scanner.py'deki COMMON_PATHS listesi çok küçük ve sabit bir "hızlı kontrol"
sağlıyordu. Bu modül, kullanıcının verdiği (veya varsayılan) bir wordlist
dosyasındaki yüzlerce yolu multi-threaded şekilde deneyerek çok daha kapsamlı
bir keşif yapar (dirb/gobuster/ffuf gibi araçların basit bir versiyonu).

Yalnızca kendi sahip olduğun veya izinli test ortamlarında kullan.
"""

import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Bulgu olarak raporlanacak "ilginç" HTTP durum kodları.
# 404 (bulunamadı) ve benzerleri gürültü olduğu için hariç tutulur.
INTERESTING_STATUS_CODES = {200, 201, 204, 301, 302, 307, 401, 403}


def load_wordlist(path: str) -> list[str]:
    """
    Wordlist dosyasını okur. Boş satırları ve '#' ile başlayan yorum
    satırlarını atlar. Her yolun '/' ile başladığından emin olur.
    """
    wordlist_path = Path(path)
    if not wordlist_path.exists():
        raise FileNotFoundError(f"Wordlist dosyası bulunamadı: {path}")

    entries = []
    for line in wordlist_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("/"):
            line = "/" + line
        entries.append(line)

    return entries


def _apply_extensions(paths: list[str], extensions: list[str] | None) -> list[str]:
    """
    Uzantı listesi verildiyse (örn. ['php', 'bak']), her yol için hem
    uzantısız hem de her uzantıyla birer varyant üretir.
    Örn: '/config' + ['php'] -> '/config', '/config.php'
    """
    if not extensions:
        return paths

    expanded = []
    for path in paths:
        expanded.append(path)
        # Zaten bir uzantısı olan yollara (örn. /wp-login.php) tekrar
        # uzantı eklemek anlamsız, o yüzden sadece "çıplak" yollara ekleriz.
        if "." not in path.rsplit("/", 1)[-1]:
            for ext in extensions:
                expanded.append(f"{path}.{ext.lstrip('.')}")

    return expanded


def check_path(base_url: str, path: str, timeout: float = 3.0) -> dict | None:
    """
    Tek bir yolu kontrol eder. İlginç bir durum kodu dönerse sonuç,
    dönmezse None döner.
    """
    url = f"{base_url.rstrip('/')}{path}"
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=False)
        if response.status_code in INTERESTING_STATUS_CODES:
            return {
                "path": path,
                "status": response.status_code,
                "content_length": len(response.content),
            }
    except requests.RequestException:
        pass

    return None


def brute_force(
    base_url: str,
    wordlist_path: str,
    extensions: list[str] | None = None,
    max_workers: int = 20,
) -> list[dict]:
    """
    Wordlist'teki tüm yolları paralel olarak dener, bulunan (ilginç durum
    kodu dönen) yolları listeler.
    """
    paths = load_wordlist(wordlist_path)
    paths = _apply_extensions(paths, extensions)

    found = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(check_path, base_url, path): path for path in paths
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    # Sonuçları yol adına göre alfabetik sırala (rastgele thread sırası yerine)
    return sorted(found, key=lambda r: r["path"])
