# Vuln Scanner

Basit, modüler bir **ağ + web zafiyet tarayıcısı**. Python ile yazılmıştır ve
port tarama, servis/versiyon tespiti, NVD üzerinden CVE eşleştirme ve temel
web güvenlik kontrollerini tek bir araçta birleştirir.

> **UYARI:** Bu araç yalnızca **kendi sahip olduğun sistemlerde** veya
> **yazılı izin aldığın test ortamlarında** (örn. kendi Kali lab'ın, DVWA,
> bWAPP gibi kasıtlı zafiyetli uygulamalar) kullanılmalıdır. İzinsiz
> sistemlerde tarama yapmak birçok ülkede suçtur. Bu proje yalnızca eğitim
> amaçlıdır.

## Özellikler

- **Port Tarama** — Multi-threaded TCP port tarama
- **Banner Grabbing** — Açık servislerin versiyon bilgisini tespit etme
- **CVE Eşleştirme** — NVD API üzerinden bilinen zafiyetleri listeleme
- **Web Güvenlik Kontrolleri**
  - Eksik güvenlik başlıkları (CSP, HSTS, X-Frame-Options vb.)
  - Yaygın hassas dosya/dizinlerin erişilebilirliği (`/admin`, `/.git/` vb.)
- **Raporlama** — Terminalde renkli çıktı + HTML/JSON rapor

## Kurulum

```bash
git clone https://github.com/kullaniciadi/vuln-scanner.git
cd vuln-scanner
pip install -r requirements.txt
```

## Kullanım

Temel port ve CVE taraması:
```bash
python main.py --target 192.168.56.10
```

Web güvenlik kontrolleriyle birlikte:
```bash
python main.py --target example.com --web
```

Özel port listesiyle:
```bash
python main.py --target 192.168.56.10 --ports 21,22,80,443,3306
```

CVE aramasını atlayarak hızlı tarama:
```bash
python main.py --target 192.168.56.10 --no-cve
```

Tüm seçenekler:
```bash
python main.py --help
```

## Proje Yapısı

```
vuln-scanner/
├── main.py                    # CLI giriş noktası
├── modules/
│   ├── port_scanner.py        # Port tarama
│   ├── banner_grabber.py      # Servis/versiyon tespiti
│   ├── cve_lookup.py          # NVD API ile CVE eşleştirme
│   ├── web_scanner.py         # Web güvenlik kontrolleri
│   └── report_generator.py    # HTML/JSON rapor oluşturma
├── wordlists/                 # (isteğe bağlı) dizin taraması kelime listeleri
├── requirements.txt
└── README.md
```

## Test Ortamı Önerisi

Bu aracı denemek için kendi izole lab ortamını kurabilirsin:
- **Kali Linux** (saldırgan makine)
- **Metasploitable2** veya **DVWA** (kasıtlı zafiyetli hedef)
- VirtualBox'ta Host-Only/Internal Network ile izole bir ağ

## Yol Haritası

- [ ] Async I/O ile port taramayı hızlandırma
- [ ] Daha kapsamlı web zafiyet testleri (basit XSS/SQLi tespiti)
- [ ] Wordlist tabanlı dizin brute-force modülü
- [ ] SSL/TLS yapılandırma kontrolü (zayıf cipher tespiti)
- [ ] Docker ile paketleme

## Lisans

MIT
