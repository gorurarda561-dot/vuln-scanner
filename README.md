# Vuln Scanner

Basit, modüler bir **ağ + web zafiyet tarayıcısı**. Python ile yazılmıştır ve
port tarama, servis/versiyon tespiti, NVD üzerinden CVE eşleştirme ve temel
web güvenlik kontrollerini tek bir araçta birleştirir.

> **UYARI:** Bu araç yalnızca **kendi sahip olduğun sistemlerde** veya
> **yazılı izin aldığın test ortamlarında** kullanılmalıdır. 
> İzinsiz sistemlerde tarama yapmak birçok ülkede suçtur. Bu proje yalnızca eğitim amaçlıdır.

## Özellikler

- **Port Tarama** — TCP port tarama
- **Banner Grabbing** — Açık servislerin versiyon bilgisini tespit etme
- **CVE Eşleştirme** — NVD API üzerinden CPE tabanlı,CVE eşleştirme + halka açık exploit referans linkleri
- **Web Güvenlik Kontrolleri**
  - Eksik güvenlik başlıkları (CSP, HSTS, X-Frame-Options vb.)
  - Yaygın hassas dosya/dizinlerin erişilebilirliği (`/admin`, `/.git/` vb.)
- **Wordlist Tabanlı Dizin/Dosya Taraması** — dirb/gobuster benzeri, kendi wordlist'inle veya varsayılan listeyle kapsamlı keşif
- **Raporlama** — Terminalde renkli çıktı + HTML/JSON rapor

## Kurulum

```bash
git clone https://github.com/gorurarda561-dot/vuln-scanner.git
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
python main.py --target target-ip --ports 21,22,80,443,3306
```

CVE aramasını atlayarak hızlı tarama:
```bash
python main.py --target target-ip --no-cve
```

Wordlist tabanlı dizin/dosya taraması:
```bash
python main.py --target target-ip --dir-scan
```

Özel wordlist ve uzantılarla dizin taraması:
```bash
python main.py --target target-ip --dir-scan --wordlist wordlists/common.txt --extensions php,bak,zip
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
│   ├── cve_lookup.py          # NVD API ile CVE eşleştirme (CPE tabanlı)
│   ├── web_scanner.py         # Web güvenlik kontrolleri
│   ├── dir_bruteforce.py      # Wordlist tabanlı dizin/dosya keşfi
│   └── report_generator.py    # HTML/JSON rapor oluşturma
├── wordlists/
│   └── common.txt             # Varsayılan dizin/dosya wordlist'i
├── requirements.txt
└── README.md
```

## Yol Haritası

- [ ] Async I/O ile port taramayı hızlandırma
- [ ] Daha kapsamlı web zafiyet testleri (basit XSS/SQLi tespiti)
- [ ] SSL/TLS yapılandırma kontrolü (zayıf cipher tespiti)
- [ ] Docker ile paketleme

## Lisans

MIT