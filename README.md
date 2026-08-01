# Vuln Scanner

Basit, modüler bir **ağ + web zafiyet tarayıcısı**. Python ile yazılmıştır.
Port tarama, servis/versiyon tespiti, NVD üzerinden CVE eşleştirme ve temel
web güvenlik kontrollerini tek bir araçta birleştirir.

> **UYARI:** Bu araç yalnızca **kendi sahip olduğun sistemlerde** veya
> **yazılı izin aldığınız test ortamlarında** kullanılmalıdır. 
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
python main.py --target target-ip
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
├── main.py                    
├── modules/
│   ├── port_scanner.py        
│   ├── banner_grabber.py      
│   ├── cve_lookup.py          
│   ├── web_scanner.py         
│   ├── dir_bruteforce.py      
│   └── report_generator.py    
├── wordlists/
│   └── common.txt             
├── requirements.txt
└── README.md
```