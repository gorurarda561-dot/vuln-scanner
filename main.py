#!/usr/bin/env python3
"""
Vuln Scanner - Basit Ağ + Web Zafiyet Tarayıcısı
==================================================

UYARI: Bu araç yalnızca kendi sahip olduğun sistemlerde veya
yazılı izin aldığın test ortamlarında (örn. kendi Kali lab'ın,
DVWA gibi kasıtlı zafiyetli uygulamalar) kullanılmalıdır.
İzinsiz sistemlerde kullanmak yasa dışıdır.

Kullanım:
    python main.py --target 192.168.56.10
    python main.py --target example.com --web
    python main.py --target 192.168.56.10 --ports 21,22,80,443
"""

import argparse
import sys

from rich.console import Console
from rich.table import Table

from modules.port_scanner import scan_ports, resolve_target, DEFAULT_PORTS
from modules.banner_grabber import get_service_info
from modules.cve_lookup import lookup_services
from modules.web_scanner import run_web_scan
from modules.report_generator import generate_html_report, generate_json_report

console = Console()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Basit Ağ + Web Zafiyet Tarayıcısı (yalnızca izinli hedeflerde kullanın)"
    )
    parser.add_argument("--target", required=True, help="Hedef IP adresi veya domain")
    parser.add_argument("--ports", help="Virgülle ayrılmış port listesi (varsayılan: yaygın portlar)")
    parser.add_argument("--web", action="store_true", help="Web güvenlik kontrollerini de çalıştır")
    parser.add_argument("--no-cve", action="store_true", help="CVE aramasını atla (daha hızlı tarama)")
    parser.add_argument("--output", default="report", help="Rapor dosya adı (uzantısız)")
    return parser.parse_args()


def print_banner():
    console.print("[bold cyan]" + "=" * 50 + "[/bold cyan]")
    console.print("[bold cyan]   VULN SCANNER - Ağ + Web Zafiyet Tarayıcısı[/bold cyan]")
    console.print("[bold cyan]" + "=" * 50 + "[/bold cyan]")
    console.print("[yellow]Uyarı: Yalnızca izinli hedeflerde kullanın![/yellow]\n")


def main():
    print_banner()
    args = parse_args()

    try:
        target_ip = resolve_target(args.target)
    except ValueError as e:
        console.print(f"[bold red]Hata:[/bold red] {e}")
        sys.exit(1)

    console.print(f"[bold]Hedef:[/bold] {args.target} ({target_ip})\n")

    # --- Port Tarama ---
    ports = [int(p) for p in args.ports.split(",")] if args.ports else DEFAULT_PORTS
    with console.status("[bold green]Portlar taranıyor..."):
        open_ports = scan_ports(target_ip, ports)

    if not open_ports:
        console.print("[yellow]Açık port bulunamadı.[/yellow]")
        services, cve_findings = {}, {}
    else:
        console.print(f"[green]{len(open_ports)} açık port bulundu:[/green] {open_ports}\n")

        # --- Banner Grabbing ---
        with console.status("[bold green]Servis bilgileri toplanıyor..."):
            services = get_service_info(target_ip, open_ports)

        table = Table(title="Açık Portlar ve Servisler")
        table.add_column("Port", style="cyan")
        table.add_column("Servis/Banner", style="white")
        for port, banner in services.items():
            table.add_row(str(port), banner[:80])
        console.print(table)

        # --- CVE Arama ---
        cve_findings = {}
        if not args.no_cve:
            with console.status("[bold green]CVE veritabanı sorgulanıyor (NVD)..."):
                cve_findings = lookup_services(services)

            if cve_findings:
                cve_table = Table(title="Tespit Edilen CVE'ler")
                cve_table.add_column("Port", style="cyan")
                cve_table.add_column("CVE ID", style="red")
                cve_table.add_column("Önem", style="yellow")
                for port, cves in cve_findings.items():
                    for cve in cves:
                        cve_table.add_row(str(port), cve["id"], cve["severity"])
                console.print(cve_table)
            else:
                console.print("[yellow]Bilinen CVE bulunamadı (veya versiyon tespit edilemedi).[/yellow]")

    # --- Web Taraması ---
    web_results = {"missing_headers": {}, "exposed_paths": []}
    if args.web:
        protocol = "https" if 443 in open_ports or 8443 in open_ports else "http"
        target_url = f"{protocol}://{args.target}"
        console.print(f"\n[bold]Web taraması başlatılıyor:[/bold] {target_url}")

        with console.status("[bold green]Web güvenlik kontrolleri yapılıyor..."):
            web_results = run_web_scan(target_url)

        if web_results["missing_headers"]:
            h_table = Table(title="Eksik Güvenlik Başlıkları")
            h_table.add_column("Başlık", style="red")
            h_table.add_column("Açıklama", style="white")
            for header, desc in web_results["missing_headers"].items():
                h_table.add_row(header, desc)
            console.print(h_table)

        if web_results["exposed_paths"]:
            p_table = Table(title="Erişilebilir Hassas Yollar")
            p_table.add_column("Yol", style="red")
            p_table.add_column("Durum Kodu", style="yellow")
            for item in web_results["exposed_paths"]:
                p_table.add_row(item["path"], str(item["status"]))
            console.print(p_table)

    # --- Rapor Oluşturma ---
    html_path = f"{args.output}.html"
    json_path = f"{args.output}.json"
    generate_html_report(args.target, services, cve_findings, web_results, html_path)
    generate_json_report(args.target, services, cve_findings, web_results, json_path)

    console.print(f"\n[bold green]Rapor oluşturuldu:[/bold green] {html_path}, {json_path}")


if __name__ == "__main__":
    main()
