"""
banner_grabber.py
Açık portlardaki servislerin banner/versiyon bilgisini çeker.
"""

import socket

# Yaygın portlar için basit servis isimlendirmesi (banner alınamazsa fallback)
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


def grab_banner(target: str, port: int, timeout: float = 2.0) -> str:
    """
    Belirtilen porta bağlanıp banner (servis tanıtım metni) almaya çalışır.
    HTTP portları için basit bir HEAD isteği gönderir.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target, port))

            if port in (80, 8080, 443, 8443):
                request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
                sock.send(request.encode())
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return banner if banner else COMMON_SERVICES.get(port, "Bilinmiyor")
    except (socket.error, socket.timeout):
        return COMMON_SERVICES.get(port, "Bilinmiyor")


def get_service_info(target: str, open_ports: list[int]) -> dict[int, str]:
    """Her açık port için banner/servis bilgisini toplar."""
    services = {}
    for port in open_ports:
        services[port] = grab_banner(target, port)
    return services
