"""
port_scanner.py
Multi-threaded TCP port tarayıcı.
Sadece izinli / kendi sahip olduğun sistemlerde kullan.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# En sık kullanılan portlar (hız için varsayılan liste küçük tutuldu,
# istenirse --ports ile genişletilebilir)
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443
]


def scan_port(target: str, port: int, timeout: float = 1.0) -> bool:
    """Tek bir portun açık olup olmadığını kontrol eder."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            return result == 0
    except socket.error:
        return False


def scan_ports(target: str, ports: list[int] = None, max_workers: int = 100) -> list[int]:
    """
    Verilen portları paralel olarak tarar, açık olanların listesini döner.
    """
    ports = ports or DEFAULT_PORTS
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, target, port): port for port in ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass

    return sorted(open_ports)


def resolve_target(target: str) -> str:
    """Domain verilmişse IP adresine çözer."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Hedef çözümlenemedi: {target}")
