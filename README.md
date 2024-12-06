import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip, port):
    """Scan a specific port on an IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Set timeout for the connection
            s.connect((ip, port))
            print(f"[+] Open port {port} found on {ip}")
    except:
        pass  # Ignore ports that are not open

def scan_ip(ip):
    """Scan common ports on a given IP address."""
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389]
    print(f"Scanning IP: {ip}")
    for port in common_ports:
        scan_port(ip, port)

def network_scan(subnet):
    """Scan all IPs in a subnet."""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        with ThreadPoolExecutor(max_workers=10) as executor:
            for ip in network.hosts():
                executor.submit(scan_ip, str(ip))
    except ValueError as e:
        print(f"Invalid subnet: {e}")

if __name__ == "__main__":
    subnet = input("Enter the subnet (e.g., 192.168.1.0/24): ")
    network_scan(subnet)
