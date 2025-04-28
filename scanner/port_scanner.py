import socket
import threading

common_ports = [
    22, 23, 110, 143, 443, 445, 3306, 3389, 8080, 5432, 27017, 5900, 
    69, 135, 161, 162, 514, 873, 2049, 5000, 5050, 8081, 8443, 993, 995, 5672, 6379,
    3307, 9200, 10000, 1723, 179, 4433, 5433, 50000, 10001, 1701, 1521, 1522, 5632, 
    5762, 3128, 8899, 5901, 8000, 8009, 8180, 4434, 2301, 81, 91, 53, 80, 27015, 
    6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 8083, 8008, 8085,
    1080, 3127, 9080, 2049, 50000, 3333, 3030
]
open_ports = []

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect((ip, port))

        banner = fetch_banner(sock, ip, port)
        open_ports.append({"port": port, "banner": banner})
        sock.close()
    except (socket.timeout, socket.error):
        pass  # Skip if connection fails

def fetch_banner(sock, ip, port):
    try:
        if port == 80:
            sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 21:
            sock.send(b"HELLO\r\n")
        elif port == 25:
            sock.send(b"EHLO example.com\r\n")
        elif port == 53:
            sock.send(b"\x00\x00\x00\x00")

        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        return banner.strip() if banner else "No banner"
    except Exception as e:
        return f"Error reading banner: {e}"

def thread_scan(target_ip, ports):
    global open_ports
    open_ports = []

    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(target_ip, port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return open_ports
