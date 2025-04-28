import ipaddress
import requests

# Load locally known malicious ports
def load_malicious_ports(filepath='data/malicious_ports.txt'):
    try:
        with open(filepath, 'r') as file:
            return set(int(line.split()[0]) for line in file if line.strip() and not line.startswith('#'))
    except FileNotFoundError:
        return set()

# Fetch FireHOL IP blocklist
def fetch_firehol_ips(feed_url="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"):
    print("[+] Fetching threat IPs from FireHOL...")
    response = requests.get(feed_url)
    if response.status_code == 200:
        ip_list = [line.strip() for line in response.text.splitlines() if line and not line.startswith("#")]
        return set(ip_list)
    else:
        print("[-] Failed to fetch FireHOL feed.")
        return set()

# Check if the given target IP is in the FireHOL list
def check_ip_threat(target_ip, malicious_ips):
    try:
        # Convert target_ip to an ip_address object
        target_ip_obj = ipaddress.ip_address(target_ip)
        
        # Loop through each IP or CIDR in the malicious_ips list
        for blocked_ip in malicious_ips:
            # Check if the blocked_ip is a CIDR block
            try:
                # If it's a CIDR block, create a network object
                network = ipaddress.ip_network(blocked_ip, strict=False)
                if target_ip_obj in network:
                    return True  # IP is in the blocked CIDR range
            except ValueError:
                # If it's not a CIDR block, treat it as a single IP
                if target_ip_obj == ipaddress.ip_address(blocked_ip):
                    return True  # Exact match with a blocked IP
        return False
    except ValueError:
        print(f"Invalid IP address: {target_ip}")
        return False

# Check if any scanned open ports are known malicious ports
def check_threats(open_ports, malicious_ports):
    return [port for port in open_ports if port in malicious_ports]

# === NEW FUNCTION ===
# Full Threat Intel Check (for IP and Ports)
def full_threat_check(target_ip, open_ports):
    results = {}

    # Step 1: Load malicious ports list
    malicious_ports = load_malicious_ports()

    # Step 2: Fetch FireHOL IPs
    malicious_ips = fetch_firehol_ips()

    # Step 3: Check if the IP is malicious
    ip_threat = check_ip_threat(target_ip, malicious_ips)

    # Step 4: Check if any ports are suspicious
    ports_threat = check_threats([p['port'] for p in open_ports], malicious_ports)

    results['ip_threat'] = ip_threat
    results['suspicious_ports'] = ports_threat

    return results
