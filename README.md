# PortHunter+: Scan, Flag, and Threat-Tag

A Python scanner that identifies open ports and correlates them with known malicious services.

# Features

- **🔎 Fast Port Scanning**
  - Multi-threaded scanning of **common ports** (e.g., 21, 22, 23, 80, 443, etc.)
  - Banner grabbing: tries to capture service information from open ports
  - Handles timeouts and socket errors gracefully

- **📜 Banner Analysis**
  - Displays any retrieved service banners (like SSH versions, HTTP server headers, FTP servers, etc.)
  - Reports when no banner is found or connection errors occur

- **🚨 Threat Detection via Port Matching**
  - Loads a **list of known malicious ports**
  - Checks if any open ports match **threatened/malicious ports** list
  - Alerts the user if dangerous ports are open

- **🛡️ IP Reputation Check**
  - Integrates with **AbuseIPDB API**
  - Checks the **abuse confidence score** and reports details like:
    - Country
    - Domain name (if available)
    - Whether IP is public
    - Total number of reports
  - Helps judge if the scanned IP is suspicious

- **📂 Report Generation**
  - Saves scan results (open ports, banners, abuse check results) into a **JSON file**
  - Organized output for later analysis

- **🌐 External Blacklist Check**
  - Fetches FireHOL IP blacklist
  - Checks if target IP is blacklisted in threat databases

- **🌟 Web Interface**
  - `app.py` builds a **web-based GUI** to scan IPs and view reports visually

---


# Installation
