<div align="center">

# 🧭 Pivot Across Datasets with MISP + VirusTotal + PassiveTotal

### Multi-Platform IOC Pivoting & Adversary Movement Tracking

![MISP](https://img.shields.io/badge/MISP-Threat%20Intel%20Platform-1E3A5F?style=for-the-badge&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2C&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API-394EFF?style=for-the-badge&logo=virustotal&logoColor=white)
![PassiveTotal](https://img.shields.io/badge/PassiveTotal-API-00C7B7?style=for-the-badge&logo=riseup&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![MariaDB](https://img.shields.io/badge/MariaDB-Database-003545?style=for-the-badge&logo=mariadb&logoColor=white)
![Apache](https://img.shields.io/badge/Apache-Web%20Server-D22128?style=for-the-badge&logo=apache&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Cloud%20Lab-FCC624?style=for-the-badge&logo=linux&logoColor=black)

</div>

---

## 📖 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [✅ Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🏗️ Task 1: Set Up MISP for Data Sharing and Enrichment](#️-task-1-set-up-misp-for-data-sharing-and-enrichment)
- [🔍 Task 2: Use VirusTotal and PassiveTotal for IOC Analysis](#-task-2-use-virustotal-and-passivetotal-for-ioc-analysis)
- [🧭 Task 3: Pivot Between Platforms to Track Adversary Movement](#-task-3-pivot-between-platforms-to-track-adversary-movement)
- [🧪 Verification and Testing](#-verification-and-testing)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | Set up and configure **MISP** for threat intelligence data sharing and enrichment |
| 2 | Utilize **VirusTotal** and **PassiveTotal** APIs for comprehensive IOC analysis |
| 3 | Master pivoting techniques between multiple intelligence platforms |
| 4 | Track adversary movement patterns across different data sources |
| 5 | Correlate threat indicators to build comprehensive attack timelines |

## ✅ Prerequisites

| Requirement | Details |
|---|---|
| 🐧 Linux CLI | Basic Linux command line knowledge |
| 🧠 Threat Intel Concepts | Understanding of threat intelligence concepts (IOCs, TTPs) |
| 🧾 JSON | Familiarity with JSON data structures |
| 🌐 Networking Basics | Basic networking concepts (domains, IPs, hashes) |

## 🖥️ Lab Environment

> ☁️ **Al Nafi Cloud Lab** — Click **Start Lab** to spin up your dedicated Linux machine. The environment is bare metal with no pre-installed tools — every tool in this lab is installed from scratch as you go.

---

## 🏗️ Task 1: Set Up MISP for Data Sharing and Enrichment

### 📦 Subtask 1.1: Install MISP Dependencies

Update the system and install required packages:

```bash
# 🔄 Update system and install MISP's full dependency stack
sudo apt update && sudo apt upgrade -y
sudo apt install -y apache2 mariadb-server php php-mysql php-xml php-mbstring php-zip php-curl php-json php-gd php-intl php-bcmath git python3 python3-pip redis-server
```

### 🗄️ Subtask 1.2: Configure Database

Set up MariaDB for MISP:

```bash
# 🔐 Harden the MariaDB installation
sudo mysql_secure_installation
sudo mysql -u root -p
```

In the MySQL console:

```sql
-- 🗄️ Create the MISP database and a dedicated user
CREATE DATABASE misp;
CREATE USER 'misp'@'localhost' IDENTIFIED BY 'MispPassword123!';
GRANT ALL PRIVILEGES ON misp.* TO 'misp'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

# TODO: Replace `MispPassword123!` with a strong, unique password before using this outside the lab sandbox

### 📥 Subtask 1.3: Install MISP

Clone and configure MISP:

```bash
# 📥 Clone MISP and its submodules
cd /var/www/html
sudo git clone https://github.com/MISP/MISP.git
cd MISP
sudo git submodule update --init --recursive

# 🔑 Set ownership and permissions for the web server user
sudo chown -R www-data:www-data /var/www/html/MISP
sudo chmod -R 755 /var/www/html/MISP
```

### ⚙️ Subtask 1.4: Configure MISP

Copy and configure MISP settings:

```bash
# 📄 Instantiate config files from their defaults
cd /var/www/html/MISP/app/Config
sudo cp bootstrap.default.php bootstrap.php
sudo cp database.default.php database.php
sudo cp config.default.php config.php
sudo cp core.default.php core.php
```

Edit the database configuration:

```bash
sudo nano database.php
```

Update the database section:

```php
// 🗄️ Point MISP at the database created in Subtask 1.2
'datasource' => 'Database/Mysql',
'persistent' => false,
'host' => 'localhost',
'login' => 'misp',
'port' => 3306,
'password' => 'MispPassword123!',
'database' => 'misp',
```

### 🧱 Subtask 1.5: Initialize MISP Database

```bash
# 🧱 Initialize schema and core settings
cd /var/www/html/MISP
sudo -u www-data php app/Console/cake Admin initDB
sudo -u www-data php app/Console/cake Admin setSetting "MISP.baseurl" "http://localhost/MISP"
sudo -u www-data php app/Console/cake Admin setSetting "MISP.python_bin" "/usr/bin/python3"
```

### 🌐 Subtask 1.6: Configure Apache

Create the MISP virtual host:

```bash
sudo nano /etc/apache2/sites-available/misp.conf
```

Add the configuration:

```apache
<VirtualHost *:80>
    ServerName localhost
    DocumentRoot /var/www/html/MISP/app/webroot
    <Directory /var/www/html/MISP/app/webroot>
        Options -Indexes
        AllowOverride all
        Require all granted
    </Directory>
    LogLevel warn
    ErrorLog /var/log/apache2/misp_error.log
    CustomLog /var/log/apache2/misp_access.log combined
</VirtualHost>
```

Enable the site and modules:

```bash
# 🔛 Enable the MISP vhost and required Apache module
sudo a2ensite misp
sudo a2enmod rewrite
sudo systemctl restart apache2
```

# TODO: Configure HTTPS with a valid certificate before exposing MISP beyond the lab environment

---

## 🔍 Task 2: Use VirusTotal and PassiveTotal for IOC Analysis

### 🔑 Subtask 2.1: Set Up API Access

Create the API configuration file:

```bash
mkdir ~/threat-intel-lab
cd ~/threat-intel-lab
nano api_config.py
```

Add the API configuration:

```python
# 🔑 API Configuration
VT_API_KEY = "your_virustotal_api_key_here"
PT_API_KEY = "your_passivetotal_api_key_here"
PT_USERNAME = "your_passivetotal_username_here"

# 🧪 For demo purposes, we'll use public/limited APIs
DEMO_MODE = True
```

# TODO: Replace the placeholder keys with your own VirusTotal/PassiveTotal credentials and store them outside version control

### 🐍 Subtask 2.2: Install Python Dependencies

```bash
# 📦 Install required Python packages
pip3 install requests json datetime pymisp
```

### 🦠 Subtask 2.3: Create VirusTotal Analysis Script

```bash
nano vt_analyzer.py
```

```python
#!/usr/bin/env python3
# 🦠 Query VirusTotal for file hash and domain reputation data
import requests
import json
import time
from api_config import VT_API_KEY, DEMO_MODE

class VTAnalyzer:
    def __init__(self):
        self.api_key = VT_API_KEY
        self.base_url = "https://www.virustotal.com/vtapi/v2/"

    def analyze_hash(self, file_hash):
        """Analyze file hash using VirusTotal"""
        if DEMO_MODE:
            # 🧪 Return demo data for educational purposes
            return {
                "response_code": 1,
                "positives": 15,
                "total": 70,
                "scan_date": "2024-01-15 10:30:00",
                "permalink": f"https://www.virustotal.com/file/{file_hash}/analysis/",
                "md5": file_hash[:32] if len(file_hash) > 32 else file_hash
            }

        url = f"{self.base_url}file/report"
        params = {
            'apikey': self.api_key,
            'resource': file_hash
        }

        try:
            response = requests.get(url, params=params)
            return response.json()
        except Exception as e:
            print(f"Error analyzing hash: {e}")
            return None

    def analyze_domain(self, domain):
        """Analyze domain using VirusTotal"""
        if DEMO_MODE:
            return {
                "response_code": 1,
                "positives": 3,
                "total": 70,
                "scan_date": "2024-01-15 10:30:00",
                "domain": domain,
                "detected_urls": [
                    {"url": f"http://{domain}/malware.exe", "positives": 12, "total": 70}
                ]
            }

        url = f"{self.base_url}domain/report"
        params = {
            'apikey': self.api_key,
            'domain': domain
        }

        try:
            response = requests.get(url, params=params)
            return response.json()
        except Exception as e:
            print(f"Error analyzing domain: {e}")
            return None

if __name__ == "__main__":
    vt = VTAnalyzer()

    # 🧪 Test with sample indicators
    test_hash = "44d88612fea8a8f36de82e1278abb02f"
    test_domain = "malicious-example.com"

    print("=== VirusTotal Hash Analysis ===")
    hash_result = vt.analyze_hash(test_hash)
    if hash_result:
        print(f"Hash: {test_hash}")
        print(f"Detections: {hash_result.get('positives', 0)}/{hash_result.get('total', 0)}")
        print(f"Scan Date: {hash_result.get('scan_date', 'N/A')}")

    print("\n=== VirusTotal Domain Analysis ===")
    domain_result = vt.analyze_domain(test_domain)
    if domain_result:
        print(f"Domain: {test_domain}")
        print(f"Detections: {domain_result.get('positives', 0)}/{domain_result.get('total', 0)}")
```

### 🌐 Subtask 2.4: Create PassiveTotal Analysis Script

```bash
nano pt_analyzer.py
```

```python
#!/usr/bin/env python3
# 🌐 Query PassiveTotal for passive DNS and WHOIS history
import requests
import json
import base64
from api_config import PT_API_KEY, PT_USERNAME, DEMO_MODE

class PTAnalyzer:
    def __init__(self):
        self.api_key = PT_API_KEY
        self.username = PT_USERNAME
        self.base_url = "https://api.passivetotal.org/v2/"

    def get_auth_header(self):
        """Create authentication header"""
        if DEMO_MODE:
            return {"Authorization": "Basic demo_auth"}

        auth_string = f"{self.username}:{self.api_key}"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
        return {"Authorization": f"Basic {auth_b64}"}

    def get_passive_dns(self, query):
        """Get passive DNS data"""
        if DEMO_MODE:
            return {
                "results": [
                    {
                        "resolve": "192.168.1.100",
                        "value": query,
                        "firstSeen": "2024-01-01",
                        "lastSeen": "2024-01-15",
                        "source": ["demo"]
                    }
                ],
                "totalRecords": 1
            }

        url = f"{self.base_url}dns/passive"
        headers = self.get_auth_header()
        params = {"query": query}

        try:
            response = requests.get(url, headers=headers, params=params)
            return response.json()
        except Exception as e:
            print(f"Error getting passive DNS: {e}")
            return None

    def get_whois_data(self, query):
        """Get WHOIS data"""
        if DEMO_MODE:
            return {
                "domain": query,
                "registrar": "Demo Registrar",
                "registrant": "Demo User",
                "registered": "2023-01-01",
                "expiresAt": "2025-01-01",
                "nameServers": ["ns1.demo.com", "ns2.demo.com"]
            }

        url = f"{self.base_url}whois"
        headers = self.get_auth_header()
        params = {"query": query}

        try:
            response = requests.get(url, headers=headers, params=params)
            return response.json()
        except Exception as e:
            print(f"Error getting WHOIS data: {e}")
            return None

if __name__ == "__main__":
    pt = PTAnalyzer()

    test_domain = "malicious-example.com"

    print("=== PassiveTotal Passive DNS ===")
    dns_result = pt.get_passive_dns(test_domain)
    if dns_result:
        print(f"Domain: {test_domain}")
        for record in dns_result.get("results", []):
            print(f"  Resolves to: {record.get('resolve')}")
            print(f"  First Seen: {record.get('firstSeen')}")
            print(f"  Last Seen: {record.get('lastSeen')}")

    print("\n=== PassiveTotal WHOIS ===")
    whois_result = pt.get_whois_data(test_domain)
    if whois_result:
        print(f"Domain: {test_domain}")
        print(f"Registrar: {whois_result.get('registrar')}")
        print(f"Registered: {whois_result.get('registered')}")
        print(f"Expires: {whois_result.get('expiresAt')}")
```

---

## 🧭 Task 3: Pivot Between Platforms to Track Adversary Movement

### 🔗 Subtask 3.1: Create Pivot Analysis Engine

```bash
nano pivot_engine.py
```

```python
#!/usr/bin/env python3
# 🔗 Chain VirusTotal and PassiveTotal lookups to follow adversary infrastructure
import json
from datetime import datetime
from vt_analyzer import VTAnalyzer
from pt_analyzer import PTAnalyzer

class PivotEngine:
    def __init__(self):
        self.vt = VTAnalyzer()
        self.pt = PTAnalyzer()
        self.investigation_data = {}

    def start_investigation(self, initial_ioc, ioc_type):
        """Start investigation with initial IOC"""
        print(f"=== Starting Investigation ===")
        print(f"Initial IOC: {initial_ioc} (Type: {ioc_type})")

        self.investigation_data = {
            "initial_ioc": initial_ioc,
            "ioc_type": ioc_type,
            "timestamp": datetime.now().isoformat(),
            "findings": {},
            "pivot_chain": []
        }

        if ioc_type == "domain":
            self.investigate_domain(initial_ioc)
        elif ioc_type == "hash":
            self.investigate_hash(initial_ioc)
        elif ioc_type == "ip":
            self.investigate_ip(initial_ioc)

    def investigate_domain(self, domain):
        """Comprehensive domain investigation"""
        print(f"\n=== Investigating Domain: {domain} ===")

        # 🦠 VirusTotal Analysis
        vt_result = self.vt.analyze_domain(domain)
        if vt_result:
            self.investigation_data["findings"][f"vt_domain_{domain}"] = vt_result
            print(f"VT Detections: {vt_result.get('positives', 0)}/{vt_result.get('total', 0)}")

            # ↪️ Pivot to detected URLs
            detected_urls = vt_result.get("detected_urls", [])
            for url_data in detected_urls[:3]:  # Limit to first 3
                url = url_data.get("url", "")
                print(f"  Detected URL: {url}")
                self.investigation_data["pivot_chain"].append({
                    "from": domain,
                    "to": url,
                    "method": "VT_detected_urls",
                    "timestamp": datetime.now().isoformat()
                })

        # 🌐 PassiveTotal Analysis
        pt_dns = self.pt.get_passive_dns(domain)
        if pt_dns:
            self.investigation_data["findings"][f"pt_dns_{domain}"] = pt_dns
            print(f"PT DNS Records: {pt_dns.get('totalRecords', 0)}")

            # ↪️ Pivot to resolved IPs
            for record in pt_dns.get("results", [])[:3]:  # Limit to first 3
                ip = record.get("resolve", "")
                if ip and self.is_valid_ip(ip):
                    print(f"  Resolves to IP: {ip}")
                    self.investigation_data["pivot_chain"].append({
                        "from": domain,
                        "to": ip,
                        "method": "PT_passive_dns",
                        "first_seen": record.get("firstSeen"),
                        "last_seen": record.get("lastSeen")
                    })
                    # 🔁 Continue investigation with IP
                    self.investigate_ip(ip)

        # 🏢 WHOIS Analysis
        whois_data = self.pt.get_whois_data(domain)
        if whois_data:
            self.investigation_data["findings"][f"pt_whois_{domain}"] = whois_data
            print(f"Registrar: {whois_data.get('registrar', 'N/A')}")

            # ↪️ Pivot to name servers
            name_servers = whois_data.get("nameServers", [])
            for ns in name_servers[:2]:  # Limit to first 2
                print(f"  Name Server: {ns}")
                self.investigation_data["pivot_chain"].append({
                    "from": domain,
                    "to": ns,
                    "method": "WHOIS_nameservers",
                    "timestamp": datetime.now().isoformat()
                })

    def investigate_hash(self, file_hash):
        """Investigate file hash"""
        print(f"\n=== Investigating Hash: {file_hash} ===")

        vt_result = self.vt.analyze_hash(file_hash)
        if vt_result:
            self.investigation_data["findings"][f"vt_hash_{file_hash}"] = vt_result
            print(f"VT Detections: {vt_result.get('positives', 0)}/{vt_result.get('total', 0)}")

            # 🧪 In a real scenario, you would extract domains/IPs from the analysis
            # For demo, we'll simulate finding related domains
            related_domains = ["related-malware.com", "c2-server.net"]
            for domain in related_domains:
                print(f"  Related Domain Found: {domain}")
                self.investigation_data["pivot_chain"].append({
                    "from": file_hash,
                    "to": domain,
                    "method": "VT_hash_analysis",
                    "timestamp": datetime.now().isoformat()
                })
                self.investigate_domain(domain)

    def investigate_ip(self, ip):
        """Investigate IP address"""
        print(f"\n=== Investigating IP: {ip} ===")

        # 🔄 Get reverse DNS from PassiveTotal
        pt_dns = self.pt.get_passive_dns(ip)
        if pt_dns:
            self.investigation_data["findings"][f"pt_reverse_dns_{ip}"] = pt_dns
            print(f"Reverse DNS Records: {pt_dns.get('totalRecords', 0)}")

            for record in pt_dns.get("results", [])[:2]:  # Limit to first 2
                domain = record.get("value", "")
                if domain:
                    print(f"  Reverse resolves to: {domain}")
                    self.investigation_data["pivot_chain"].append({
                        "from": ip,
                        "to": domain,
                        "method": "PT_reverse_dns",
                        "first_seen": record.get("firstSeen"),
                        "last_seen": record.get("lastSeen")
                    })

    def is_valid_ip(self, ip):
        """Basic IP validation"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    def generate_report(self):
        """Generate investigation report"""
        print(f"\n=== Investigation Report ===")
        print(f"Initial IOC: {self.investigation_data['initial_ioc']}")
        print(f"Investigation Started: {self.investigation_data['timestamp']}")
        print(f"Total Findings: {len(self.investigation_data['findings'])}")
        print(f"Pivot Chain Length: {len(self.investigation_data['pivot_chain'])}")

        print(f"\n=== Pivot Chain ===")
        for i, pivot in enumerate(self.investigation_data['pivot_chain'], 1):
            print(f"{i}. {pivot['from']} -> {pivot['to']} (via {pivot['method']})")

        # 💾 Save report to file
        with open(f"investigation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
            json.dump(self.investigation_data, f, indent=2)

        print(f"\nReport saved to investigation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

if __name__ == "__main__":
    engine = PivotEngine()

    # 🎯 Start investigation with a suspicious domain
    engine.start_investigation("malicious-example.com", "domain")

    # 📄 Generate final report
    engine.generate_report()
```

# TODO: Add a recursion depth limit to `investigate_domain`/`investigate_hash` to prevent runaway pivot chains

### 🔌 Subtask 3.2: Create MISP Integration Script

```bash
nano misp_integration.py
```

```python
#!/usr/bin/env python3
# 🔌 Convert a pivot investigation into a MISP event with typed attributes
import json
import requests
from datetime import datetime

class MISPIntegration:
    def __init__(self):
        self.misp_url = "http://localhost/MISP"
        self.misp_key = "demo_key"  # In real scenario, use actual API key
        self.demo_mode = True

    def create_event(self, investigation_data):
        """Create MISP event from investigation data"""
        if self.demo_mode:
            print("=== Creating MISP Event (Demo Mode) ===")

            event_data = {
                "Event": {
                    "info": f"Threat Investigation: {investigation_data['initial_ioc']}",
                    "threat_level_id": "2",  # Medium
                    "analysis": "1",  # Ongoing
                    "distribution": "1",  # Community
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "Attribute": []
                }
            }

            # 🎯 Add initial IOC as attribute
            event_data["Event"]["Attribute"].append({
                "category": "Network activity",
                "type": investigation_data["ioc_type"],
                "value": investigation_data["initial_ioc"],
                "to_ids": True,
                "comment": "Initial IOC from investigation"
            })

            # ↪️ Add pivoted IOCs
            for pivot in investigation_data["pivot_chain"]:
                attr_type = self.determine_attribute_type(pivot["to"])
                if attr_type:
                    event_data["Event"]["Attribute"].append({
                        "category": "Network activity",
                        "type": attr_type,
                        "value": pivot["to"],
                        "to_ids": True,
                        "comment": f"Discovered via {pivot['method']} from {pivot['from']}"
                    })

            print(f"Event created with {len(event_data['Event']['Attribute'])} attributes")

            # 💾 Save event data
            with open(f"misp_event_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
                json.dump(event_data, f, indent=2)

            return event_data

        # Real MISP API call would go here
        return None

    def determine_attribute_type(self, value):
        """Determine MISP attribute type based on value"""
        if self.is_domain(value):
            return "domain"
        elif self.is_ip(value):
            return "ip-dst"
        elif self.is_url(value):
            return "url"
        elif self.is_hash(value):
            if len(value) == 32:
                return "md5"
            elif len(value) == 40:
                return "sha1"
            elif len(value) == 64:
                return "sha256"
        return None

    def is_domain(self, value):
        return '.' in value and not value.startswith('http') and not self.is_ip(value)

    def is_ip(self, value):
        parts = value.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    def is_url(self, value):
        return value.startswith(('http://', 'https://'))

    def is_hash(self, value):
        return len(value) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in value)

if __name__ == "__main__":
    # 📂 Load investigation data
    import glob
    report_files = glob.glob("investigation_report_*.json")

    if report_files:
        latest_report = max(report_files)
        with open(latest_report, 'r') as f:
            investigation_data = json.load(f)

        misp = MISPIntegration()
        event = misp.create_event(investigation_data)

        print(f"MISP event created from {latest_report}")
    else:
        print("No investigation reports found. Run pivot_engine.py first.")
```

### ▶️ Subtask 3.3: Run Complete Investigation

Execute the complete investigation workflow:

```bash
# 🔧 Make scripts executable
chmod +x *.py

# 🧭 Run the pivot analysis
python3 pivot_engine.py

# 🔌 Integrate findings into MISP
python3 misp_integration.py

# 📁 View generated reports
ls -la *.json
```

### 📊 Subtask 3.4: Create Investigation Dashboard

```bash
nano dashboard.py
```

```python
#!/usr/bin/env python3
# 📊 Render a text dashboard summarizing the latest pivot investigation
import json
import glob
from datetime import datetime

def display_dashboard():
    """Display investigation dashboard"""
    print("=" * 60)
    print("THREAT INTELLIGENCE INVESTIGATION DASHBOARD")
    print("=" * 60)

    # 📂 Load latest investigation
    report_files = glob.glob("investigation_report_*.json")
    if not report_files:
        print("No investigations found.")
        return

    latest_report = max(report_files)
    with open(latest_report, 'r') as f:
        data = json.load(f)

    print(f"\nLatest Investigation: {latest_report}")
    print(f"Initial IOC: {data['initial_ioc']} ({data['ioc_type']})")
    print(f"Started: {data['timestamp']}")
    print(f"Total Findings: {len(data['findings'])}")
    print(f"Pivot Operations: {len(data['pivot_chain'])}")

    print(f"\n{'='*20} PIVOT CHAIN {'='*20}")
    for i, pivot in enumerate(data['pivot_chain'], 1):
        print(f"{i:2d}. {pivot['from']:<25} -> {pivot['to']:<25} [{pivot['method']}]")

    print(f"\n{'='*20} DATA SOURCES {'='*20}")
    vt_findings = sum(1 for key in data['findings'].keys() if key.startswith('vt_'))
    pt_findings = sum(1 for key in data['findings'].keys() if key.startswith('pt_'))

    print(f"VirusTotal Queries: {vt_findings}")
    print(f"PassiveTotal Queries: {pt_findings}")

    print(f"\n{'='*20} THREAT SUMMARY {'='*20}")

    # 🧮 Analyze findings for threat indicators
    domains_found = set()
    ips_found = set()

    for pivot in data['pivot_chain']:
        if '.' in pivot['to'] and not pivot['to'].startswith('http'):
            if any(char.isalpha() for char in pivot['to']):
                domains_found.add(pivot['to'])
            else:
                try:
                    parts = pivot['to'].split('.')
                    if len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts):
                        ips_found.add(pivot['to'])
                except:
                    pass

    print(f"Unique Domains Discovered: {len(domains_found)}")
    print(f"Unique IPs Discovered: {len(ips_found)}")

    if domains_found:
        print(f"\nDomains:")
        for domain in sorted(domains_found):
            print(f"  - {domain}")

    if ips_found:
        print(f"\nIP Addresses:")
        for ip in sorted(ips_found):
            print(f"  - {ip}")

    print(f"\n{'='*60}")

if __name__ == "__main__":
    display_dashboard()
```

Run the dashboard:

```bash
python3 dashboard.py
```

# TODO: Add a `--export csv` option to the dashboard for sharing findings outside the terminal

---

## 🧪 Verification and Testing

### ▶️ Test the Complete Workflow

```bash
# 🧭 Run complete investigation workflow
echo "Starting complete threat intelligence investigation..."

# 1️⃣ Run pivot analysis
python3 pivot_engine.py

# 2️⃣ Create MISP event
python3 misp_integration.py

# 3️⃣ Display dashboard
python3 dashboard.py

# 4️⃣ Verify all components
echo -e "\n=== Verification ==="
echo "Generated files:"
ls -la *.json

echo -e "\nMISP Status:"
sudo systemctl status apache2 | grep Active

echo -e "\nDatabase Status:"
sudo systemctl status mariadb | grep Active
```

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Tool Used |
|---|---|---|---|
| T1596.005 | Search Open Technical Databases: Scan Databases | Reconnaissance | VirusTotal |
| T1596.001 | Search Open Technical Databases: DNS/Passive DNS | Reconnaissance | PassiveTotal |
| T1590.001 | Gather Victim Network Information: Domain Properties | Reconnaissance | PassiveTotal (WHOIS) |
| T1583.001 | Acquire Infrastructure: Domains | Resource Development | Pivot Engine (name server pivoting) |
| T1583.006 | Acquire Infrastructure: Web Services | Resource Development | MISP event attribution |

---

## 🛠️ Troubleshooting

<details>
<summary>❌ MISP Installation Issues</summary>

Ensure all PHP modules are installed:

```bash
sudo apt install php-{mysql,xml,mbstring,zip,curl,json,gd,intl,bcmath}
```

Check the Apache error log for details:

```bash
sudo tail -f /var/log/apache2/error.log
```
</details>

<details>
<summary>❌ API Connection Issues (VirusTotal / PassiveTotal)</summary>

Verify network connectivity:

```bash
curl -I https://www.virustotal.com
```

Check that your API key format and permissions are correct, and confirm `DEMO_MODE` in `api_config.py` matches whether you intend to call the real APIs.
</details>

<details>
<summary>❌ Database Connection Issues</summary>

Verify MariaDB is running:

```bash
sudo systemctl status mariadb
```

Test the database connection directly:

```bash
mysql -u misp -p misp
```
</details>

<details>
<summary>❌ <code>misp_integration.py</code> reports "No investigation reports found"</summary>

Run `python3 pivot_engine.py` first — it generates the `investigation_report_*.json` file that `misp_integration.py` depends on.
</details>

---

## 🏁 Conclusion

### ✅ Key Accomplishments

- 🏗️ **MISP Setup:** Configured a complete threat intelligence platform for data sharing and enrichment
- 🔍 **Multi-Source Analysis:** Integrated VirusTotal and PassiveTotal for comprehensive IOC analysis
- 🧭 **Pivot Techniques:** Mastered the art of pivoting between different intelligence sources to uncover related threats
- 🕸️ **Adversary Tracking:** Built investigation chains that reveal adversary infrastructure and movement patterns
- 🔗 **Data Correlation:** Connected disparate threat indicators to build comprehensive attack timelines

### 🌍 Real-World Applications

This lab simulates real-world threat hunting scenarios where analysts must correlate information across multiple intelligence platforms to build a complete picture of adversary operations. The skills demonstrated here are essential for advanced threat intelligence analysis and incident response operations.

---

<div align="center">

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cybersecurity%20Training-1E90FF?style=for-the-badge)

</div>
