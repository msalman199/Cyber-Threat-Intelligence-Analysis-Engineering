<div align="center">

# 🕵️ Investigate Adversary Infrastructure with Amass + Shodan

### OSINT-Driven Infrastructure Mapping & Attack Surface Analysis

![Amass](https://img.shields.io/badge/Amass-v4-FF4500?style=for-the-badge&logo=owasp&logoColor=white)
![Shodan](https://img.shields.io/badge/Shodan-API-EE2939?style=for-the-badge&logo=shodan&logoColor=white)
![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-Scripting-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![DNS](https://img.shields.io/badge/DNS-Enumeration-0078D4?style=for-the-badge&logo=cloudflare&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Cloud%20Lab-FCC624?style=for-the-badge&logo=linux&logoColor=black)

</div>

---

## 📖 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [✅ Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🌐 Task 1: Set Up Amass to Gather Domain and Infrastructure Data](#-task-1-set-up-amass-to-gather-domain-and-infrastructure-data)
- [🔎 Task 2: Use Shodan to Scan for Exposed Systems](#-task-2-use-shodan-to-scan-for-exposed-systems)
- [🧩 Task 3: Correlate Data to Map Adversary Infrastructure](#-task-3-correlate-data-to-map-adversary-infrastructure)
- [🧪 Verification and Testing](#-verification-and-testing)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | Install and configure **Amass** for domain enumeration and infrastructure mapping |
| 2 | Utilize the **Shodan API** for exposed system reconnaissance |
| 3 | Correlate data from multiple sources to build comprehensive adversary infrastructure profiles |
| 4 | Analyze attack surfaces and potential security vulnerabilities |

## ✅ Prerequisites

| Requirement | Details |
|---|---|
| 🐧 Linux CLI | Basic command-line knowledge |
| 🌐 DNS Fundamentals | Understanding of DNS concepts and network fundamentals |
| 🕵️ Recon Principles | Familiarity with cybersecurity reconnaissance principles |
| 📡 Connectivity | Active internet connection for API queries |

## 🖥️ Lab Environment

> ☁️ **Al Nafi Cloud Lab** — Click **Start Lab** to spin up your dedicated Linux machine. The environment is bare metal with no pre-installed tools — every tool in this lab is installed from scratch as you go.

---

## 🌐 Task 1: Set Up Amass to Gather Domain and Infrastructure Data

### 🧱 Subtask 1.1: Install Amass and Dependencies

Update system packages and install required tools:

```bash
# 🔄 Refresh package index and upgrade existing packages
sudo apt update && sudo apt upgrade -y

# 📦 Install Go, Git, and download utilities
sudo apt install -y golang-go git curl wget
```

Install Amass from source:

```bash
# 🚀 Build and install Amass v4 via Go
go install -v github.com/owasp-amass/amass/v4/...@master

# 🧭 Add the Go binary path to your shell profile
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

Verify installation:

```bash
# ✅ Confirm Amass is installed and check the version
amass version
```

# TODO: Confirm the installed Amass version matches the release notes for your lab environment

### ⚙️ Subtask 1.2: Configure Amass Data Sources

Create the Amass configuration directory and file:

```bash
# 📁 Create the Amass config directory
mkdir -p ~/.config/amass

# 📝 Define enabled OSINT data sources and brute-force behavior
cat > ~/.config/amass/config.ini << 'EOF'
[data_sources]
minimum_ttl = 1440

[data_sources.AlienVault]
[data_sources.Censys]
[data_sources.CertSpotter]
[data_sources.Crtsh]
[data_sources.DNSRecon]
[data_sources.HackerTarget]
[data_sources.Riddler]
[data_sources.ThreatCrowd]
[data_sources.VirusTotal]
[data_sources.Wayback]

[bruteforce]
enabled = true
recursive = true
minimum_for_recursive = 1
EOF
```

### 🔍 Subtask 1.3: Perform Domain Enumeration

Create a target domain list for testing:

```bash
# 🎯 Build the list of target domains
echo "example.com" > targets.txt
echo "github.com" >> targets.txt
echo "microsoft.com" >> targets.txt
```

Run Amass enumeration:

```bash
# 🌐 Active + passive enumeration against the target domain
amass enum -d example.com -o amass_results.txt
```

Run passive enumeration with additional sources:

```bash
# 🕶️ Passive-only enumeration (no direct target interaction)
amass enum -passive -d example.com -o amass_passive.txt
```

View results:

```bash
# 👀 Inspect the discovered subdomains
cat amass_results.txt | head -20
wc -l amass_results.txt
```

# TODO: Swap `example.com` for a domain you're authorized to assess and re-run enumeration

---

## 🔎 Task 2: Use Shodan to Scan for Exposed Systems

### 🛰️ Subtask 2.1: Install Shodan CLI

Install Python pip and Shodan:

```bash
# 📦 Install pip
sudo apt install -y python3-pip

# 🛰️ Install the Shodan CLI
pip3 install shodan

# 🧭 Add the local bin path to your shell profile
echo 'export PATH=$PATH:~/.local/bin' >> ~/.bashrc
source ~/.bashrc
```

### 🔑 Subtask 2.2: Configure Shodan API

Create a free account at `shodan.io` and obtain your API key. Initialize the Shodan CLI:

```bash
# 🔑 Link your Shodan API key to the CLI
shodan init YOUR_API_KEY_HERE
```

Test Shodan connectivity:

```bash
# 📡 Verify API connectivity and account status
shodan info
```

# TODO: Store `YOUR_API_KEY_HERE` in a secrets manager rather than hardcoding it in scripts

### 🌍 Subtask 2.3: Search for Infrastructure Data

Search for systems by organization:

```bash
# 🏢 Search exposed systems by organization name
shodan search "org:Microsoft" --limit 10 > shodan_microsoft.txt
cat shodan_microsoft.txt
```

Search for specific services:

```bash
# 🧰 Search by exposed service/banner
shodan search "apache" --limit 5
shodan search "nginx" --limit 5
```

Search by IP range:

```bash
# 📡 Search within a specific network range
shodan search "net:8.8.8.0/24" --limit 5
```

Download host information:

```bash
# 🖥️ Pull detailed host information for a single IP
shodan host 8.8.8.8 > host_info.txt
cat host_info.txt
```

---

## 🧩 Task 3: Correlate Data to Map Adversary Infrastructure

### 🧮 Subtask 3.1: Extract IP Addresses from Amass Results

Create a script to resolve domains to IPs:

```bash
# 🧮 Resolve each discovered domain to its IPv4 address
cat > resolve_domains.sh << 'EOF'
#!/bin/bash
echo "Resolving domains to IP addresses..."
while read domain; do
    ip=$(dig +short $domain | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    if [ ! -z "$ip" ]; then
        echo "$domain,$ip"
    fi
done < amass_results.txt > domain_ip_mapping.csv
EOF

chmod +x resolve_domains.sh
./resolve_domains.sh
```

View IP mappings:

```bash
# 👀 Preview the domain → IP mapping
head -10 domain_ip_mapping.csv
```

### 🔗 Subtask 3.2: Cross-Reference with Shodan Data

Create the correlation script:

```python
#!/usr/bin/env python3
# 🔗 Cross-reference each resolved IP against Shodan host data
import csv
import subprocess
import json
import time

def get_shodan_info(ip):
    try:
        result = subprocess.run(['shodan', 'host', ip],
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return result.stdout
        return None
    except:
        return None

print("Domain,IP,Shodan_Info")
with open('domain_ip_mapping.csv', 'r') as f:
    for line in f:
        if ',' in line:
            domain, ip = line.strip().split(',', 1)
            shodan_info = get_shodan_info(ip)
            if shodan_info:
                # 🧵 Extract key fields from the raw Shodan output
                lines = shodan_info.split('\n')
                ports = [l for l in lines if 'Ports:' in l]
                org = [l for l in lines if 'Organization:' in l]

                info_summary = f"Ports: {ports[0] if ports else 'N/A'} | Org: {org[0] if org else 'N/A'}"
                print(f"{domain},{ip},{info_summary}")
            else:
                print(f"{domain},{ip},No Shodan data")
            time.sleep(1)  # ⏱️ Rate limiting
```

```bash
# ▶️ Run the correlation script and save results
chmod +x correlate_data.py
python3 correlate_data.py > infrastructure_map.csv
```

# TODO: Add error handling for domains that fail to resolve to any IP address

### 📊 Subtask 3.3: Generate Infrastructure Report

Create a comprehensive analysis script:

```bash
# 📊 Assemble a consolidated infrastructure report
cat > generate_report.sh << 'EOF'
#!/bin/bash
echo "=== ADVERSARY INFRASTRUCTURE ANALYSIS REPORT ===" > final_report.txt
echo "Generated on: $(date)" >> final_report.txt
echo "" >> final_report.txt

echo "=== DOMAIN ENUMERATION SUMMARY ===" >> final_report.txt
echo "Total domains discovered: $(wc -l < amass_results.txt)" >> final_report.txt
echo "Passive enumeration results: $(wc -l < amass_passive.txt)" >> final_report.txt
echo "" >> final_report.txt

echo "=== TOP 10 DISCOVERED DOMAINS ===" >> final_report.txt
head -10 amass_results.txt >> final_report.txt
echo "" >> final_report.txt

echo "=== IP ADDRESS MAPPINGS ===" >> final_report.txt
echo "Domain to IP mappings found: $(wc -l < domain_ip_mapping.csv)" >> final_report.txt
head -5 domain_ip_mapping.csv >> final_report.txt
echo "" >> final_report.txt

echo "=== INFRASTRUCTURE CORRELATION ===" >> final_report.txt
head -10 infrastructure_map.csv >> final_report.txt
echo "" >> final_report.txt

echo "=== ANALYSIS COMPLETE ===" >> final_report.txt
EOF

chmod +x generate_report.sh
./generate_report.sh
```

View the final report:

```bash
# 📄 Display the generated report
cat final_report.txt
```

### 🎯 Subtask 3.4: Identify Attack Surfaces

Create the attack surface analysis:

```bash
# 🎯 Summarize unique assets and flag high-risk subdomain patterns
cat > attack_surface.sh << 'EOF'
#!/bin/bash
echo "=== ATTACK SURFACE ANALYSIS ===" > attack_surface.txt
echo "" >> attack_surface.txt

echo "Unique IP addresses identified:" >> attack_surface.txt
cut -d',' -f2 domain_ip_mapping.csv | sort -u | wc -l >> attack_surface.txt
echo "" >> attack_surface.txt

echo "Unique domains identified:" >> attack_surface.txt
wc -l < amass_results.txt >> attack_surface.txt
echo "" >> attack_surface.txt

echo "Potential entry points (subdomains):" >> attack_surface.txt
grep -E "(admin|test|dev|staging|api|mail|ftp)" amass_results.txt | head -10 >> attack_surface.txt
echo "" >> attack_surface.txt
EOF

chmod +x attack_surface.sh
./attack_surface.sh
cat attack_surface.txt
```

# TODO: Add a severity rating column to attack_surface.txt (e.g., Low/Medium/High) based on exposed service and subdomain naming

---

## 🧪 Verification and Testing

```bash
# 🧱 Check Amass installation
amass version

# 🛰️ Check Shodan CLI
shodan info

# 📁 Verify output files exist
ls -la *.txt *.csv

# 📊 Display summary statistics
echo "Files created:"
echo "- Amass results: $(wc -l < amass_results.txt) domains"
echo "- IP mappings: $(wc -l < domain_ip_mapping.csv) entries"
echo "- Infrastructure map: $(wc -l < infrastructure_map.csv) correlations"
```

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Tool Used |
|---|---|---|---|
| T1590.002 | Gather Victim Network Information: DNS | Reconnaissance | Amass |
| T1596.001 | Search Open Technical Databases: DNS/Passive DNS | Reconnaissance | Amass |
| T1596.005 | Search Open Technical Databases: Scan Databases | Reconnaissance | Shodan |
| T1595.001 | Active Scanning: Scanning IP Blocks | Reconnaissance | Shodan |
| T1590.005 | Gather Victim Network Information: IP Addresses | Reconnaissance | resolve_domains.sh |

---

## 🛠️ Troubleshooting

<details>
<summary>❌ <code>amass: command not found</code></summary>

Ensure the Go bin path was added to your shell profile and reloaded:

```bash
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```
</details>

<details>
<summary>❌ Shodan API errors / <code>Invalid API key</code></summary>

Re-run `shodan init YOUR_API_KEY_HERE` with a valid key copied from your Shodan account dashboard, then re-test with `shodan info`.
</details>

<details>
<summary>❌ Empty <code>domain_ip_mapping.csv</code></summary>

Confirm `dig` is installed (`sudo apt install -y dnsutils`) and that `amass_results.txt` actually contains resolvable domains before running `resolve_domains.sh`.
</details>

<details>
<summary>❌ Shodan correlation script runs slowly or times out</summary>

The 1-second `time.sleep(1)` in `correlate_data.py` is intentional rate limiting to respect Shodan API limits — reduce the target list size for faster iteration during testing.
</details>

---

## 🏁 Conclusion

### ✅ Key Accomplishments

- 🌐 Enumerated domains using OSINT techniques with Amass
- 🛰️ Gathered intelligence on exposed systems using the Shodan API
- 🔗 Correlated data from multiple sources to build comprehensive infrastructure maps
- 🎯 Analyzed attack surfaces to identify potential security vulnerabilities

### 🌍 Real-World Applications

These skills are essential for **threat intelligence analysts**, **penetration testers**, and **security researchers** who need to understand adversary infrastructure and potential attack vectors. Combining passive reconnaissance tools provides a powerful methodology for mapping organizational digital footprints and identifying security exposures without direct interaction with target systems.

---

<div align="center">

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cybersecurity%20Training-1E90FF?style=for-the-badge)

</div>
