<div align="center">

# 🤖 Automate OSINT Pulls with SpiderFoot HX + recon-ng

### Building an Automated Intelligence Collection & Correlation Pipeline

![SpiderFoot](https://img.shields.io/badge/SpiderFoot-HX-8A2BE2?style=for-the-badge&logo=spider&logoColor=white)
![recon--ng](https://img.shields.io/badge/recon--ng-Reconnaissance-DC143C?style=for-the-badge&logo=gnometerminal&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-Automation-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Cloud%20Lab-FCC624?style=for-the-badge&logo=linux&logoColor=black)

</div>

---

## 📖 Table of Contents

- [🎯 Objectives](#-objectives)
- [✅ Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🕸️ Task 1: Set Up SpiderFoot HX for Automated OSINT Collection](#️-task-1-set-up-spiderfoot-hx-for-automated-osint-collection)
- [🔎 Task 2: Integrate recon-ng for Additional Data Pulls](#-task-2-integrate-recon-ng-for-additional-data-pulls)
- [🧩 Task 3: Correlate Findings for Adversary Profiling](#-task-3-correlate-findings-for-adversary-profiling)
- [🧪 Verification and Testing](#-verification-and-testing)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Objectives

| # | Objective |
|---|-----------|
| 1 | Install and configure **SpiderFoot HX** for automated OSINT collection |
| 2 | Set up **recon-ng** for comprehensive reconnaissance data gathering |
| 3 | Integrate both tools to create an automated intelligence pipeline |
| 4 | Correlate findings from multiple sources for adversary profiling |
| 5 | Generate comprehensive reports combining data from both platforms |

## ✅ Prerequisites

| Requirement | Details |
|---|---|
| 🐧 Linux CLI | Basic Linux command-line knowledge |
| 🕵️ OSINT Concepts | Understanding of OSINT concepts and methodologies |
| 🌐 Web Interfaces | Familiarity with web-based interfaces |
| 🐍 Python Packaging | Knowledge of Python package management |

## 🖥️ Lab Environment

> ☁️ **Al Nafi Cloud Lab** — Click **Start Lab** to spin up your dedicated Linux machine. The environment is bare metal with no pre-installed tools — every tool in this lab is installed from scratch as you go.

---

## 🕸️ Task 1: Set Up SpiderFoot HX for Automated OSINT Collection

### 📦 Subtask 1.1: Install SpiderFoot HX

Update system and install dependencies:

```bash
# 🔄 Update system and install dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip git wget curl -y
```

Clone and install SpiderFoot:

```bash
# 📥 Clone the SpiderFoot repository
cd /opt
sudo git clone https://github.com/smicallef/spiderfoot.git
sudo chown -R $USER:$USER spiderfoot
cd spiderfoot

# 📦 Install Python dependencies
pip3 install -r requirements.txt
```

# TODO: Verify the cloned SpiderFoot commit hash against a known-good release before installing dependencies

### ⚙️ Subtask 1.2: Configure SpiderFoot HX

Start the SpiderFoot web interface:

```bash
# ▶️ Launch SpiderFoot's web UI, listening on all interfaces
python3 sf.py -l 0.0.0.0:5001
```

Open a new terminal and verify the service:

```bash
# ✅ Confirm the web service is responding
curl -I http://localhost:5001
```

> 🌐 Access the SpiderFoot web interface by opening a browser and navigating to `http://localhost:5001`.

### 🎯 Subtask 1.3: Create Automated Scan Configuration

In the SpiderFoot web interface:

1. Click **New Scan**
2. Enter target domain: `example-target.com`
3. Select scan modules:
   - 🌐 DNS resolution modules
   - 📱 Social media modules
   - 📧 Email harvesting modules
   - 🧬 Subdomain enumeration modules
4. Configure scan settings:
   - Set **Scan Name**: `Automated_OSINT_Scan`
   - Enable **Auto-correlate findings**
   - Set **Maximum threads**: `10`
5. Start the scan and note the **scan ID** for later correlation.

# TODO: Replace `example-target.com` with a domain you're authorized to assess

---

## 🔎 Task 2: Integrate recon-ng for Additional Data Pulls

### 📦 Subtask 2.1: Install recon-ng

Install recon-ng from the official repository:

```bash
# 📥 Clone the recon-ng repository
cd /opt
sudo git clone https://github.com/lanmaster53/recon-ng.git
sudo chown -R $USER:$USER recon-ng
cd recon-ng

# 📦 Install Python dependencies
pip3 install -r REQUIREMENTS
```

### 🗂️ Subtask 2.2: Configure recon-ng Workspace

Launch recon-ng and create a workspace:

```bash
# ▶️ Launch the recon-ng console
python3 recon-ng
```

Within the recon-ng console:

```text
# 🗂️ Create an isolated workspace for this engagement
workspaces create osint_automation

# 🌐 Load and run a domains-hosts module
use recon/domains-hosts/hackertarget
options set SOURCE example-target.com
run
```

### 🧰 Subtask 2.3: Install and Configure Modules

Install essential modules for comprehensive data collection:

```text
# 📦 Install every available module from the marketplace
marketplace install all

# 🌐 Brute-force subdomain discovery
modules load recon/domains-hosts/brute_hosts
options set SOURCE example-target.com
run

# 🧭 Resolve discovered hosts to IPs
modules load recon/hosts-hosts/resolve
options set SOURCE default
run

# 📡 Pull netblock data from Shodan
modules load recon/netblocks-hosts/shodan_net
options set SOURCE default
run
```

# TODO: Add a Shodan API key via `keys add shodan_api <YOUR_KEY>` before running the `shodan_net` module

### 📤 Subtask 2.4: Export recon-ng Data

Export collected data for correlation:

```text
# 📋 Review collected hosts
show hosts

# 📤 Export in multiple formats for downstream correlation
output report html
output report csv
exit
```

---

## 🧩 Task 3: Correlate Findings for Adversary Profiling

### 🔗 Subtask 3.1: Create Data Correlation Script

Create a Python script to correlate findings from both tools:

```bash
# 📝 Open the correlation script for editing
nano /opt/correlate_osint.py
```

Add the following script:

```python
#!/usr/bin/env python3
# 🔗 Pull findings from SpiderFoot and recon-ng databases and merge them
import json
import csv
import sqlite3
import os
from datetime import datetime

class OSINTCorrelator:
    def __init__(self):
        self.spiderfoot_db = "/opt/spiderfoot/spiderfoot.db"
        self.reconng_db = "/opt/recon-ng/workspaces/osint_automation/data.db"
        self.output_file = "/opt/correlated_findings.json"

    def extract_spiderfoot_data(self):
        """Extract data from SpiderFoot database"""
        findings = []
        try:
            conn = sqlite3.connect(self.spiderfoot_db)
            cursor = conn.cursor()

            query = """
            SELECT scan_instance_id, data_type, data, source_data_type,
                   source_data, created_time
            FROM tbl_scan_results
            ORDER BY created_time DESC LIMIT 100
            """

            cursor.execute(query)
            results = cursor.fetchall()

            for row in results:
                findings.append({
                    'tool': 'spiderfoot',
                    'scan_id': row[0],
                    'data_type': row[1],
                    'data': row[2],
                    'source_type': row[3],
                    'source_data': row[4],
                    'timestamp': row[5]
                })

            conn.close()
        except Exception as e:
            print(f"Error extracting SpiderFoot data: {e}")

        return findings

    def extract_reconng_data(self):
        """Extract data from recon-ng database"""
        findings = []
        try:
            conn = sqlite3.connect(self.reconng_db)
            cursor = conn.cursor()

            # 🖥️ Get hosts data
            cursor.execute("SELECT host, ip_address, region, country FROM hosts")
            hosts = cursor.fetchall()

            for host in hosts:
                findings.append({
                    'tool': 'recon-ng',
                    'data_type': 'host',
                    'hostname': host[0],
                    'ip_address': host[1],
                    'region': host[2],
                    'country': host[3],
                    'timestamp': datetime.now().isoformat()
                })

            conn.close()
        except Exception as e:
            print(f"Error extracting recon-ng data: {e}")

        return findings

    def correlate_findings(self, spiderfoot_data, reconng_data):
        """Correlate findings from both tools"""
        correlated = {
            'summary': {
                'spiderfoot_findings': len(spiderfoot_data),
                'reconng_findings': len(reconng_data),
                'correlation_timestamp': datetime.now().isoformat()
            },
            'ip_addresses': set(),
            'domains': set(),
            'emails': set(),
            'social_profiles': [],
            'vulnerabilities': [],
            'correlated_data': []
        }

        # 🕸️ Process SpiderFoot data
        for finding in spiderfoot_data:
            if 'IP_ADDRESS' in finding['data_type']:
                correlated['ip_addresses'].add(finding['data'])
            elif 'DOMAIN' in finding['data_type']:
                correlated['domains'].add(finding['data'])
            elif 'EMAIL' in finding['data_type']:
                correlated['emails'].add(finding['data'])
            elif 'SOCIAL' in finding['data_type']:
                correlated['social_profiles'].append(finding)

        # 🔎 Process recon-ng data
        for finding in reconng_data:
            if finding['ip_address']:
                correlated['ip_addresses'].add(finding['ip_address'])
            if finding['hostname']:
                correlated['domains'].add(finding['hostname'])

        # 🔤 Convert sets to lists for JSON serialization
        correlated['ip_addresses'] = list(correlated['ip_addresses'])
        correlated['domains'] = list(correlated['domains'])
        correlated['emails'] = list(correlated['emails'])

        return correlated

    def generate_report(self):
        """Generate comprehensive correlation report"""
        print("Extracting SpiderFoot data...")
        spiderfoot_data = self.extract_spiderfoot_data()

        print("Extracting recon-ng data...")
        reconng_data = self.extract_reconng_data()

        print("Correlating findings...")
        correlated = self.correlate_findings(spiderfoot_data, reconng_data)

        # 💾 Save to JSON file
        with open(self.output_file, 'w') as f:
            json.dump(correlated, f, indent=2, default=str)

        print(f"Correlation report saved to: {self.output_file}")
        return correlated

if __name__ == "__main__":
    correlator = OSINTCorrelator()
    results = correlator.generate_report()

    print("\n=== OSINT Correlation Summary ===")
    print(f"SpiderFoot findings: {results['summary']['spiderfoot_findings']}")
    print(f"recon-ng findings: {results['summary']['reconng_findings']}")
    print(f"Unique IP addresses: {len(results['ip_addresses'])}")
    print(f"Unique domains: {len(results['domains'])}")
    print(f"Email addresses found: {len(results['emails'])}")
```

Make the script executable:

```bash
chmod +x /opt/correlate_osint.py
```

# TODO: Add a `--min-confidence` flag to filter out low-signal SpiderFoot data types before correlation

### ▶️ Subtask 3.2: Run Correlation Analysis

Execute the correlation script:

```bash
# 🔗 Merge SpiderFoot and recon-ng findings into one JSON file
python3 /opt/correlate_osint.py
```

### 🧑‍💻 Subtask 3.3: Generate Adversary Profile

Create an adversary profiling script:

```bash
nano /opt/adversary_profile.py
```

Add the following content:

```python
#!/usr/bin/env python3
# 🧑‍💻 Turn correlated OSINT data into a structured adversary/exposure profile
import json
import sys
from datetime import datetime

def generate_adversary_profile(correlation_file):
    """Generate adversary profile from correlated OSINT data"""

    try:
        with open(correlation_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print("Correlation file not found. Run correlation script first.")
        return

    profile = {
        'target_analysis': {
            'assessment_date': datetime.now().isoformat(),
            'data_sources': ['SpiderFoot HX', 'recon-ng'],
            'confidence_level': 'Medium'
        },
        'infrastructure': {
            'ip_addresses': data.get('ip_addresses', []),
            'domains': data.get('domains', []),
            'subdomains': []
        },
        'attack_surface': {
            'exposed_services': [],
            'email_addresses': data.get('emails', []),
            'social_media_presence': len(data.get('social_profiles', []))
        },
        'risk_assessment': {
            'exposure_level': 'TBD',
            'recommendations': []
        }
    }

    # 🧮 Analyze infrastructure
    ip_count = len(profile['infrastructure']['ip_addresses'])
    domain_count = len(profile['infrastructure']['domains'])

    if ip_count > 10:
        profile['risk_assessment']['exposure_level'] = 'High'
        profile['risk_assessment']['recommendations'].append(
            'Large IP address space detected - review for unnecessary exposure'
        )
    elif ip_count > 5:
        profile['risk_assessment']['exposure_level'] = 'Medium'
    else:
        profile['risk_assessment']['exposure_level'] = 'Low'

    # 📧 Analyze email exposure
    email_count = len(profile['attack_surface']['email_addresses'])
    if email_count > 5:
        profile['risk_assessment']['recommendations'].append(
            'Multiple email addresses exposed - potential for social engineering'
        )

    # 💾 Save profile
    profile_file = '/opt/adversary_profile.json'
    with open(profile_file, 'w') as f:
        json.dump(profile, f, indent=2)

    print("=== ADVERSARY PROFILE GENERATED ===")
    print(f"Target Infrastructure: {ip_count} IPs, {domain_count} domains")
    print(f"Email Exposure: {email_count} addresses")
    print(f"Social Media Presence: {profile['attack_surface']['social_media_presence']} profiles")
    print(f"Risk Level: {profile['risk_assessment']['exposure_level']}")
    print(f"Profile saved to: {profile_file}")

    return profile

if __name__ == "__main__":
    correlation_file = '/opt/correlated_findings.json'
    generate_adversary_profile(correlation_file)
```

Run the adversary profiling:

```bash
python3 /opt/adversary_profile.py
```

# TODO: Extend `risk_assessment` with a weighted scoring model instead of fixed IP-count thresholds

### 🧵 Subtask 3.4: Create Automation Script

Create a master automation script:

```bash
nano /opt/automate_osint.sh
```

Add the following content:

```bash
#!/bin/bash
# 🧵 Orchestrate SpiderFoot + recon-ng scans, then correlate and profile

echo "=== AUTOMATED OSINT COLLECTION PIPELINE ==="
echo "Starting at: $(date)"

TARGET_DOMAIN="$1"
if [ -z "$TARGET_DOMAIN" ]; then
    echo "Usage: $0 <target_domain>"
    exit 1
fi

echo "Target: $TARGET_DOMAIN"

# 🕸️ Start SpiderFoot scan
echo "Starting SpiderFoot scan..."
cd /opt/spiderfoot
python3 sf.py -s $TARGET_DOMAIN -t all -q &
SPIDERFOOT_PID=$!

# 🔎 Run recon-ng scan
echo "Starting recon-ng reconnaissance..."
cd /opt/recon-ng
python3 recon-ng -w osint_automation -C "modules load recon/domains-hosts/hackertarget; options set SOURCE $TARGET_DOMAIN; run; exit" &
RECONNG_PID=$!

# ⏳ Wait for both tools to complete
echo "Waiting for scans to complete..."
wait $SPIDERFOOT_PID
wait $RECONNG_PID

# 🔗 Correlate findings
echo "Correlating findings..."
python3 /opt/correlate_osint.py

# 🧑‍💻 Generate adversary profile
echo "Generating adversary profile..."
python3 /opt/adversary_profile.py

echo "=== AUTOMATION COMPLETE ==="
echo "Results available in:"
echo "  - /opt/correlated_findings.json"
echo "  - /opt/adversary_profile.json"
```

Make the script executable:

```bash
chmod +x /opt/automate_osint.sh
```

### 🚀 Subtask 3.5: Test Complete Automation

Run the complete automation pipeline:

```bash
# 🚀 Kick off the full pipeline against the target domain
/opt/automate_osint.sh example-target.com
```

View the final results:

```bash
# 📄 Pretty-print the final adversary profile
cat /opt/adversary_profile.json | python3 -m json.tool
```

---

## 🧪 Verification and Testing

```bash
# 🕸️ Check SpiderFoot installation
python3 /opt/spiderfoot/sf.py --help

# 🔎 Check recon-ng installation
python3 /opt/recon-ng/recon-ng --help

# 📁 Verify output files exist
ls -la /opt/correlated_findings.json /opt/adversary_profile.json

# ✅ Check automation script syntax
bash -n /opt/automate_osint.sh
```

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Tool Used |
|---|---|---|---|
| T1596 | Search Open Technical Databases | Reconnaissance | SpiderFoot HX |
| T1593.001 | Search Open Websites/Domains: Social Media | Reconnaissance | SpiderFoot HX |
| T1589.002 | Gather Victim Identity Information: Email Addresses | Reconnaissance | SpiderFoot HX, recon-ng |
| T1590.005 | Gather Victim Network Information: IP Addresses | Reconnaissance | recon-ng (hackertarget, resolve, shodan_net) |
| T1590.001 | Gather Victim Network Information: Domain Properties | Reconnaissance | recon-ng (brute_hosts) |

---

## 🛠️ Troubleshooting

<details>
<summary>❌ SpiderFoot web UI unreachable at <code>localhost:5001</code></summary>

Confirm `python3 sf.py -l 0.0.0.0:5001` is still running in its terminal, and check for port conflicts with `sudo lsof -i :5001` before retrying.
</details>

<details>
<summary>❌ <code>pip3 install -r requirements.txt</code> fails for SpiderFoot or recon-ng</summary>

Ensure `python3-pip` installed correctly in Subtask 1.1, and re-run with `pip3 install --upgrade pip` first if dependency resolution errors appear.
</details>

<details>
<summary>❌ <code>correlate_osint.py</code> reports "Error extracting SpiderFoot data"</summary>

Confirm the scan in Task 1 has actually completed and `/opt/spiderfoot/spiderfoot.db` exists before running the correlation script — an in-progress scan may hold a lock on the database.
</details>

<details>
<summary>❌ recon-ng workspace or hosts table not found</summary>

Verify the workspace name matches exactly — `osint_automation` — since `reconng_db` in `correlate_osint.py` hardcodes that path, and re-run `workspaces create osint_automation` if it wasn't created in Subtask 2.2.
</details>

---

## 🏁 Conclusion

### ✅ Key Accomplishments

- 🕸️ Set up automated OSINT data collection with SpiderFoot HX
- 🔎 Gathered comprehensive reconnaissance data with recon-ng
- 🔗 Implemented cross-tool correlation between two independent OSINT platforms
- 🧑‍💻 Generated structured adversary profiles with risk-level scoring
- 🧵 Created reusable automation scripts that can be deployed for ongoing intelligence operations

### 🌍 Real-World Applications

This integrated approach significantly enhances the efficiency and comprehensiveness of OSINT gathering activities. The automation scripts built here can correlate findings from different sources, generate adversary profiles, and provide actionable intelligence for security assessments — skills directly applicable to threat intelligence programs, red team engagements, and external attack surface management.

---

<div align="center">

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cybersecurity%20Training-1E90FF?style=for-the-badge)

</div>
