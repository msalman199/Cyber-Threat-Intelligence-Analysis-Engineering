<div align="center">

# 🤖 Use AI (LangChain + MISP) to Enrich Raw Intel Feeds

### AI-Driven IOC Extraction · MISP Threat Sharing · Automated Enrichment Pipelines

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-Shell_Scripting-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![MISP](https://img.shields.io/badge/MISP-Threat_Sharing-1F4E79?style=for-the-badge)
![LangChain](https://img.shields.io/badge/LangChain-AI_Orchestration-1C3C3C?style=for-the-badge&logo=langchain&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-Database-4479A1?style=for-the-badge&logo=mysql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-Cache-DC382D?style=for-the-badge&logo=redis&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-Data_Analysis-150458?style=for-the-badge&logo=pandas&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Advanced-red?style=for-the-badge)
![Duration](https://img.shields.io/badge/Duration-~4_Hours-informational?style=for-the-badge)

</div>

---

## 📖 Overview

This lab stands up a full **MISP** (Malware Information Sharing Platform) instance and wires it together with **LangChain**-powered Python tooling to automatically extract, enrich, and analyze indicators of compromise from raw threat intelligence feeds. You'll build a regex-driven IOC extractor, enrich hits against MISP, auto-create MISP events, generate prioritized threat reports, and run the whole pipeline across multiple feed files at once.

---

## 📑 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [✅ Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🧩 Task 1: Set up MISP for IOC Enrichment](#-task-1-set-up-misp-for-ioc-enrichment)
- [🔗 Task 2: Integrate LangChain to Automate Data Enrichment](#-task-2-integrate-langchain-to-automate-data-enrichment)
- [📊 Task 3: Analyze Enriched Feeds for Actionable Intelligence](#-task-3-analyze-enriched-feeds-for-actionable-intelligence)
- [🧪 Verification and Testing](#-verification-and-testing)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

By completing this lab, you will:

| # | Objective |
|---|-----------|
| 1 | 🗄️ Set up and configure MISP (Malware Information Sharing Platform) for IOC management |
| 2 | 🔗 Integrate LangChain with MISP to automate intelligence enrichment |
| 3 | 🔎 Process raw threat intelligence feeds and extract actionable insights |
| 4 | 🤖 Implement AI-driven analysis workflows for cybersecurity intelligence |

---

## ✅ Prerequisites

| Requirement | Details |
|-------------|---------|
| 🐍 Python Programming | Basic understanding of Python |
| 🔌 REST APIs / JSON | Familiarity with REST APIs and JSON data structures |
| 🔐 Threat Intelligence | Knowledge of cybersecurity concepts (IOCs, threat intelligence) |
| 🐧 Linux CLI | Experience with Linux command line operations |

---

## 🖥️ Lab Environment

> 💡 **Al Nafi provides a Linux-based cloud machine for this lab.** Click **Start Lab** to access your dedicated environment. The machine comes as bare metal with no pre-installed tools — you'll install all required components during the lab.

---

## 🧩 Task 1: Set up MISP for IOC Enrichment

### 📦 Subtask 1.1: Install System Dependencies

```bash
# 🔄 Update the system and install required packages
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git curl wget apache2 mysql-server redis-server

# ▶️ Start and enable core services
sudo systemctl start mysql redis-server apache2
sudo systemctl enable mysql redis-server apache2
```

### ⬇️ Subtask 1.2: Install MISP

```bash
# 📥 Download and install MISP
cd /var/www/html
sudo git clone https://github.com/MISP/MISP.git
cd MISP
sudo git submodule update --init --recursive
sudo chown -R www-data:www-data /var/www/html/MISP
```

### 🗄️ Subtask 1.3: Configure MySQL Database

```bash
# 🔑 Set up the MISP database
sudo mysql -u root -p
```

```sql
-- 🏗️ Run inside the MySQL prompt
CREATE DATABASE misp;
CREATE USER 'misp'@'localhost' IDENTIFIED BY 'misppassword';
GRANT ALL PRIVILEGES ON misp.* TO 'misp'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

> 📝 **TODO:** Replace `misppassword` with a strong, unique credential before using this outside an isolated lab environment.

### 📚 Subtask 1.4: Install MISP Dependencies

```bash
cd /var/www/html/MISP
sudo -u www-data composer install --no-dev
sudo -u www-data cp -a app/Config/bootstrap.default.php app/Config/bootstrap.php
sudo -u www-data cp -a app/Config/database.default.php app/Config/database.php
sudo -u www-data cp -a app/Config/core.default.php app/Config/core.php
sudo -u www-data cp -a app/Config/config.default.php app/Config/config.php
```

### 🔧 Subtask 1.5: Configure MISP Database Connection

```bash
# 📝 Edit the database configuration
sudo nano app/Config/database.php
```

```php
// ⚙️ Update the database settings
public $default = array(
    'datasource' => 'Database/Mysql',
    'persistent' => false,
    'host' => 'localhost',
    'login' => 'misp',
    'password' => 'misppassword',
    'database' => 'misp',
    'prefix' => '',
    'encoding' => 'utf8',
);
```

### 🏁 Subtask 1.6: Initialize MISP Database

```bash
sudo -u www-data app/Console/cake Admin setSetting "MISP.baseurl" "http://localhost"
sudo -u www-data app/Console/cake Admin setSetting "MISP.python_bin" "/usr/bin/python3"
sudo -u www-data app/Console/cake schema create
```

---

## 🔗 Task 2: Integrate LangChain to Automate Data Enrichment

### 🐍 Subtask 2.1: Create Python Virtual Environment

```bash
cd /home/ubuntu
python3 -m venv misp-langchain-env
source misp-langchain-env/bin/activate
pip install --upgrade pip
```

### 📦 Subtask 2.2: Install Required Python Packages

```bash
pip install langchain langchain-openai pymisp requests pandas numpy python-dotenv
```

### ⚙️ Subtask 2.3: Create MISP API Configuration

```bash
# 📝 Create a configuration file
nano misp_config.py
```

```python
#!/usr/bin/env python3
# 📄 misp_config.py — central MISP + OpenAI connection settings

import os
from dotenv import load_dotenv

load_dotenv()

MISP_CONFIG = {
    'url': 'http://localhost',
    'key': 'your-misp-api-key-here',  # Will be generated later
    'ssl': False,
    'debug': True,
    'proxies': None,
    'cert': None,
    'auth': None,
    'tool': 'LangChain-MISP-Integration'
}

# 🤖 OpenAI API configuration (optional - for advanced AI features)
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
```

> 📝 **TODO:** Generate a real MISP API key from **Global Actions → My Profile** in the MISP web UI and replace the placeholder value above.

### 🧠 Subtask 2.4: Create Intelligence Enrichment Script

```bash
# 📝 Create the main enrichment script
nano intel_enricher.py
```

```python
#!/usr/bin/env python3
# 📄 intel_enricher.py — extracts IOCs from raw text, enriches via MISP, creates MISP events

import json
import re
import requests
from pymisp import PyMISP
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document
from misp_config import MISP_CONFIG
import logging

# 📋 Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IntelligenceEnricher:
    def __init__(self):
        self.misp = PyMISP(
            url=MISP_CONFIG['url'],
            key=MISP_CONFIG['key'],
            ssl=MISP_CONFIG['ssl'],
            debug=MISP_CONFIG['debug']
        )
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200
        )

    def extract_iocs(self, text):
        """Extract IOCs from raw text using regex patterns"""
        iocs = {
            'ips': [],
            'domains': [],
            'urls': [],
            'hashes': [],
            'emails': []
        }

        # 🌐 IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        iocs['ips'] = re.findall(ip_pattern, text)

        # 🌍 Domain names
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b'
        iocs['domains'] = re.findall(domain_pattern, text)
        iocs['domains'] = ['.'.join(domain) for domain in iocs['domains']]

        # 🔗 URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        iocs['urls'] = re.findall(url_pattern, text)

        # 🧬 Hash values (MD5, SHA1, SHA256)
        hash_patterns = [
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b',  # SHA1
            r'\b[a-fA-F0-9]{64}\b'   # SHA256
        ]
        for pattern in hash_patterns:
            iocs['hashes'].extend(re.findall(pattern, text))

        # ✉️ Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        iocs['emails'] = re.findall(email_pattern, text)

        return iocs

    def enrich_with_misp(self, iocs):
        """Enrich IOCs using MISP database"""
        enriched_data = {}

        for ioc_type, ioc_list in iocs.items():
            enriched_data[ioc_type] = []
            for ioc in ioc_list:
                try:
                    # 🔍 Search for existing IOC in MISP
                    search_result = self.misp.search(value=ioc)
                    if search_result:
                        enriched_data[ioc_type].append({
                            'value': ioc,
                            'misp_data': search_result,
                            'threat_level': 'Known threat' if search_result else 'Unknown'
                        })
                    else:
                        enriched_data[ioc_type].append({
                            'value': ioc,
                            'misp_data': None,
                            'threat_level': 'Unknown'
                        })
                except Exception as e:
                    logger.error(f"Error enriching {ioc}: {str(e)}")
                    enriched_data[ioc_type].append({
                        'value': ioc,
                        'misp_data': None,
                        'threat_level': 'Error',
                        'error': str(e)
                    })

        return enriched_data

    def create_misp_event(self, enriched_data, event_info="Automated Intel Feed Analysis"):
        """Create a new MISP event with enriched IOCs"""
        try:
            event = self.misp.new_event(
                distribution=0,
                threat_level_id=2,
                analysis=1,
                info=event_info
            )

            event_id = event['Event']['id']

            # 📌 Add attributes to the event
            for ioc_type, ioc_list in enriched_data.items():
                for ioc_data in ioc_list:
                    if ioc_data['value']:
                        attribute_type = self.map_ioc_type_to_misp(ioc_type)
                        if attribute_type:
                            self.misp.add_attribute(
                                event_id,
                                attribute_type,
                                ioc_data['value'],
                                comment=f"Auto-extracted from intel feed - {ioc_data['threat_level']}"
                            )

            logger.info(f"Created MISP event {event_id} with enriched IOCs")
            return event_id

        except Exception as e:
            logger.error(f"Error creating MISP event: {str(e)}")
            return None

    def map_ioc_type_to_misp(self, ioc_type):
        """Map IOC types to MISP attribute types"""
        mapping = {
            'ips': 'ip-dst',
            'domains': 'domain',
            'urls': 'url',
            'hashes': 'md5',  # Default to MD5, could be improved
            'emails': 'email-src'
        }
        return mapping.get(ioc_type)

    def process_intel_feed(self, raw_text):
        """Main processing function"""
        logger.info("Starting intelligence feed processing...")

        # 🎯 Extract IOCs
        iocs = self.extract_iocs(raw_text)
        logger.info(f"Extracted IOCs: {sum(len(v) for v in iocs.values())} total")

        # 🔗 Enrich with MISP
        enriched_data = self.enrich_with_misp(iocs)

        # 📌 Create MISP event
        event_id = self.create_misp_event(enriched_data)

        return {
            'extracted_iocs': iocs,
            'enriched_data': enriched_data,
            'misp_event_id': event_id
        }

def main():
    # 📄 Sample raw intelligence feed data
    sample_intel_feed = """
    Threat Report: APT Group Activity

    Recent analysis has identified malicious activity from IP addresses 192.168.1.100 and 10.0.0.50.
    The threat actors are using domain malicious-site.com and evil-domain.net for C2 communication.

    Malware samples with hashes:
    MD5: 5d41402abc4b2a76b9719d911017c592
    SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae

    Phishing emails observed from attacker@malicious-site.com targeting victims.

    Additional IOCs:
    - URL: http://malicious-site.com/payload.exe
    - IP: 203.0.113.42
    """

    enricher = IntelligenceEnricher()
    results = enricher.process_intel_feed(sample_intel_feed)

    print("\n=== Intelligence Enrichment Results ===")
    print(json.dumps(results, indent=2, default=str))

if __name__ == "__main__":
    main()
```

> 📝 **TODO:** Improve `map_ioc_type_to_misp()` to detect hash length (32/40/64 hex chars) and map to `md5`, `sha1`, or `sha256` accordingly instead of always defaulting to MD5.

---

## 📊 Task 3: Analyze Enriched Feeds for Actionable Intelligence

### 📈 Subtask 3.1: Create Analysis Dashboard Script

```bash
nano intel_analyzer.py
```

```python
#!/usr/bin/env python3
# 📄 intel_analyzer.py — scores threat patterns and exports a CSV summary

import json
import pandas as pd
from collections import Counter
from intel_enricher import IntelligenceEnricher
import matplotlib.pyplot as plt

class IntelligenceAnalyzer:
    def __init__(self):
        self.enricher = IntelligenceEnricher()

    def analyze_threat_patterns(self, enriched_data):
        """Analyze patterns in enriched threat intelligence"""
        analysis_results = {
            'ioc_summary': {},
            'threat_levels': {},
            'recommendations': []
        }

        # 🔢 Count IOCs by type
        for ioc_type, ioc_list in enriched_data.items():
            analysis_results['ioc_summary'][ioc_type] = len(ioc_list)

            # 🚦 Analyze threat levels
            threat_levels = [ioc.get('threat_level', 'Unknown') for ioc in ioc_list]
            analysis_results['threat_levels'][ioc_type] = Counter(threat_levels)

        # 💡 Generate recommendations
        total_known_threats = sum(
            counts.get('Known threat', 0)
            for counts in analysis_results['threat_levels'].values()
        )

        if total_known_threats > 0:
            analysis_results['recommendations'].append(
                f"HIGH PRIORITY: {total_known_threats} known threats detected - immediate investigation required"
            )

        unknown_threats = sum(
            counts.get('Unknown', 0)
            for counts in analysis_results['threat_levels'].values()
        )

        if unknown_threats > 5:
            analysis_results['recommendations'].append(
                f"MEDIUM PRIORITY: {unknown_threats} unknown IOCs require further analysis"
            )

        return analysis_results

    def generate_report(self, analysis_results):
        """Generate a comprehensive threat intelligence report"""
        report = []
        report.append("=" * 60)
        report.append("THREAT INTELLIGENCE ANALYSIS REPORT")
        report.append("=" * 60)

        # 📊 IOC Summary
        report.append("\n📊 IOC SUMMARY:")
        for ioc_type, count in analysis_results['ioc_summary'].items():
            report.append(f"  {ioc_type.upper()}: {count}")

        # 🚨 Threat Level Analysis
        report.append("\n🚨 THREAT LEVEL BREAKDOWN:")
        for ioc_type, threat_counts in analysis_results['threat_levels'].items():
            if threat_counts:
                report.append(f"  {ioc_type.upper()}:")
                for threat_level, count in threat_counts.items():
                    report.append(f"    - {threat_level}: {count}")

        # 💡 Recommendations
        report.append("\n💡 RECOMMENDATIONS:")
        for i, recommendation in enumerate(analysis_results['recommendations'], 1):
            report.append(f"  {i}. {recommendation}")

        if not analysis_results['recommendations']:
            report.append("  No immediate threats detected. Continue monitoring.")

        report.append("\n" + "=" * 60)

        return "\n".join(report)

    def export_to_csv(self, enriched_data, filename="threat_intelligence_export.csv"):
        """Export enriched data to CSV for further analysis"""
        rows = []

        for ioc_type, ioc_list in enriched_data.items():
            for ioc_data in ioc_list:
                rows.append({
                    'IOC_Type': ioc_type,
                    'IOC_Value': ioc_data['value'],
                    'Threat_Level': ioc_data['threat_level'],
                    'MISP_Match': 'Yes' if ioc_data['misp_data'] else 'No',
                    'Error': ioc_data.get('error', '')
                })

        df = pd.DataFrame(rows)
        df.to_csv(filename, index=False)
        print(f"Data exported to {filename}")
        return df

def main():
    # 📄 Sample intelligence feed for analysis
    sample_feed = """
    Security Alert: Ransomware Campaign Detected

    Multiple organizations report infections from ransomware family "CryptoLocker2024"

    Command and Control servers:
    - 198.51.100.42
    - 203.0.113.15
    - malware-c2.example.com
    - backup-c2.badsite.net

    Malware samples:
    MD5: d41d8cd98f00b204e9800998ecf8427e
    SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
    SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

    Phishing campaign using:
    - sender@phishing-domain.com
    - http://phishing-domain.com/login
    - http://fake-bank.malicious.net/secure

    Additional indicators:
    - Registry key: HKLM\\Software\\CryptoLocker2024
    - File path: C:\\temp\\malware.exe
    - Mutex: Global\\CryptoLocker2024_Mutex
    """

    analyzer = IntelligenceAnalyzer()

    # ▶️ Process the intelligence feed
    print("Processing intelligence feed...")
    results = analyzer.enricher.process_intel_feed(sample_feed)

    # 🔬 Analyze the results
    print("Analyzing threat patterns...")
    analysis = analyzer.analyze_threat_patterns(results['enriched_data'])

    # 📄 Generate and display report
    report = analyzer.generate_report(analysis)
    print(report)

    # 💾 Export to CSV
    df = analyzer.export_to_csv(results['enriched_data'])
    print(f"\nProcessed {len(df)} IOCs total")

    # 📈 Display summary statistics
    print("\n📈 SUMMARY STATISTICS:")
    print(df['IOC_Type'].value_counts().to_string())

if __name__ == "__main__":
    main()
```

### 📁 Subtask 3.2: Create Sample Intelligence Feeds

```bash
mkdir -p intel_feeds
nano intel_feeds/sample_feed_1.txt
```

```text
APT29 Campaign Analysis - March 2024

Recent spear-phishing campaign targeting government entities.

Infrastructure:
- C2 Server: 185.220.101.42
- Backup C2: secure-update.gov-portal.net
- Phishing domain: government-portal.secure-login.net

Malware artifacts:
SHA256: 7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730
MD5: 098f6bcd4621d373cade4e832627b4f6
File: government_update.exe

Email indicators:
From: admin@government-portal.secure-login.net
Subject: Urgent Security Update Required

URLs:
https://government-portal.secure-login.net/update
http://185.220.101.42/payload.bin
```

### 🚀 Subtask 3.3: Run Complete Analysis Pipeline

```bash
# 📝 Create a comprehensive analysis script
nano run_analysis.py
```

```python
#!/usr/bin/env python3
# 📄 run_analysis.py — batch-processes every feed in intel_feeds/ and combines the results

import os
import glob
from intel_enricher import IntelligenceEnricher
from intel_analyzer import IntelligenceAnalyzer

def process_multiple_feeds():
    """Process multiple intelligence feeds and generate comprehensive analysis"""

    enricher = IntelligenceEnricher()
    analyzer = IntelligenceAnalyzer()

    # 📂 Process all feed files
    feed_files = glob.glob("intel_feeds/*.txt")
    all_results = []

    print("🔍 Processing Intelligence Feeds...")
    print("=" * 50)

    for feed_file in feed_files:
        print(f"\nProcessing: {feed_file}")

        with open(feed_file, 'r') as f:
            feed_content = f.read()

        # ▶️ Process the feed
        results = enricher.process_intel_feed(feed_content)
        all_results.append({
            'source': feed_file,
            'results': results
        })

        # 📊 Quick summary
        total_iocs = sum(len(v) for v in results['extracted_iocs'].values())
        print(f"  ✓ Extracted {total_iocs} IOCs")
        print(f"  ✓ Created MISP event: {results['misp_event_id']}")

    # 🧩 Combine all results for comprehensive analysis
    combined_enriched_data = {
        'ips': [],
        'domains': [],
        'urls': [],
        'hashes': [],
        'emails': []
    }

    for result_set in all_results:
        for ioc_type in combined_enriched_data.keys():
            combined_enriched_data[ioc_type].extend(
                result_set['results']['enriched_data'].get(ioc_type, [])
            )

    # 🔬 Generate comprehensive analysis
    print("\n🔬 COMPREHENSIVE THREAT ANALYSIS")
    print("=" * 50)

    analysis = analyzer.analyze_threat_patterns(combined_enriched_data)
    report = analyzer.generate_report(analysis)
    print(report)

    # 💾 Export comprehensive dataset
    df = analyzer.export_to_csv(combined_enriched_data, "comprehensive_threat_intel.csv")

    return all_results, analysis

if __name__ == "__main__":
    results, analysis = process_multiple_feeds()
```

### ▶️ Subtask 3.4: Execute the Complete Analysis

```bash
# 🐍 Activate virtual environment
source misp-langchain-env/bin/activate

# 🚀 Run the analysis
python3 run_analysis.py
```

### 🔍 Subtask 3.5: Verify Results

```bash
# 📄 View CSV export
head -10 comprehensive_threat_intel.csv

# 📂 Check for MISP events (if MISP is properly configured)
ls -la intel_feeds/

# 📊 View analysis results
cat threat_intelligence_export.csv
```

---

## 🧪 Verification and Testing

### ✅ Test IOC Extraction

```bash
# 📝 Create a simple test script
nano test_extraction.py
```

```python
# 📄 test_extraction.py — quick sanity check for the extractor
from intel_enricher import IntelligenceEnricher

enricher = IntelligenceEnricher()
test_text = "Malicious IP 192.168.1.1 and domain evil.com detected"
iocs = enricher.extract_iocs(test_text)
print("Extracted IOCs:", iocs)
```

```bash
# ▶️ Run the test
python3 test_extraction.py
```

---

## 🗺️ MITRE ATT&CK Mapping

The IOC categories extracted and enriched by this pipeline correspond to observable artifacts across the following ATT&CK tactics — reflected directly in the lab's sample feeds (APT29 phishing infrastructure, CryptoLocker2024 ransomware C2):

| IOC Type | ATT&CK Tactic | Related Technique | Example from Lab Data |
|---|---|---|---|
| ✉️ Email addresses | Initial Access | T1566 (Phishing) | `admin@government-portal.secure-login.net` |
| 🔗 URLs | Initial Access, Execution | T1204 (User Execution) | `https://government-portal.secure-login.net/update` |
| 🌐 Domains / IPs | Command and Control | T1071 (Application Layer Protocol) | `185.220.101.42`, `malware-c2.example.com` |
| 🧬 File hashes | Execution, Defense Evasion | T1027 (Obfuscated Files or Information) | SHA256 artifact for `government_update.exe` |
| 🗝️ Registry keys / mutexes | Persistence | T1112 (Modify Registry) | `HKLM\Software\CryptoLocker2024` |

> 📝 **TODO:** As MISP events accumulate, tag each with its corresponding ATT&CK Navigator layer so enrichment output feeds directly into detection-coverage tracking.

---

## 🛠️ Troubleshooting

<details>
<summary>❓ MISP Connection Issues</summary>

Check that the web server is running and reachable.

```bash
sudo systemctl status apache2
curl -I http://localhost
```
</details>

<details>
<summary>❓ Python Dependency Errors</summary>

Reinstall the affected packages inside the virtual environment.

```bash
source misp-langchain-env/bin/activate
pip install --force-reinstall pymisp langchain
```
</details>

<details>
<summary>❓ Permission Issues on <code>/var/www/html/MISP</code></summary>

```bash
sudo chown -R www-data:www-data /var/www/html/MISP
sudo chmod -R 755 /var/www/html/MISP
```
</details>

<details>
<summary>❓ <code>PyMISP</code> raises an authentication error on every request</summary>

`MISP_CONFIG['key']` in `misp_config.py` is still the placeholder value. Generate a real API key from the MISP web UI (**Global Actions → My Profile → Auth keys**) and update the config.

```bash
nano misp_config.py
# Replace 'your-misp-api-key-here' with the generated key
```
</details>

<details>
<summary>❓ <code>run_analysis.py</code> reports 0 files processed</summary>

The pipeline globs `intel_feeds/*.txt` from the current working directory. Confirm the feed files exist and you're running from the correct directory.

```bash
cd /home/ubuntu
ls intel_feeds/*.txt
```
</details>

---

## 🏁 Conclusion

You have successfully implemented an AI-powered threat intelligence enrichment system using LangChain and MISP. This lab demonstrated:

- **MISP Integration:** Set up a complete threat intelligence platform for IOC management
- **AI-Powered Analysis:** Used LangChain to automate the extraction and enrichment of indicators from raw intelligence feeds
- **Actionable Intelligence:** Created automated workflows that transform raw threat data into structured, actionable intelligence
- **Comprehensive Reporting:** Built analysis capabilities that provide security teams with prioritized threat assessments

### 🏆 Key Accomplishments
- ✅ Stood up a self-hosted MISP instance with MySQL and Redis backing services
- ✅ Built a regex-driven multi-type IOC extractor (IPs, domains, URLs, hashes, emails)
- ✅ Automated MISP event creation directly from extracted IOCs
- ✅ Generated prioritized, human-readable threat intelligence reports
- ✅ Ran a batch pipeline across multiple intel feeds with combined CSV export

### 🌍 Real-World Applications
- 📌 Automating first-pass triage of incoming threat intel reports and vendor advisories
- 📌 Reducing analyst time spent manually copy-pasting IOCs into a TIP
- 📌 Standardizing IOC sharing across teams via MISP events and attributes
- 📌 Feeding enriched, prioritized indicators directly into SIEM/EDR blocklists
- 📌 Scaling threat intelligence processing as feed volume grows

This system enables security teams to process large volumes of threat intelligence automatically, identify known threats quickly, and focus their efforts on the most critical security indicators. The integration of AI with established threat intelligence platforms represents a significant advancement in cybersecurity automation and threat detection capabilities.

---

<div align="center">

### 🎓 Al Nafi — Practical Cybersecurity Training

![Al Nafi](https://img.shields.io/badge/Al_Nafi-Cybersecurity_Training-1976D2?style=for-the-badge)

</div>
