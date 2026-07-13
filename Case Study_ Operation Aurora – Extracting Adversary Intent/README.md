<div align="center">

# 🕵️ Case Study: Operation Aurora – Extracting Adversary Intent

### APT Analysis · Diamond Model Framework · Indicator Extraction

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-Shell_Scripting-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![YARA](https://img.shields.io/badge/YARA-Malware_Detection-CC0000?style=for-the-badge&logo=yara&logoColor=white)
![Regex](https://img.shields.io/badge/Regex-IOC_Extraction-FF6F00?style=for-the-badge)
![JSON](https://img.shields.io/badge/JSON-Data_Format-000000?style=for-the-badge&logo=json&logoColor=white)
![Diamond Model](https://img.shields.io/badge/Framework-Diamond_Model-8A2BE2?style=for-the-badge&logo=shieldsdotio&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-orange?style=for-the-badge)
![Duration](https://img.shields.io/badge/Duration-~2_Hours-informational?style=for-the-badge)

</div>

---

## 📖 Overview

This lab is a hands-on case study of **Operation Aurora**, the 2009–2010 state-sponsored espionage campaign against Google, Adobe, and other major technology firms. You'll build a full analysis pipeline in Python — parsing case data for intent signals, extracting and validating technical IOCs, generating a YARA detection rule, and mapping the entire campaign onto the **Diamond Model of Intrusion Analysis** to understand how adversary, infrastructure, capability, and victim relate.

---

## 📑 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [✅ Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🧩 Task 1: Review the Operation Aurora Case](#-task-1-review-the-operation-aurora-case)
- [🔎 Task 2: Extract Key Indicators of Adversary Intent](#-task-2-extract-key-indicators-of-adversary-intent)
- [💎 Task 3: Map Adversary Goals and Capabilities Using the Diamond Model](#-task-3-map-adversary-goals-and-capabilities-using-the-diamond-model)
- [🔍 Lab Verification](#-lab-verification)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

By completing this lab, you will:

| # | Objective |
|---|-----------|
| 1 | 🧠 Analyze the Operation Aurora cyber attack to understand adversary tactics and motivations |
| 2 | 🔎 Extract key indicators of adversary intent from real-world attack data |
| 3 | 💎 Apply the Diamond Model framework to map adversary goals and capabilities |
| 4 | 🛠️ Develop skills in threat intelligence analysis using open-source tools |

---

## ✅ Prerequisites

| Requirement | Details |
|-------------|---------|
| 🔐 Cybersecurity Concepts | Basic understanding of core concepts |
| 🐧 Linux CLI | Familiarity with the Linux command line |
| 🌐 Network Protocols | Knowledge of network protocols and web technologies |
| 🧠 Threat Intelligence | Understanding of threat intelligence fundamentals |

---

## 🖥️ Lab Environment

> 💡 **Al Nafi provides Linux-based cloud machines for this lab.** Simply click **Start Lab** to access your dedicated environment. The provided Linux machine is bare metal with no pre-installed tools — you will install every required tool yourself during the lab exercises.

---

## 🧩 Task 1: Review the Operation Aurora Case

### 🔧 Subtask 1.1: Set Up Analysis Environment

```bash
# 🔄 Update system packages
sudo apt update && sudo apt upgrade -y

# 📦 Install essential tools
sudo apt install -y curl wget git python3 python3-pip jq tree

# 🧬 Install YARA for malware analysis
sudo apt install -y yara

# 📂 Create working directory
mkdir ~/aurora_analysis
cd ~/aurora_analysis
```

### 📥 Subtask 1.2: Gather Operation Aurora Intelligence

```bash
# 🗂️ Create directory structure
mkdir -p {reports,indicators,timeline,analysis}

# 📄 Download Operation Aurora technical reports (simulated data)
cat > reports/aurora_summary.txt << 'EOF'
OPERATION AURORA - CASE STUDY SUMMARY
=====================================

Timeline: December 2009 - January 2010
Primary Targets: Google, Adobe, Yahoo, Symantec, Northrop Grumman
Attack Vector: Spear-phishing emails with malicious attachments
Malware: Hydraq/Aurora trojan
Attribution: Advanced Persistent Threat (APT1/Comment Crew)

Key Attack Phases:
1. Initial Compromise: Spear-phishing emails to employees
2. Exploitation: Internet Explorer zero-day vulnerability (CVE-2010-0249)
3. Installation: Hydraq backdoor deployment
4. Command & Control: Communication with attacker infrastructure
5. Data Exfiltration: Intellectual property and source code theft

Primary Objectives:
- Steal intellectual property
- Access Gmail accounts of Chinese human rights activists
- Compromise corporate networks for long-term access
EOF

# 🎯 Create indicators file
cat > indicators/iocs.txt << 'EOF'
# Operation Aurora Indicators of Compromise

## Domains
ratteam.net
trendmicr0.com
micr0s0ft-update.com

## IP Addresses
209.191.93.52
74.86.118.23
98.126.158.42

## File Hashes (MD5)
4cfe5b89c8e21a4c0b0d0f2e8a3b7c9d
7f8e9a1b2c3d4e5f6789abcdef012345
a1b2c3d4e5f6789012345678901234ab

## Registry Keys
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\GoogleUpdate
HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl

## File Paths
%TEMP%\GoogleUpdate.exe
%APPDATA%\Adobe\update.exe
C:\Windows\system32\drivers\etc\hosts
EOF
```

> 📝 **TODO:** Swap this simulated case data for a real vendor writeup (e.g. McAfee's original Hydraq analysis) if you want to practice on primary-source reporting.

### 🗓️ Subtask 1.3: Create Attack Timeline

```bash
# ⏱️ Generate a detailed timeline of Operation Aurora
cat > timeline/aurora_timeline.txt << 'EOF'
OPERATION AURORA TIMELINE
========================

2009-12-15: Initial spear-phishing campaign begins
2009-12-16: First successful compromise at target organization
2009-12-17: Hydraq malware deployed on compromised systems
2009-12-20: C2 communication established with attacker infrastructure
2009-12-25: Lateral movement within corporate networks
2010-01-02: Data exfiltration activities detected
2010-01-12: Google publicly announces the attack
2010-01-14: Additional companies confirm compromise
2010-01-21: Microsoft releases emergency patch for IE vulnerability
2010-02-01: Attribution analysis points to Chinese APT group
EOF
```

---

## 🔎 Task 2: Extract Key Indicators of Adversary Intent

### 🧠 Subtask 2.1: Analyze Attack Patterns

```python
#!/usr/bin/env python3
# 📄 analysis/intent_analyzer.py — keyword-driven adversary intent scoring

import json
import re
from datetime import datetime

class IntentAnalyzer:
    def __init__(self):
        # 🏷️ Keyword banks per intent category
        self.intent_indicators = {
            'espionage': ['intellectual property', 'source code', 'gmail accounts', 'human rights'],
            'persistence': ['backdoor', 'long-term access', 'lateral movement'],
            'stealth': ['zero-day', 'spear-phishing', 'targeted'],
            'attribution_masking': ['legitimate domains', 'typosquatting', 'infrastructure']
        }
        # TODO: Extend these keyword banks with terms specific to the campaign you're analyzing

    def analyze_text(self, text):
        # 🔍 Score each intent category by keyword hits
        results = {}
        text_lower = text.lower()

        for intent_type, keywords in self.intent_indicators.items():
            matches = []
            for keyword in keywords:
                if keyword in text_lower:
                    matches.append(keyword)

            if matches:
                results[intent_type] = {
                    'confidence': len(matches) / len(keywords),
                    'indicators': matches
                }

        return results

    def generate_report(self, analysis_results):
        # 📊 Console summary of intent confidence
        print("ADVERSARY INTENT ANALYSIS")
        print("=" * 25)

        for intent_type, data in analysis_results.items():
            confidence_pct = int(data['confidence'] * 100)
            print(f"\n{intent_type.upper()}: {confidence_pct}% confidence")
            print(f"Indicators: {', '.join(data['indicators'])}")

if __name__ == "__main__":
    analyzer = IntentAnalyzer()

    # 📥 Read case study data
    with open('../reports/aurora_summary.txt', 'r') as f:
        case_data = f.read()

    # 🧮 Analyze intent
    results = analyzer.analyze_text(case_data)
    analyzer.generate_report(results)
```

```bash
# ✅ Make script executable and run analysis
chmod +x analysis/intent_analyzer.py
python3 analysis/intent_analyzer.py
```

### 🧬 Subtask 2.2: Extract Technical Indicators

```python
#!/usr/bin/env python3
# 📄 analysis/ioc_extractor.py — regex-based IOC extraction and YARA rule generation

import re
import json

class IOCExtractor:
    def __init__(self):
        # 🎯 Regex patterns per IOC type
        self.patterns = {
            'domains': r'[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})',
            'ips': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'md5_hashes': r'\b[a-fA-F0-9]{32}\b',
            'registry_keys': r'HK[A-Z_]+\\[\\a-zA-Z0-9_\s]+',
            'file_paths': r'[A-Za-z]:\\[\\a-zA-Z0-9_\s\.%]+|%[A-Z]+%\\[\\a-zA-Z0-9_\s\.]+'
        }

    def extract_iocs(self, text):
        # 🔎 Run every pattern and de-duplicate hits
        iocs = {}

        for ioc_type, pattern in self.patterns.items():
            matches = re.findall(pattern, text)
            if ioc_type == 'domains':
                # 🧹 Filter out common false positives
                matches = [match[0] + '.' + match[1] if isinstance(match, tuple) else match
                          for match in matches]
                matches = [m for m in matches if not m.endswith(('.txt', '.py', '.exe'))]

            iocs[ioc_type] = list(set(matches)) if matches else []

        return iocs

    def generate_yara_rule(self, iocs):
        # 🧪 Build a detection rule from extracted domains/hashes
        rule = '''rule Operation_Aurora_Indicators {
    meta:
        description = "Operation Aurora IOCs"
        author = "Threat Intelligence Team"
        date = "2024-01-01"

    strings:'''

        for i, domain in enumerate(iocs.get('domains', [])[:5]):
            rule += f'\n        $domain{i} = "{domain}" nocase'

        for i, hash_val in enumerate(iocs.get('md5_hashes', [])[:3]):
            rule += f'\n        $hash{i} = "{hash_val}" nocase'

        rule += '''

    condition:
        any of them
}'''
        return rule

if __name__ == "__main__":
    extractor = IOCExtractor()

    # 📥 Read IOC data
    with open('../indicators/iocs.txt', 'r') as f:
        ioc_data = f.read()

    # 🎯 Extract IOCs
    extracted_iocs = extractor.extract_iocs(ioc_data)

    print("EXTRACTED INDICATORS OF COMPROMISE")
    print("=" * 35)

    for ioc_type, indicators in extracted_iocs.items():
        if indicators:
            print(f"\n{ioc_type.upper()}:")
            for indicator in indicators:
                print(f"  - {indicator}")

    # 🧬 Generate YARA rule
    yara_rule = extractor.generate_yara_rule(extracted_iocs)

    with open('../analysis/aurora_detection.yar', 'w') as f:
        f.write(yara_rule)

    print(f"\nYARA rule generated: ../analysis/aurora_detection.yar")
```

```bash
# ▶️ Run IOC extraction
python3 analysis/ioc_extractor.py
```

> 📝 **TODO:** Tune the regex patterns to reduce false positives before pointing this extractor at a live threat report.

---

## 💎 Task 3: Map Adversary Goals and Capabilities Using the Diamond Model

### 🏗️ Subtask 3.1: Implement Diamond Model Analysis

```python
#!/usr/bin/env python3
# 📄 analysis/diamond_model.py — populates and exports the four Diamond Model vertices

import json
from datetime import datetime

class DiamondModel:
    def __init__(self):
        # 💎 Four core vertices of the Diamond Model
        self.model = {
            'adversary': {},
            'infrastructure': {},
            'capability': {},
            'victim': {}
        }

    def add_adversary_data(self, name, motivation, sophistication, attribution):
        self.model['adversary'] = {
            'name': name,
            'motivation': motivation,
            'sophistication': sophistication,
            'attribution_confidence': attribution,
            'tactics': []
        }

    def add_infrastructure_data(self, domains, ips, hosting_providers):
        self.model['infrastructure'] = {
            'domains': domains,
            'ip_addresses': ips,
            'hosting_providers': hosting_providers,
            'infrastructure_type': 'Command and Control'
        }

    def add_capability_data(self, malware, exploits, techniques):
        self.model['capability'] = {
            'malware_families': malware,
            'exploits': exploits,
            'attack_techniques': techniques,
            'sophistication_level': 'Advanced'
        }

    def add_victim_data(self, organizations, sectors, geographic_regions):
        self.model['victim'] = {
            'target_organizations': organizations,
            'target_sectors': sectors,
            'geographic_regions': geographic_regions,
            'victim_selection': 'Targeted'
        }

    def analyze_relationships(self):
        # 🔗 Edges connecting the four vertices
        relationships = {
            'adversary_infrastructure': 'Uses compromised and attacker-controlled infrastructure',
            'adversary_capability': 'Deploys sophisticated malware and zero-day exploits',
            'adversary_victim': 'Targets specific organizations for espionage purposes',
            'infrastructure_capability': 'Hosts malware and facilitates C2 communications',
            'infrastructure_victim': 'Delivers malicious payloads to victim networks',
            'capability_victim': 'Exploits victim vulnerabilities for persistent access'
        }
        return relationships

    def generate_report(self):
        print("DIAMOND MODEL ANALYSIS - OPERATION AURORA")
        print("=" * 45)

        for vertex, data in self.model.items():
            print(f"\n{vertex.upper()} VERTEX:")
            print("-" * 20)
            for key, value in data.items():
                if isinstance(value, list):
                    print(f"{key}: {', '.join(value)}")
                else:
                    print(f"{key}: {value}")

        print("\nRELATIONSHIP ANALYSIS:")
        print("-" * 22)
        relationships = self.analyze_relationships()
        for rel_type, description in relationships.items():
            print(f"{rel_type}: {description}")

    def export_json(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.model, f, indent=2)
        print(f"\nDiamond Model exported to: {filename}")

if __name__ == "__main__":
    # 💎 Initialize Diamond Model
    diamond = DiamondModel()

    # 🧑‍💻 Populate Aurora data
    diamond.add_adversary_data(
        name="APT1/Comment Crew",
        motivation=["Espionage", "Intellectual Property Theft", "Political Intelligence"],
        sophistication="Advanced Persistent Threat",
        attribution="High Confidence - Chinese State-Sponsored"
    )

    diamond.add_infrastructure_data(
        domains=["ratteam.net", "trendmicr0.com", "micr0s0ft-update.com"],
        ips=["209.191.93.52", "74.86.118.23", "98.126.158.42"],
        hosting_providers=["Various bulletproof hosting services"]
    )

    diamond.add_capability_data(
        malware=["Hydraq/Aurora Trojan"],
        exploits=["CVE-2010-0249 (Internet Explorer Zero-day)"],
        techniques=["Spear-phishing", "Watering Hole", "Lateral Movement", "Data Exfiltration"]
    )

    diamond.add_victim_data(
        organizations=["Google", "Adobe", "Yahoo", "Symantec", "Northrop Grumman"],
        sectors=["Technology", "Defense", "Software Development"],
        geographic_regions=["United States", "Global Technology Companies"]
    )

    # 📊 Generate analysis report
    diamond.generate_report()

    # 💾 Export to JSON
    diamond.export_json('../analysis/aurora_diamond_model.json')
```

```bash
# ▶️ Run Diamond Model analysis
python3 analysis/diamond_model.py
```

### 🎨 Subtask 3.2: Create Visual Mapping

```python
#!/usr/bin/env python3
# 📄 analysis/diamond_visualizer.py — ASCII visualization of the four-vertex model

def create_diamond_visualization():
    visualization = '''
OPERATION AURORA - DIAMOND MODEL VISUALIZATION
==============================================

                    ADVERSARY
                 ┌─────────────────┐
                 │   APT1/Comment  │
                 │      Crew       │
                 │                 │
                 │ • State-sponsored│
                 │ • Espionage     │
                 │ • Advanced      │
                 └─────────────────┘
                          │
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│INFRASTRUCTURE│    │ CAPABILITY  │    │   VICTIM    │
│             │    │             │    │             │
│• C2 Domains │    │• Hydraq     │    │• Google     │
│• Bulletproof│    │• Zero-day   │    │• Adobe      │
│  Hosting    │    │• Spear-     │    │• Yahoo      │
│• Typosquat  │    │  phishing   │    │• Tech Sector│
│  Domains    │    │• Lateral    │    │• US-based   │
│             │    │  Movement   │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
        │                 │                 │
        └─────────────────┼─────────────────┘
                          │
                    RELATIONSHIPS
                 ┌─────────────────┐
                 │ • Targeted      │
                 │ • Persistent    │
                 │ • Sophisticated │
                 │ • State-nexus   │
                 └─────────────────┘

KEY INSIGHTS:
============
1. State-sponsored adversary with clear espionage objectives
2. Sophisticated capability set including zero-day exploits
3. Targeted victim selection in technology and defense sectors
4. Professional infrastructure management and operational security
5. Long-term persistent access goals rather than quick financial gain
'''
    return visualization

if __name__ == "__main__":
    print(create_diamond_visualization())

    # 💾 Save visualization to file
    with open('../analysis/diamond_visualization.txt', 'w') as f:
        f.write(create_diamond_visualization())

    print("Visualization saved to: ../analysis/diamond_visualization.txt")
```

```bash
# ▶️ Generate visualization
python3 analysis/diamond_visualizer.py
```

### 📋 Subtask 3.3: Generate Intelligence Summary

```python
#!/usr/bin/env python3
# 📄 analysis/intelligence_summary.py — executive-level assessment and recommendations

def generate_intelligence_summary():
    summary = {
        'executive_summary': '''
Operation Aurora represents a sophisticated state-sponsored cyber espionage campaign
targeting major technology companies and defense contractors. The attack demonstrates
advanced persistent threat capabilities with clear strategic objectives focused on
intellectual property theft and intelligence gathering.
        ''',

        'key_findings': [
            'Adversary demonstrated advanced capabilities including zero-day exploits',
            'Attack infrastructure showed professional operational security practices',
            'Victim selection was highly targeted and strategic',
            'Campaign objectives aligned with state-level intelligence requirements',
            'Long-term persistence was prioritized over immediate financial gain'
        ],

        'threat_assessment': {
            'sophistication': 'Advanced',
            'persistence': 'High',
            'stealth': 'High',
            'impact': 'Significant',
            'attribution_confidence': 'High'
        },

        'recommendations': [
            'Implement advanced email security to detect spear-phishing',
            'Deploy endpoint detection and response (EDR) solutions',
            'Conduct regular vulnerability assessments and patching',
            'Implement network segmentation and zero-trust architecture',
            'Enhance threat hunting capabilities for APT detection',
            'Develop incident response procedures for state-sponsored threats'
        ]
    }
    # TODO: Replace these findings/recommendations with conclusions drawn from your own analysis

    return summary

def print_summary(summary):
    print("OPERATION AURORA - INTELLIGENCE ASSESSMENT")
    print("=" * 45)

    print("\nEXECUTIVE SUMMARY:")
    print(summary['executive_summary'].strip())

    print("\nKEY FINDINGS:")
    for i, finding in enumerate(summary['key_findings'], 1):
        print(f"{i}. {finding}")

    print("\nTHREAT ASSESSMENT:")
    for metric, level in summary['threat_assessment'].items():
        print(f"  {metric.replace('_', ' ').title()}: {level}")

    print("\nRECOMMENDATIONS:")
    for i, rec in enumerate(summary['recommendations'], 1):
        print(f"{i}. {rec}")

if __name__ == "__main__":
    summary = generate_intelligence_summary()
    print_summary(summary)

    # 💾 Export summary
    import json
    with open('../analysis/intelligence_assessment.json', 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"\nIntelligence assessment exported to: ../analysis/intelligence_assessment.json")
```

```bash
# ▶️ Generate intelligence summary
python3 analysis/intelligence_summary.py
```

---

## 🔍 Lab Verification

```bash
# 🌳 Check generated files
echo "Generated Analysis Files:"
echo "========================"
tree ~/aurora_analysis/

# 🧪 Validate YARA rule syntax
echo -e "\nValidating YARA rule:"
yara ~/aurora_analysis/analysis/aurora_detection.yar ~/aurora_analysis/indicators/iocs.txt

# 📂 Display final directory structure
echo -e "\nFinal Lab Structure:"
ls -la ~/aurora_analysis/analysis/
```

---

## 🗺️ MITRE ATT&CK Mapping

Operation Aurora's attack phases map cleanly onto the following ATT&CK tactics and techniques:

| Attack Phase | ATT&CK Tactic | Technique | Detail |
|---|---|---|---|
| ✉️ Initial Compromise | Initial Access | T1566.001 (Spearphishing Attachment) | Malicious attachments sent to targeted employees |
| 💥 Exploitation | Execution | T1203 (Exploitation for Client Execution) | CVE-2010-0249 Internet Explorer zero-day |
| 🚪 Installation | Persistence | T1547.001 (Registry Run Keys) | Hydraq backdoor installed via `GoogleUpdate` run key |
| 📡 Command & Control | Command and Control | T1071 (Application Layer Protocol) | Beaconing to attacker-controlled domains/IPs |
| ↔️ Lateral Movement | Lateral Movement | T1021 (Remote Services) | Movement across compromised corporate networks |
| 📤 Data Exfiltration | Exfiltration | T1041 (Exfiltration Over C2 Channel) | Intellectual property and source code theft |

> 📝 **TODO:** Cross-reference this mapping against the current ATT&CK Navigator layer for APT groups tracked as related to this campaign (e.g. APT17/Comment Crew associations).

---

## 🛠️ Troubleshooting

<details>
<summary>❓ <code>yara: command not found</code></summary>

The YARA package didn't install correctly, or the binary isn't on `PATH`.

```bash
sudo apt update
sudo apt install -y yara
yara --version
```
</details>

<details>
<summary>❓ IOC extractor returns an empty <code>domains</code> list</summary>

The domain regex captures matches as tuples; make sure you're running the script from inside the `analysis/` directory so relative paths (`../indicators/iocs.txt`) resolve correctly.

```bash
cd ~/aurora_analysis/analysis
python3 ioc_extractor.py
```
</details>

<details>
<summary>❓ <code>yara aurora_detection.yar iocs.txt</code> reports a syntax error</summary>

This usually means a generated string value contains an unescaped quote or backslash. Inspect the generated rule before scanning:

```bash
cat analysis/aurora_detection.yar
```

Regenerate it after fixing the source IOC file if needed.
</details>

<details>
<summary>❓ <code>FileNotFoundError</code> when running any <code>analysis/*.py</code> script</summary>

Every analysis script uses relative paths (`../reports/...`, `../indicators/...`) and expects to be run from inside `~/aurora_analysis/analysis`. Run scripts in order from the correct directory:

```bash
cd ~/aurora_analysis
python3 analysis/intent_analyzer.py
python3 analysis/ioc_extractor.py
python3 analysis/diamond_model.py
python3 analysis/diamond_visualizer.py
python3 analysis/intelligence_summary.py
```
</details>

<details>
<summary>❓ <code>tree: command not found</code></summary>

`tree` isn't installed by default on minimal images.

```bash
sudo apt install -y tree
```
</details>

---

## 🏁 Conclusion

In this lab, you analyzed **Operation Aurora**, one of the most significant cyber espionage campaigns in history. You extracted key indicators of adversary intent, mapped the attack using the Diamond Model framework, and generated actionable threat intelligence.

### 🏆 Key Accomplishments
- ✅ Analyzed real-world APT campaign data to understand adversary motivations
- ✅ Extracted and categorized technical indicators of compromise
- ✅ Generated a working YARA detection rule from extracted IOCs
- ✅ Applied the Diamond Model to map relationships between adversary, infrastructure, capability, and victim
- ✅ Produced intelligence assessments and defensive recommendations

### 🌍 Real-World Applications
- 📌 Structuring APT case studies for internal threat intelligence briefings
- 📌 Building repeatable IOC-extraction pipelines from vendor threat reports
- 📌 Using the Diamond Model to drive pivoting during incident response
- 📌 Translating campaign analysis into concrete detection content (YARA, Sigma)
- 📌 Informing executive risk conversations with structured threat assessments

> 💡 **Why This Matters:** Understanding adversary intent is crucial for effective cybersecurity defense. By analyzing campaigns like Operation Aurora, security professionals can better prepare for similar threats, develop appropriate countermeasures, and make informed decisions about security investments and priorities. These skills translate directly to threat intelligence analysis, incident response, and strategic security planning in enterprise environments.

---

<div align="center">

### 🎓 Al Nafi — Practical Cybersecurity Training

![Al Nafi](https://img.shields.io/badge/Al_Nafi-Cybersecurity_Training-1976D2?style=for-the-badge)

</div>
