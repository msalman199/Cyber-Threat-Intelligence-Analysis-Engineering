<div align="center">

# 💎 Conduct Structured Requirement Planning with Diamond Model

### Diamond Model of Intrusion Analysis · Gap Identification · Collection Prioritization

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-Shell_Scripting-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-Data_Analysis-150458?style=for-the-badge&logo=pandas&logoColor=white)
![Matplotlib](https://img.shields.io/badge/Matplotlib-Visualization-11557C?style=for-the-badge&logo=plotly&logoColor=white)
![NetworkX](https://img.shields.io/badge/NetworkX-Graph_Analysis-3776AB?style=for-the-badge)
![Graphviz](https://img.shields.io/badge/Graphviz-Diagramming-2E8B57?style=for-the-badge)
![Diamond Model](https://img.shields.io/badge/Framework-Diamond_Model-8A2BE2?style=for-the-badge&logo=shieldsdotio&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-orange?style=for-the-badge)
![Duration](https://img.shields.io/badge/Duration-~3_Hours-informational?style=for-the-badge)

</div>

---

## 📖 Overview

This lab builds a reusable **Diamond Model of Intrusion Analysis** framework in Python and applies it end-to-end to a hypothetical financial-sector APT campaign. You'll model the four core elements — adversary, capability, infrastructure, and victim — build dedicated deep-dive analyses for each, systematically identify intelligence gaps, and consolidate everything into a prioritized collection-requirements report ready for threat intelligence consumers.

---

## 📑 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [✅ Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [⚙️ Task 1: Environment Setup](#️-task-1-environment-setup)
- [💎 Task 2: Create Diamond Model Framework](#-task-2-create-diamond-model-framework)
- [🕵️ Task 3: Map Adversary Characteristics](#️-task-3-map-adversary-characteristics)
- [🧰 Task 4: Analyze Capability and Infrastructure](#-task-4-analyze-capability-and-infrastructure)
- [🎯 Task 5: Victim Analysis and Intelligence Gaps](#-task-5-victim-analysis-and-intelligence-gaps)
- [📊 Task 6: Generate Comprehensive Diamond Model Report](#-task-6-generate-comprehensive-diamond-model-report)
- [🔍 Task 7: Verification and Review](#-task-7-verification-and-review)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

By completing this lab, you will:

| # | Objective |
|---|-----------|
| 1 | 💎 Apply the Diamond Model framework to structure threat intelligence requirements |
| 2 | 🗺️ Map adversary characteristics across the four core elements: adversary, capability, infrastructure, and victim |
| 3 | 🔍 Identify intelligence gaps and prioritize collection requirements |
| 4 | 📄 Create actionable threat intelligence documentation using open-source tools |

---

## ✅ Prerequisites

| Requirement | Details |
|-------------|---------|
| 🔐 Cybersecurity Concepts | Basic understanding of core concepts |
| 🐧 Linux CLI | Familiarity with the Linux command line |
| 🧠 Threat Intelligence | Knowledge of threat intelligence fundamentals |
| ⚔️ Attack Methodologies | Understanding of attack methodologies |

---

## 🖥️ Lab Environment

> 💡 **Al Nafi provides a Linux-based cloud machine for this lab.** Click **Start Lab** to access your environment. The machine is bare metal with no pre-installed tools — you will install every required tool yourself during the lab.

---

## ⚙️ Task 1: Environment Setup

### 📦 Subtask 1.1: Install Required Packages

```bash
# 🔄 Update system packages
sudo apt update && sudo apt upgrade -y

# 🧰 Install essential tools
sudo apt install -y curl wget git python3 python3-pip vim tree

# 🐍 Install Python libraries for data analysis
pip3 install pandas matplotlib networkx graphviz
```

### 📁 Subtask 1.2: Create Lab Directory Structure

```bash
# 📂 Create working directory
mkdir -p ~/diamond-model-lab/{data,templates,analysis,reports}
cd ~/diamond-model-lab

# 🗂️ Create subdirectories
mkdir -p data/{raw,processed} templates analysis/{adversary,capability,infrastructure,victim} reports
```

---

## 💎 Task 2: Create Diamond Model Framework

### 🏗️ Subtask 2.1: Build Diamond Model Template

```python
#!/usr/bin/env python3
# 📄 templates/diamond_model_template.py — reusable Diamond Model class
"""
Diamond Model Framework for Threat Intelligence Analysis
"""

class DiamondModel:
    def __init__(self, incident_name):
        self.incident_name = incident_name
        self.adversary = {}
        self.capability = {}
        self.infrastructure = {}
        self.victim = {}
        self.meta_features = {}

    def set_adversary(self, **kwargs):
        self.adversary.update(kwargs)

    def set_capability(self, **kwargs):
        self.capability.update(kwargs)

    def set_infrastructure(self, **kwargs):
        self.infrastructure.update(kwargs)

    def set_victim(self, **kwargs):
        self.victim.update(kwargs)

    def set_meta_features(self, **kwargs):
        self.meta_features.update(kwargs)

    def generate_report(self):
        # 📄 Render all four vertices plus meta-features
        report = f"""
DIAMOND MODEL ANALYSIS: {self.incident_name}
{'='*50}

ADVERSARY:
{self._format_dict(self.adversary)}

CAPABILITY:
{self._format_dict(self.capability)}

INFRASTRUCTURE:
{self._format_dict(self.infrastructure)}

VICTIM:
{self._format_dict(self.victim)}

META-FEATURES:
{self._format_dict(self.meta_features)}
        """
        return report

    def _format_dict(self, data):
        if not data:
            return "  [No data available]"
        return '\n'.join([f"  {k}: {v}" for k, v in data.items()])

    def identify_gaps(self):
        # 🕳️ Flag missing vertices and missing required fields per vertex
        gaps = []
        elements = {
            'Adversary': self.adversary,
            'Capability': self.capability,
            'Infrastructure': self.infrastructure,
            'Victim': self.victim
        }

        for element, data in elements.items():
            if not data:
                gaps.append(f"{element}: Complete data missing")
            else:
                required_fields = self._get_required_fields(element)
                missing = [field for field in required_fields if field not in data]
                if missing:
                    gaps.append(f"{element}: Missing {', '.join(missing)}")

        return gaps

    def _get_required_fields(self, element):
        # 📋 Minimum expected fields per vertex
        field_map = {
            'Adversary': ['identity', 'motivation', 'sophistication'],
            'Capability': ['attack_vector', 'tools', 'techniques'],
            'Infrastructure': ['ip_addresses', 'domains', 'hosting'],
            'Victim': ['industry', 'geography', 'size']
        }
        return field_map.get(element, [])
```

```bash
# ✅ Make script executable
chmod +x templates/diamond_model_template.py
```

> 📝 **TODO:** Extend `_get_required_fields()` with any additional fields your organization's CTI program considers mandatory.

### 🧪 Subtask 2.2: Create Analysis Script

```python
#!/usr/bin/env python3
# 📄 analysis/diamond_analysis.py — applies the framework to a hypothetical APT campaign
import sys
import os
sys.path.append('../templates')
from diamond_model_template import DiamondModel

def analyze_apt_campaign():
    # 💎 Create Diamond Model instance for hypothetical APT campaign
    apt_campaign = DiamondModel("APT-Finance-2024")

    # 🕵️ Populate Adversary information
    apt_campaign.set_adversary(
        identity="Unknown APT Group",
        motivation="Financial gain",
        sophistication="High",
        attribution_confidence="Medium",
        suspected_origin="Eastern Europe",
        operational_pattern="Persistent, targeted attacks"
    )

    # 🧰 Populate Capability information
    apt_campaign.set_capability(
        attack_vector="Spear phishing emails",
        tools=["Custom RAT", "Mimikatz", "PowerShell scripts"],
        techniques=["T1566.001 - Spearphishing Attachment", "T1003 - Credential Dumping"],
        malware_family="Custom banking trojan",
        persistence_method="Registry modification",
        evasion_techniques="Process hollowing, DLL sideloading"
    )

    # 🌐 Populate Infrastructure information
    apt_campaign.set_infrastructure(
        ip_addresses=["192.168.1.100", "10.0.0.50"],
        domains=["fake-bank-update.com", "secure-finance.net"],
        hosting="Bulletproof hosting services",
        c2_protocol="HTTPS",
        registration_pattern="Privacy-protected domains",
        infrastructure_reuse="High - domains used across multiple campaigns"
    )

    # 🎯 Populate Victim information
    apt_campaign.set_victim(
        industry="Financial services",
        geography="North America, Western Europe",
        size="Medium to large enterprises",
        target_selection="High-value financial institutions",
        victim_count="15+ confirmed",
        impact_assessment="Data theft, financial fraud"
    )

    # 🧭 Set meta-features
    apt_campaign.set_meta_features(
        timestamp="2024-01-15 to ongoing",
        phase="Ongoing campaign",
        result="Successful data exfiltration",
        direction="Adversary to Victim",
        methodology="Targeted attacks",
        resources="Well-funded operation"
    )

    return apt_campaign

if __name__ == "__main__":
    campaign = analyze_apt_campaign()
    print(campaign.generate_report())

    print("\nINTELLIGENCE GAPS IDENTIFIED:")
    print("="*40)
    gaps = campaign.identify_gaps()
    if gaps:
        for gap in gaps:
            print(f"- {gap}")
    else:
        print("- No critical gaps identified")
```

```bash
# ✅ Make script executable
chmod +x analysis/diamond_analysis.py
```

> 📝 **TODO:** Replace the hypothetical `APT-Finance-2024` details with data from a real case you're tracking.

---

## 🕵️ Task 3: Map Adversary Characteristics

### 🧬 Subtask 3.1: Detailed Adversary Analysis

```python
#!/usr/bin/env python3
# 📄 analysis/adversary/adversary_profile.py — identity, motivation, capability, and intent deep-dive

def create_adversary_profile():
    profile = {
        "Identity Analysis": {
            "known_aliases": ["APT-Finance", "BankingThreat", "MoneyHunter"],
            "attribution_indicators": [
                "Code similarities with previous campaigns",
                "Infrastructure overlap",
                "Operational timing patterns"
            ],
            "confidence_level": "Medium (60%)"
        },

        "Motivation Assessment": {
            "primary_motivation": "Financial gain",
            "secondary_motivations": ["Intelligence gathering", "Reputation"],
            "evidence": [
                "Targeting of financial institutions",
                "Focus on payment systems",
                "Monetization of stolen data"
            ]
        },

        "Capability Assessment": {
            "sophistication_level": "High",
            "technical_skills": [
                "Custom malware development",
                "Advanced evasion techniques",
                "Social engineering expertise"
            ],
            "operational_security": "High - minimal attribution artifacts"
        },

        "Intent Analysis": {
            "strategic_objectives": [
                "Long-term access to financial networks",
                "Systematic data harvesting",
                "Establishment of persistent presence"
            ],
            "tactical_goals": [
                "Credential harvesting",
                "Lateral movement",
                "Data exfiltration"
            ]
        }
    }

    return profile

def generate_adversary_report(profile):
    # 📄 Render the profile as a readable text report
    report = "ADVERSARY PROFILE ANALYSIS\n"
    report += "="*50 + "\n\n"

    for section, data in profile.items():
        report += f"{section.upper()}:\n"
        report += "-" * len(section) + "\n"

        for key, value in data.items():
            if isinstance(value, list):
                report += f"{key}:\n"
                for item in value:
                    report += f"  • {item}\n"
            else:
                report += f"{key}: {value}\n"
        report += "\n"

    return report

if __name__ == "__main__":
    profile = create_adversary_profile()
    report = generate_adversary_report(profile)
    print(report)

    # 💾 Save to file
    with open("../../reports/adversary_profile.txt", "w") as f:
        f.write(report)
```

```bash
# ✅ Make script executable
chmod +x analysis/adversary/adversary_profile.py
```

### ▶️ Subtask 3.2: Execute Adversary Analysis

```bash
cd analysis/adversary
python3 adversary_profile.py
cd ../..
```

---

## 🧰 Task 4: Analyze Capability and Infrastructure

### 🗺️ Subtask 4.1: Capability Mapping

```python
#!/usr/bin/env python3
# 📄 analysis/capability/capability_mapping.py — TTP mapping and infrastructure breakdown

def map_attack_capabilities():
    # ⚔️ Kill-chain phase → techniques, tools, effectiveness, detection difficulty
    capabilities = {
        "Initial Access": {
            "techniques": ["T1566.001 - Spearphishing Attachment"],
            "tools": ["Custom phishing framework"],
            "effectiveness": "High",
            "detection_difficulty": "Medium"
        },

        "Execution": {
            "techniques": ["T1059.001 - PowerShell", "T1204.002 - Malicious File"],
            "tools": ["PowerShell scripts", "Custom droppers"],
            "effectiveness": "High",
            "detection_difficulty": "Low to Medium"
        },

        "Persistence": {
            "techniques": ["T1547.001 - Registry Run Keys"],
            "tools": ["Registry modification tools"],
            "effectiveness": "Medium",
            "detection_difficulty": "Medium"
        },

        "Credential Access": {
            "techniques": ["T1003 - OS Credential Dumping"],
            "tools": ["Mimikatz", "Custom credential harvesters"],
            "effectiveness": "High",
            "detection_difficulty": "Medium"
        },

        "Command and Control": {
            "techniques": ["T1071.001 - Web Protocols"],
            "tools": ["Custom C2 framework"],
            "effectiveness": "High",
            "detection_difficulty": "High"
        }
    }

    return capabilities

def analyze_infrastructure():
    # 🌐 C2, delivery, and OPSEC infrastructure breakdown
    infrastructure = {
        "Command and Control": {
            "domains": [
                "fake-bank-update.com",
                "secure-finance.net",
                "banking-security.org"
            ],
            "ip_addresses": [
                "192.168.1.100",
                "10.0.0.50",
                "172.16.0.25"
            ],
            "hosting_providers": [
                "BulletproofHost LLC",
                "Anonymous Hosting Services"
            ]
        },

        "Delivery Infrastructure": {
            "email_servers": ["mail.fake-bank.com"],
            "compromised_sites": ["legitimate-site1.com", "news-portal.net"],
            "cdn_services": ["CloudFlare (abused)"]
        },

        "Operational Security": {
            "domain_registration": "Privacy protected",
            "ssl_certificates": "Let's Encrypt (automated)",
            "infrastructure_rotation": "Every 30-45 days"
        }
    }

    return infrastructure

def generate_capability_report():
    capabilities = map_attack_capabilities()
    infrastructure = analyze_infrastructure()

    report = "CAPABILITY AND INFRASTRUCTURE ANALYSIS\n"
    report += "="*50 + "\n\n"

    report += "ATTACK CAPABILITIES:\n"
    report += "-"*20 + "\n"
    for phase, details in capabilities.items():
        report += f"\n{phase}:\n"
        for key, value in details.items():
            if isinstance(value, list):
                report += f"  {key}: {', '.join(value)}\n"
            else:
                report += f"  {key}: {value}\n"

    report += "\n\nINFRASTRUCTURE ANALYSIS:\n"
    report += "-"*25 + "\n"
    for category, details in infrastructure.items():
        report += f"\n{category}:\n"
        for key, value in details.items():
            if isinstance(value, list):
                report += f"  {key}:\n"
                for item in value:
                    report += f"    • {item}\n"
            else:
                report += f"  {key}: {value}\n"

    return report

if __name__ == "__main__":
    report = generate_capability_report()
    print(report)

    # 💾 Save to file
    with open("../../reports/capability_infrastructure.txt", "w") as f:
        f.write(report)
```

```bash
# ✅ Make script executable
chmod +x analysis/capability/capability_mapping.py
```

### ▶️ Subtask 4.2: Execute Capability Analysis

```bash
cd analysis/capability
python3 capability_mapping.py
cd ../..
```

---

## 🎯 Task 5: Victim Analysis and Intelligence Gaps

### 👥 Subtask 5.1: Victimology Assessment

```python
#!/usr/bin/env python3
# 📄 analysis/victim/victim_analysis.py — victim targeting patterns and prioritized gap list

def analyze_victim_patterns():
    victim_data = {
        "Target Selection Criteria": {
            "industry_focus": "Financial services",
            "geographic_distribution": ["North America", "Western Europe"],
            "organization_size": "Medium to large enterprises (500+ employees)",
            "revenue_threshold": "$100M+ annual revenue",
            "technology_stack": "Windows-based environments"
        },

        "Attack Patterns": {
            "initial_targeting": "C-level executives and finance personnel",
            "reconnaissance_methods": [
                "Social media profiling",
                "Public financial records research",
                "Employee directory harvesting"
            ],
            "timing_patterns": "Business hours in target timezone"
        },

        "Impact Assessment": {
            "confirmed_victims": 15,
            "suspected_victims": 8,
            "average_dwell_time": "120 days",
            "data_types_stolen": [
                "Customer financial records",
                "Internal financial documents",
                "Authentication credentials",
                "Business intelligence"
            ],
            "estimated_financial_impact": "$2.5M per victim (average)"
        },

        "Victim Response Patterns": {
            "detection_methods": [
                "Anomalous network traffic",
                "Suspicious email reports",
                "Third-party threat intelligence"
            ],
            "response_time": "72-96 hours average",
            "containment_effectiveness": "Moderate"
        }
    }

    return victim_data

def identify_intelligence_gaps():
    # 🕳️ Gaps bucketed by priority, plus concrete collection requirements
    gaps = {
        "Critical Gaps": [
            "Exact adversary identity and attribution",
            "Full scope of compromised organizations",
            "Complete malware functionality analysis",
            "Detailed C2 communication protocols"
        ],

        "High Priority Gaps": [
            "Future targeting intentions",
            "Additional infrastructure components",
            "Adversary operational timeline",
            "Monetization methods and partners"
        ],

        "Medium Priority Gaps": [
            "Historical campaign connections",
            "Adversary resource assessment",
            "Defensive countermeasure effectiveness",
            "Industry-specific attack variations"
        ],

        "Collection Requirements": [
            "Network traffic analysis from additional victims",
            "Malware sample collection and analysis",
            "Infrastructure monitoring and tracking",
            "Human intelligence on adversary operations"
        ]
    }

    return gaps

def generate_victim_gap_report():
    victim_data = analyze_victim_patterns()
    gaps = identify_intelligence_gaps()

    report = "VICTIM ANALYSIS AND INTELLIGENCE GAPS\n"
    report += "="*50 + "\n\n"

    report += "VICTIMOLOGY ASSESSMENT:\n"
    report += "-"*25 + "\n"
    for category, details in victim_data.items():
        report += f"\n{category}:\n"
        for key, value in details.items():
            if isinstance(value, list):
                report += f"  {key}:\n"
                for item in value:
                    report += f"    • {item}\n"
            else:
                report += f"  {key}: {value}\n"

    report += "\n\nINTELLIGENCE GAPS ANALYSIS:\n"
    report += "-"*30 + "\n"
    for priority, gap_list in gaps.items():
        report += f"\n{priority}:\n"
        for gap in gap_list:
            report += f"  • {gap}\n"

    return report

if __name__ == "__main__":
    report = generate_victim_gap_report()
    print(report)

    # 💾 Save to file
    with open("../../reports/victim_gaps_analysis.txt", "w") as f:
        f.write(report)
```

```bash
# ✅ Make script executable
chmod +x analysis/victim/victim_analysis.py
```

> 📝 **TODO:** Replace the simulated victim counts and financial-impact figures with data validated against your own case tracking.

### ▶️ Subtask 5.2: Execute Victim and Gap Analysis

```bash
cd analysis/victim
python3 victim_analysis.py
cd ../..
```

---

## 📊 Task 6: Generate Comprehensive Diamond Model Report

### 🧾 Subtask 6.1: Create Final Analysis

```bash
# ▶️ Execute main Diamond Model analysis
cd analysis
python3 diamond_analysis.py > ../reports/diamond_model_report.txt
cd ..
```

### 🧩 Subtask 6.2: Consolidate All Reports

```python
#!/usr/bin/env python3
# 📄 reports/comprehensive_analysis.py — merges all vertex reports into one final deliverable
import os
from datetime import datetime

def consolidate_reports():
    report_files = [
        "diamond_model_report.txt",
        "adversary_profile.txt",
        "capability_infrastructure.txt",
        "victim_gaps_analysis.txt"
    ]

    consolidated = f"""
COMPREHENSIVE DIAMOND MODEL THREAT INTELLIGENCE ANALYSIS
{'='*60}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

"""

    for report_file in report_files:
        if os.path.exists(report_file):
            with open(report_file, 'r') as f:
                consolidated += f"\n{f.read()}\n"
                consolidated += "\n" + "="*60 + "\n"

    # 📌 Add intelligence requirements summary
    consolidated += """
INTELLIGENCE COLLECTION PRIORITIES
==================================

IMMEDIATE REQUIREMENTS (0-30 days):
• Malware sample analysis and reverse engineering
• C2 infrastructure monitoring and takedown coordination
• Victim notification and impact assessment
• Defensive signature development

SHORT-TERM REQUIREMENTS (30-90 days):
• Attribution analysis and adversary profiling
• Campaign timeline reconstruction
• Additional victim identification
• Threat hunting rule development

LONG-TERM REQUIREMENTS (90+ days):
• Strategic adversary assessment
• Predictive analysis for future campaigns
• Industry threat landscape analysis
• Defensive capability gap assessment

RECOMMENDED ACTIONS:
• Implement network monitoring for identified IOCs
• Develop custom detection rules for observed TTPs
• Coordinate with industry partners for intelligence sharing
• Establish proactive threat hunting procedures
"""

    return consolidated

if __name__ == "__main__":
    report = consolidate_reports()
    print(report)

    with open("final_diamond_analysis.txt", "w") as f:
        f.write(report)

    print("\n" + "="*50)
    print("ANALYSIS COMPLETE")
    print("="*50)
    print("Final report saved to: final_diamond_analysis.txt")
```

```bash
# ✅ Make script executable and run it
chmod +x reports/comprehensive_analysis.py
cd reports
python3 comprehensive_analysis.py
```

---

## 🔍 Task 7: Verification and Review

### 📂 Subtask 7.1: Review Generated Reports

```bash
# 🌳 Display directory structure
echo "Generated Reports:"
tree reports/

# 📄 Show summary of final analysis
echo -e "\nFINAL ANALYSIS SUMMARY:"
tail -20 reports/final_diamond_analysis.txt
```

### ✅ Subtask 7.2: Validate Diamond Model Components

```python
#!/usr/bin/env python3
# 📄 validate_analysis.py — confirms every expected report file exists and has content
import os

def validate_diamond_model():
    required_files = [
        "reports/diamond_model_report.txt",
        "reports/adversary_profile.txt",
        "reports/capability_infrastructure.txt",
        "reports/victim_gaps_analysis.txt",
        "reports/final_diamond_analysis.txt"
    ]

    validation_results = {}

    for file_path in required_files:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                content = f.read()
                validation_results[file_path] = {
                    'exists': True,
                    'size': len(content),
                    'has_content': len(content) > 100
                }
        else:
            validation_results[file_path] = {
                'exists': False,
                'size': 0,
                'has_content': False
            }

    print("DIAMOND MODEL VALIDATION RESULTS")
    print("="*40)

    all_valid = True
    for file_path, results in validation_results.items():
        status = "✓ PASS" if results['exists'] and results['has_content'] else "✗ FAIL"
        print(f"{status} {file_path}")
        if not (results['exists'] and results['has_content']):
            all_valid = False

    print(f"\nOverall Status: {'✓ ALL COMPONENTS VALIDATED' if all_valid else '✗ VALIDATION FAILED'}")

    return all_valid

if __name__ == "__main__":
    validate_diamond_model()
```

```bash
# ▶️ Run validation
python3 validate_analysis.py
```

---

## 🗺️ MITRE ATT&CK Mapping

The capability vertex of this lab's Diamond Model is built directly from ATT&CK techniques observed across the simulated campaign's kill chain:

| Kill Chain Phase | ATT&CK Tactic | Technique | Effectiveness / Detection Difficulty |
|---|---|---|---|
| ✉️ Initial Access | Initial Access | T1566.001 (Spearphishing Attachment) | High / Medium |
| ⚡ Execution | Execution | T1059.001 (PowerShell), T1204.002 (Malicious File) | High / Low–Medium |
| 🚪 Persistence | Persistence | T1547.001 (Registry Run Keys) | Medium / Medium |
| 🔑 Credential Access | Credential Access | T1003 (OS Credential Dumping) | High / Medium |
| 📡 Command and Control | Command and Control | T1071.001 (Web Protocols) | High / High |

> 📝 **TODO:** As collection gaps close, add rows for Lateral Movement and Exfiltration once dwell-time telemetry confirms observed techniques.

---

## 🛠️ Troubleshooting

<details>
<summary>❓ <code>ModuleNotFoundError: No module named 'diamond_model_template'</code></summary>

`diamond_analysis.py` relies on `sys.path.append('../templates')` — it must be run from inside the `analysis/` directory.

```bash
cd ~/diamond-model-lab/analysis
python3 diamond_analysis.py
```
</details>

<details>
<summary>❓ <code>ModuleNotFoundError: No module named 'graphviz'</code> or <code>'networkx'</code></summary>

Reinstall the analysis dependencies; on some distros `graphviz` also needs the system package for rendering.

```bash
pip3 install --upgrade pandas matplotlib networkx graphviz
sudo apt install -y graphviz
```
</details>

<details>
<summary>❓ <code>comprehensive_analysis.py</code> produces a mostly-empty final report</summary>

The consolidation script only reads report files that already exist in the working directory. Run Tasks 3–6 in order first so every source `.txt` file is present before consolidating:

```bash
cd ~/diamond-model-lab
python3 analysis/adversary/adversary_profile.py
python3 analysis/capability/capability_mapping.py
python3 analysis/victim/victim_analysis.py
cd analysis && python3 diamond_analysis.py > ../reports/diamond_model_report.txt && cd ..
cd reports && python3 comprehensive_analysis.py
```
</details>

<details>
<summary>❓ <code>validate_analysis.py</code> reports FAIL on files that clearly exist</summary>

Validation checks `len(content) > 100` — a report that ran but produced trivial output (e.g. an exception was silently swallowed) will still fail. Inspect the flagged file directly:

```bash
cat reports/<flagged_file>.txt
wc -c reports/<flagged_file>.txt
```
</details>

<details>
<summary>❓ Relative-path <code>cd ../..</code> commands fail with "No such file or directory"</summary>

These scripts assume they're launched from their own subdirectory (e.g. `analysis/adversary/`). Always `cd` into the exact directory shown in each subtask before running its script.
</details>

---

## 🏁 Conclusion

You have successfully completed a comprehensive Diamond Model threat intelligence analysis. This lab demonstrated how to:

- Structure threat intelligence using the Diamond Model framework with four core elements
- Map adversary characteristics including identity, motivation, and capabilities
- Analyze attack infrastructure and technical capabilities systematically
- Assess victim patterns and targeting methodologies
- Identify intelligence gaps and prioritize collection requirements
- Generate actionable reports for threat intelligence consumers

The Diamond Model provides a structured approach to threat intelligence analysis that enables analysts to organize complex attack data, identify relationships between threat elements, and develop targeted intelligence requirements. This methodology is essential for mature threat intelligence programs and supports both tactical and strategic security decision-making.

### 🏆 Key Accomplishments
- ✅ Built a reusable, extensible Diamond Model Python framework
- ✅ Populated and analyzed all four vertices for a simulated APT campaign
- ✅ Mapped observed techniques to MITRE ATT&CK across the kill chain
- ✅ Identified and prioritized intelligence gaps by urgency tier
- ✅ Consolidated per-vertex reports into a single actionable deliverable
- ✅ Validated every report artifact programmatically

### 🌍 Real-World Applications
- 📌 Structuring incident findings during live APT investigations
- 📌 Driving intelligence collection tasking from identified gaps
- 📌 Briefing stakeholders using a consistent, repeatable four-vertex format
- 📌 Feeding ATT&CK-mapped capability data into detection engineering backlogs
- 📌 Supporting strategic threat landscape assessments with structured historical data

> 💡 **Why This Matters:** Your analysis produced comprehensive documentation that can guide defensive actions, threat hunting activities, and intelligence collection priorities for ongoing security operations — turning raw campaign observations into a structured, decision-ready intelligence product.

---

<div align="center">

### 🎓 Al Nafi — Practical Cybersecurity Training

![Al Nafi](https://img.shields.io/badge/Al_Nafi-Cybersecurity_Training-1976D2?style=for-the-badge)

</div>
