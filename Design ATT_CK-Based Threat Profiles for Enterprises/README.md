<div align="center">

# 🗺️ Design ATT&CK-Based Threat Profiles for Enterprises

### MITRE ATT&CK Navigation · Enterprise Threat Profiling · Risk-Aligned Prioritization

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-Shell_Scripting-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-D6202D?style=for-the-badge&logo=mitre&logoColor=white)
![STIX/TAXII](https://img.shields.io/badge/STIX%2FTAXII-Threat_Data-4B0082?style=for-the-badge)
![Pandas](https://img.shields.io/badge/Pandas-Data_Analysis-150458?style=for-the-badge&logo=pandas&logoColor=white)
![Matplotlib](https://img.shields.io/badge/Matplotlib-Visualization-11557C?style=for-the-badge)
![Risk Modeling](https://img.shields.io/badge/Domain-Risk_Modeling-8A2BE2?style=for-the-badge&logo=shieldsdotio&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-orange?style=for-the-badge)
![Duration](https://img.shields.io/badge/Duration-~3_Hours-informational?style=for-the-badge)

</div>

---

## 📖 Overview

This lab builds a full pipeline for turning the **MITRE ATT&CK Enterprise Matrix** into actionable, industry-specific threat profiles. You'll pull live ATT&CK data via STIX, parse tactics and techniques with Python, generate threat profiles for Financial Services, Healthcare, and Manufacturing scenarios, align each profile with an organizational risk model, and roll everything up into a single threat intelligence dashboard.

---

## 📑 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [✅ Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🧩 Task 1: Review MITRE ATT&CK Tactics, Techniques, and Procedures](#-task-1-review-mitre-attck-tactics-techniques-and-procedures)
- [🏢 Task 2: Design Threat Profile Based on Enterprise Attack Vectors](#-task-2-design-threat-profile-based-on-enterprise-attack-vectors)
- [⚖️ Task 3: Align Threat Profiles with Organizational Risk Models](#️-task-3-align-threat-profiles-with-organizational-risk-models)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

By completing this lab, you will:

| # | Objective |
|---|-----------|
| 1 | 🗺️ Navigate and utilize the MITRE ATT&CK framework effectively |
| 2 | 🏢 Create comprehensive threat profiles for enterprise environments |
| 3 | 🔗 Map attack vectors to organizational risk models |
| 4 | 📄 Develop actionable threat intelligence reports |

---

## ✅ Prerequisites

| Requirement | Details |
|-------------|---------|
| 🔐 Cybersecurity Concepts | Basic understanding of core concepts |
| 🐧 Linux CLI | Familiarity with the Linux command line |
| 🏗️ Enterprise Architecture | Knowledge of enterprise network architectures |
| 🧠 Threat Modeling | Understanding of threat modeling principles |

---

## 🖥️ Lab Environment

> 💡 **Al Nafi provides Linux-based cloud machines for this lab.** Simply click **Start Lab** to access your dedicated environment. The provided Linux machine is bare metal with no pre-installed tools — you will install all required tools yourself during the lab exercises.

---

## 🧩 Task 1: Review MITRE ATT&CK Tactics, Techniques, and Procedures

### 🔧 Subtask 1.1: Install Required Tools

```bash
# 🔄 Update system packages
sudo apt update && sudo apt upgrade -y

# 🐍 Install Python and pip
sudo apt install python3 python3-pip git curl jq -y

# 🧬 Install MITRE ATT&CK Python library
pip3 install mitreattack-python requests pandas

# 📊 Install additional analysis tools
pip3 install stix2 taxii2-client matplotlib seaborn

# 📂 Create working directory
mkdir ~/attack-lab && cd ~/attack-lab
```

### ⬇️ Subtask 1.2: Download ATT&CK Framework Data

```bash
# 🏢 Download ATT&CK Enterprise data
curl -o enterprise-attack.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

# 📱 Download Mobile ATT&CK data
curl -o mobile-attack.json https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json

# ✅ Verify downloads
ls -la *.json
```

### 🧠 Subtask 1.3: Create ATT&CK Analysis Script

```python
#!/usr/bin/env python3
# 📄 attack_analyzer.py — parses tactics and techniques from the STIX bundle

import json
import pandas as pd
from collections import defaultdict

class AttackAnalyzer:
    def __init__(self, data_file):
        with open(data_file, 'r') as f:
            self.data = json.load(f)
        self.tactics = []
        self.techniques = []
        self.parse_data()

    def parse_data(self):
        # 🔍 Walk the STIX object list, splitting tactics from techniques
        for obj in self.data['objects']:
            if obj['type'] == 'x-mitre-tactic':
                self.tactics.append({
                    'id': obj['external_references'][0]['external_id'],
                    'name': obj['name'],
                    'description': obj['description']
                })
            elif obj['type'] == 'attack-pattern':
                technique = {
                    'id': obj['external_references'][0]['external_id'],
                    'name': obj['name'],
                    'description': obj['description'],
                    'tactics': [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])]
                }
                self.techniques.append(technique)

    def get_tactics_summary(self):
        print("MITRE ATT&CK Tactics Summary:")
        print("-" * 50)
        for tactic in sorted(self.tactics, key=lambda x: x['id']):
            print(f"{tactic['id']}: {tactic['name']}")
        print(f"\nTotal Tactics: {len(self.tactics)}")

    def get_techniques_by_tactic(self, tactic_name):
        techniques = [t for t in self.techniques if tactic_name.lower() in [tac.lower() for tac in t['tactics']]]
        return techniques

    def export_tactic_techniques(self, tactic_name):
        # 💾 Write a per-tactic technique dump to a text file
        techniques = self.get_techniques_by_tactic(tactic_name)
        filename = f"{tactic_name.lower().replace(' ', '_')}_techniques.txt"
        with open(filename, 'w') as f:
            f.write(f"Techniques for {tactic_name}:\n")
            f.write("=" * 40 + "\n\n")
            for tech in techniques:
                f.write(f"ID: {tech['id']}\n")
                f.write(f"Name: {tech['name']}\n")
                f.write(f"Description: {tech['description'][:200]}...\n")
                f.write("-" * 40 + "\n")
        print(f"Exported {len(techniques)} techniques to {filename}")

if __name__ == "__main__":
    analyzer = AttackAnalyzer('enterprise-attack.json')
    analyzer.get_tactics_summary()
```

```bash
# ✅ Make script executable
chmod +x attack_analyzer.py
```

### ▶️ Subtask 1.4: Analyze ATT&CK Framework

```bash
# 🧮 Execute ATT&CK analysis
python3 attack_analyzer.py

# 📤 Export specific tactic techniques
python3 -c "
from attack_analyzer import AttackAnalyzer
analyzer = AttackAnalyzer('enterprise-attack.json')
analyzer.export_tactic_techniques('Initial Access')
analyzer.export_tactic_techniques('Persistence')
analyzer.export_tactic_techniques('Lateral Movement')
"
```

---

## 🏢 Task 2: Design Threat Profile Based on Enterprise Attack Vectors

### 🏗️ Subtask 2.1: Create Threat Profile Template

```python
#!/usr/bin/env python3
# 📄 threat_profile_generator.py — builds a scored, ATT&CK-mapped threat profile

import json
import datetime
from attack_analyzer import AttackAnalyzer

class ThreatProfileGenerator:
    def __init__(self, attack_data_file):
        self.analyzer = AttackAnalyzer(attack_data_file)
        self.profile = {
            'metadata': {},
            'threat_actor': {},
            'attack_vectors': [],
            'techniques': [],
            'mitigations': [],
            'risk_assessment': {}
        }

    def create_enterprise_profile(self, actor_name, industry, attack_vectors):
        self.profile['metadata'] = {
            'profile_name': f"{actor_name}_Enterprise_Profile",
            'created_date': datetime.datetime.now().isoformat(),
            'target_industry': industry,
            'profile_version': '1.0'
        }

        self.profile['threat_actor'] = {
            'name': actor_name,
            'sophistication': 'Advanced',
            'motivation': 'Financial/Espionage',
            'target_sectors': [industry]
        }

        # 🗺️ Map attack vectors to ATT&CK techniques
        for vector in attack_vectors:
            techniques = self.analyzer.get_techniques_by_tactic(vector)
            self.profile['attack_vectors'].append({
                'tactic': vector,
                'technique_count': len(techniques),
                'top_techniques': [t['name'] for t in techniques[:5]]
            })
            self.profile['techniques'].extend(techniques[:3])  # Top 3 per tactic

    def add_risk_assessment(self, likelihood, impact):
        self.profile['risk_assessment'] = {
            'likelihood': likelihood,
            'impact': impact,
            'risk_score': likelihood * impact,
            'risk_level': self.calculate_risk_level(likelihood * impact)
        }

    def calculate_risk_level(self, score):
        if score >= 20: return 'Critical'
        elif score >= 15: return 'High'
        elif score >= 10: return 'Medium'
        else: return 'Low'

    def export_profile(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.profile, f, indent=2)
        print(f"Threat profile exported to {filename}")

    def generate_report(self):
        # 📄 Human-readable profile summary
        report = f"""
ENTERPRISE THREAT PROFILE REPORT
================================

Profile: {self.profile['metadata']['profile_name']}
Created: {self.profile['metadata']['created_date']}
Target Industry: {self.profile['metadata']['target_industry']}

THREAT ACTOR OVERVIEW
--------------------
Name: {self.profile['threat_actor']['name']}
Sophistication: {self.profile['threat_actor']['sophistication']}
Motivation: {self.profile['threat_actor']['motivation']}

ATTACK VECTORS
--------------
"""
        for vector in self.profile['attack_vectors']:
            report += f"• {vector['tactic']}: {vector['technique_count']} techniques available\n"
            report += f"  Top techniques: {', '.join(vector['top_techniques'])}\n\n"

        report += f"""
RISK ASSESSMENT
---------------
Likelihood: {self.profile['risk_assessment']['likelihood']}/5
Impact: {self.profile['risk_assessment']['impact']}/5
Risk Score: {self.profile['risk_assessment']['risk_score']}/25
Risk Level: {self.profile['risk_assessment']['risk_level']}
"""
        return report

if __name__ == "__main__":
    # 💡 Example usage
    generator = ThreatProfileGenerator('enterprise-attack.json')
    generator.create_enterprise_profile(
        'APT-Finance-Hunter',
        'Financial Services',
        ['Initial Access', 'Persistence', 'Credential Access', 'Lateral Movement', 'Exfiltration']
    )
    generator.add_risk_assessment(4, 5)  # High likelihood, Critical impact
    generator.export_profile('financial_threat_profile.json')
    print(generator.generate_report())
```

```bash
# ✅ Make script executable
chmod +x threat_profile_generator.py
```

> 📝 **TODO:** Swap `APT-Finance-Hunter` and its attack vectors for a threat actor and industry relevant to your own organization.

### 🏭 Subtask 2.2: Generate Multiple Threat Profiles

```bash
# 💰 Generate Financial Services threat profile
python3 threat_profile_generator.py

# 🏥 Create Healthcare threat profile
python3 -c "
from threat_profile_generator import ThreatProfileGenerator
generator = ThreatProfileGenerator('enterprise-attack.json')
generator.create_enterprise_profile(
    'Healthcare-Ransomware-Group',
    'Healthcare',
    ['Initial Access', 'Defense Evasion', 'Impact', 'Command and Control']
)
generator.add_risk_assessment(5, 4)
generator.export_profile('healthcare_threat_profile.json')
print(generator.generate_report())
"

# 🏭 Create Manufacturing threat profile
python3 -c "
from threat_profile_generator import ThreatProfileGenerator
generator = ThreatProfileGenerator('enterprise-attack.json')
generator.create_enterprise_profile(
    'Industrial-Espionage-Actor',
    'Manufacturing',
    ['Initial Access', 'Persistence', 'Discovery', 'Collection', 'Exfiltration']
)
generator.add_risk_assessment(3, 4)
generator.export_profile('manufacturing_threat_profile.json')
print(generator.generate_report())
"
```

### 🔗 Subtask 2.3: Create Attack Vector Mapping

```python
#!/usr/bin/env python3
# 📄 attack_vector_mapper.py — maps common delivery vectors to ATT&CK tactics/techniques

import json
from attack_analyzer import AttackAnalyzer

class AttackVectorMapper:
    def __init__(self, attack_data_file):
        self.analyzer = AttackAnalyzer(attack_data_file)
        # 📬 Common enterprise attack vectors mapped to their driving tactics
        self.common_vectors = {
            'Email-Based': ['Initial Access', 'Execution'],
            'Web-Based': ['Initial Access', 'Persistence'],
            'Network-Based': ['Lateral Movement', 'Command and Control'],
            'Endpoint-Based': ['Persistence', 'Defense Evasion'],
            'Credential-Based': ['Credential Access', 'Lateral Movement']
        }

    def map_vectors_to_techniques(self):
        mapping = {}
        for vector, tactics in self.common_vectors.items():
            mapping[vector] = {}
            for tactic in tactics:
                techniques = self.analyzer.get_techniques_by_tactic(tactic)
                mapping[vector][tactic] = [
                    {'id': t['id'], 'name': t['name']}
                    for t in techniques[:5]  # Top 5 techniques
                ]
        return mapping

    def export_vector_mapping(self, filename='attack_vector_mapping.json'):
        mapping = self.map_vectors_to_techniques()
        with open(filename, 'w') as f:
            json.dump(mapping, f, indent=2)
        print(f"Attack vector mapping exported to {filename}")
        return mapping

if __name__ == "__main__":
    mapper = AttackVectorMapper('enterprise-attack.json')
    mapping = mapper.export_vector_mapping()

    # 📊 Print summary
    print("\nATTACK VECTOR MAPPING SUMMARY")
    print("=" * 40)
    for vector, tactics in mapping.items():
        print(f"\n{vector}:")
        for tactic, techniques in tactics.items():
            print(f"  {tactic}: {len(techniques)} techniques")
```

```bash
# ▶️ Run the vector mapper
python3 attack_vector_mapper.py
```

---

## ⚖️ Task 3: Align Threat Profiles with Organizational Risk Models

### 📐 Subtask 3.1: Create Risk Assessment Framework

```python
#!/usr/bin/env python3
# 📄 risk_alignment_tool.py — aligns ATT&CK-mapped profiles with org-specific risk context

import json
import pandas as pd

class RiskAlignmentTool:
    def __init__(self):
        # ⚖️ Weighted risk factor scales
        self.risk_factors = {
            'asset_criticality': {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4},
            'threat_likelihood': {'Very Low': 1, 'Low': 2, 'Medium': 3, 'High': 4, 'Very High': 5},
            'vulnerability_severity': {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4},
            'impact_magnitude': {'Minimal': 1, 'Minor': 2, 'Moderate': 3, 'Major': 4, 'Severe': 5}
        }

        # 🏢 Organizational context by industry
        self.organizational_contexts = {
            'Financial Services': {
                'regulatory_requirements': 'High',
                'data_sensitivity': 'Critical',
                'availability_requirements': 'Critical',
                'reputation_impact': 'High'
            },
            'Healthcare': {
                'regulatory_requirements': 'Critical',
                'data_sensitivity': 'Critical',
                'availability_requirements': 'Critical',
                'reputation_impact': 'High'
            },
            'Manufacturing': {
                'regulatory_requirements': 'Medium',
                'data_sensitivity': 'High',
                'availability_requirements': 'High',
                'reputation_impact': 'Medium'
            }
        }

    def calculate_risk_score(self, asset_crit, threat_like, vuln_sev, impact_mag):
        score = (
            self.risk_factors['asset_criticality'][asset_crit] +
            self.risk_factors['threat_likelihood'][threat_like] +
            self.risk_factors['vulnerability_severity'][vuln_sev] +
            self.risk_factors['impact_magnitude'][impact_mag]
        )
        return score

    def align_threat_with_organization(self, threat_profile_file, organization_type):
        with open(threat_profile_file, 'r') as f:
            threat_profile = json.load(f)

        org_context = self.organizational_contexts.get(organization_type, {})

        alignment = {
            'threat_profile': threat_profile['metadata']['profile_name'],
            'organization_type': organization_type,
            'organizational_context': org_context,
            'aligned_risk_assessment': {},
            'mitigation_priorities': [],
            'monitoring_requirements': []
        }

        # 🧮 Calculate aligned risk scores for each attack vector
        for vector in threat_profile['attack_vectors']:
            risk_score = self.calculate_risk_score(
                'High',  # Assume high asset criticality
                'High',  # From threat profile
                'High',  # Assume high vulnerability
                'Major'  # Significant impact
            )

            alignment['aligned_risk_assessment'][vector['tactic']] = {
                'risk_score': risk_score,
                'priority': 'High' if risk_score >= 12 else 'Medium' if risk_score >= 8 else 'Low',
                'techniques_count': vector['technique_count']
            }

        # 🎯 Generate mitigation priorities
        sorted_tactics = sorted(
            alignment['aligned_risk_assessment'].items(),
            key=lambda x: x[1]['risk_score'],
            reverse=True
        )

        alignment['mitigation_priorities'] = [
            {
                'tactic': tactic,
                'priority_level': data['priority'],
                'risk_score': data['risk_score']
            }
            for tactic, data in sorted_tactics[:5]  # Top 5 priorities
        ]

        return alignment

    def export_alignment_report(self, alignment, filename):
        with open(filename, 'w') as f:
            json.dump(alignment, f, indent=2)

        # 📄 Generate readable report
        report_filename = filename.replace('.json', '_report.txt')
        with open(report_filename, 'w') as f:
            f.write("THREAT PROFILE RISK ALIGNMENT REPORT\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Threat Profile: {alignment['threat_profile']}\n")
            f.write(f"Organization Type: {alignment['organization_type']}\n\n")

            f.write("ORGANIZATIONAL CONTEXT\n")
            f.write("-" * 25 + "\n")
            for key, value in alignment['organizational_context'].items():
                f.write(f"{key.replace('_', ' ').title()}: {value}\n")

            f.write("\nRISK ASSESSMENT BY TACTIC\n")
            f.write("-" * 30 + "\n")
            for tactic, data in alignment['aligned_risk_assessment'].items():
                f.write(f"{tactic}: Score {data['risk_score']}/16 ({data['priority']} Priority)\n")

            f.write("\nMITIGATION PRIORITIES\n")
            f.write("-" * 20 + "\n")
            for i, priority in enumerate(alignment['mitigation_priorities'], 1):
                f.write(f"{i}. {priority['tactic']} (Risk Score: {priority['risk_score']})\n")

        print(f"Alignment report exported to {filename} and {report_filename}")

if __name__ == "__main__":
    tool = RiskAlignmentTool()

    # 💰 Align financial services threat profile
    alignment = tool.align_threat_with_organization(
        'financial_threat_profile.json',
        'Financial Services'
    )
    tool.export_alignment_report(alignment, 'financial_risk_alignment.json')
```

```bash
# ✅ Make script executable
chmod +x risk_alignment_tool.py
```

> 📝 **TODO:** Replace the assumed `'High'` / `'Major'` inputs to `calculate_risk_score()` with values from your own vulnerability scans and asset inventory.

### 📊 Subtask 3.2: Generate Risk Alignment Reports

```bash
# 💰 Generate risk alignment for all threat profiles
python3 risk_alignment_tool.py

# 🏥 Generate healthcare alignment
python3 -c "
from risk_alignment_tool import RiskAlignmentTool
tool = RiskAlignmentTool()
alignment = tool.align_threat_with_organization('healthcare_threat_profile.json', 'Healthcare')
tool.export_alignment_report(alignment, 'healthcare_risk_alignment.json')
"

# 🏭 Generate manufacturing alignment
python3 -c "
from risk_alignment_tool import RiskAlignmentTool
tool = RiskAlignmentTool()
alignment = tool.align_threat_with_organization('manufacturing_threat_profile.json', 'Manufacturing')
tool.export_alignment_report(alignment, 'manufacturing_risk_alignment.json')
"
```

### 📈 Subtask 3.3: Create Comprehensive Dashboard

```python
#!/usr/bin/env python3
# 📄 threat_dashboard.py — rolls up every profile and alignment into one dashboard

import json
import os
from datetime import datetime

class ThreatDashboard:
    def __init__(self):
        self.profiles = []
        self.alignments = []
        self.load_data()

    def load_data(self):
        # 📥 Load threat profiles
        profile_files = [f for f in os.listdir('.') if f.endswith('_threat_profile.json')]
        for file in profile_files:
            with open(file, 'r') as f:
                self.profiles.append(json.load(f))

        # 📥 Load risk alignments
        alignment_files = [f for f in os.listdir('.') if f.endswith('_risk_alignment.json')]
        for file in alignment_files:
            with open(file, 'r') as f:
                self.alignments.append(json.load(f))

    def generate_dashboard(self):
        dashboard = f"""
ENTERPRISE THREAT INTELLIGENCE DASHBOARD
========================================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

THREAT PROFILES SUMMARY
-----------------------
Total Profiles: {len(self.profiles)}

"""

        for profile in self.profiles:
            dashboard += f"Profile: {profile['metadata']['profile_name']}\n"
            dashboard += f"  Industry: {profile['metadata']['target_industry']}\n"
            dashboard += f"  Risk Level: {profile['risk_assessment']['risk_level']}\n"
            dashboard += f"  Attack Vectors: {len(profile['attack_vectors'])}\n"
            dashboard += f"  Risk Score: {profile['risk_assessment']['risk_score']}/25\n\n"

        dashboard += "RISK ALIGNMENT SUMMARY\n"
        dashboard += "----------------------\n"

        for alignment in self.alignments:
            dashboard += f"Organization: {alignment['organization_type']}\n"
            dashboard += f"  Top Priority: {alignment['mitigation_priorities'][0]['tactic']}\n"
            dashboard += f"  High Priority Tactics: {len([p for p in alignment['mitigation_priorities'] if p['priority_level'] == 'High'])}\n\n"

        dashboard += "RECOMMENDATIONS\n"
        dashboard += "---------------\n"
        dashboard += "1. Focus on Initial Access and Persistence tactics across all profiles\n"
        dashboard += "2. Implement enhanced monitoring for high-risk attack vectors\n"
        dashboard += "3. Prioritize mitigation controls based on organizational context\n"
        dashboard += "4. Regular threat profile updates based on emerging threats\n"

        return dashboard

    def export_dashboard(self, filename='threat_intelligence_dashboard.txt'):
        dashboard = self.generate_dashboard()
        with open(filename, 'w') as f:
            f.write(dashboard)
        print(f"Dashboard exported to {filename}")
        return dashboard

if __name__ == "__main__":
    dashboard = ThreatDashboard()
    print(dashboard.export_dashboard())
```

```bash
# ▶️ Generate the dashboard
python3 threat_dashboard.py
```

### 🔍 Subtask 3.4: Verify Lab Outputs

```bash
# 📂 List all generated files
echo "Generated Lab Files:"
echo "==================="
ls -la *.json *.txt *.py | grep -E '\.(json|txt)$'

# 📏 Display file sizes and creation times
echo -e "\nFile Details:"
echo "============="
for file in *.json *.txt; do
    if [ -f "$file" ]; then
        echo "$file: $(wc -l < "$file") lines, $(du -h "$file" | cut -f1)"
    fi
done

# 📋 Show summary of threat profiles
echo -e "\nThreat Profile Summary:"
echo "======================="
python3 -c "
import json
import glob

for file in glob.glob('*_threat_profile.json'):
    with open(file, 'r') as f:
        data = json.load(f)
    print(f'{file}: {data[\"metadata\"][\"target_industry\"]} - Risk Level: {data[\"risk_assessment\"][\"risk_level\"]}')
"
```

---

## 🗺️ MITRE ATT&CK Mapping

Each enterprise threat profile built in this lab is anchored to a specific set of ATT&CK tactics selected for that industry's threat landscape:

| Industry Profile | Threat Actor Archetype | ATT&CK Tactics Mapped | Risk Level |
|---|---|---|---|
| 💰 Financial Services | APT-Finance-Hunter | Initial Access, Persistence, Credential Access, Lateral Movement, Exfiltration | Critical (Likelihood 4 × Impact 5) |
| 🏥 Healthcare | Healthcare-Ransomware-Group | Initial Access, Defense Evasion, Impact, Command and Control | High (Likelihood 5 × Impact 4) |
| 🏭 Manufacturing | Industrial-Espionage-Actor | Initial Access, Persistence, Discovery, Collection, Exfiltration | Medium-High (Likelihood 3 × Impact 4) |

**Common attack vector → tactic mapping** (from `attack_vector_mapper.py`):

| Attack Vector | Primary Tactics |
|---|---|
| 📧 Email-Based | Initial Access, Execution |
| 🌐 Web-Based | Initial Access, Persistence |
| 🖧 Network-Based | Lateral Movement, Command and Control |
| 💻 Endpoint-Based | Persistence, Defense Evasion |
| 🔑 Credential-Based | Credential Access, Lateral Movement |

> 📝 **TODO:** Re-run `attack_analyzer.py` against a fresh `enterprise-attack.json` periodically — ATT&CK adds new techniques and sub-techniques with each release.

---

## 🛠️ Troubleshooting

<details>
<summary>❓ <code>curl</code> download of <code>enterprise-attack.json</code> fails or returns HTML</summary>

Usually a network/proxy issue or GitHub rate limiting. Verify connectivity and re-try, or check the response body for a rate-limit message.

```bash
curl -sI https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
curl -o enterprise-attack.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
python3 -m json.tool enterprise-attack.json > /dev/null && echo "Valid JSON"
```
</details>

<details>
<summary>❓ <code>ModuleNotFoundError: No module named 'mitreattack'</code> or <code>'stix2'</code></summary>

```bash
pip3 install --upgrade mitreattack-python stix2 taxii2-client pandas matplotlib seaborn
```
</details>

<details>
<summary>❓ <code>get_techniques_by_tactic()</code> returns an empty list for a valid tactic name</summary>

Tactic names in ATT&CK's `kill_chain_phases` use lowercase, hyphenated `phase_name` values (e.g. `initial-access`), while the script matches on `tactic_name.lower()`. Pass the tactic name exactly as shown in ATT&CK (e.g. `"Initial Access"`, not `"initial-access"`) — the script handles the case-folding internally, but hyphen-vs-space mismatches will still return zero results.
</details>

<details>
<summary>❓ <code>threat_dashboard.py</code> shows 0 profiles or 0 alignments</summary>

The dashboard only scans the current directory for files ending in `_threat_profile.json` / `_risk_alignment.json`. Confirm you're running it from `~/attack-lab` and that Tasks 2 and 3 completed successfully:

```bash
cd ~/attack-lab
ls *_threat_profile.json *_risk_alignment.json
```
</details>

<details>
<summary>❓ Inline <code>python3 -c "..."</code> commands fail with import errors</summary>

These one-liners import from `attack_analyzer.py`, `threat_profile_generator.py`, etc., which must exist in the current working directory.

```bash
cd ~/attack-lab
ls attack_analyzer.py threat_profile_generator.py risk_alignment_tool.py
```
</details>

---

## 🏁 Conclusion

In this lab, you successfully:

- Analyzed the MITRE ATT&CK framework by installing analysis tools and exploring tactics, techniques, and procedures
- Created comprehensive threat profiles for different enterprise environments including financial services, healthcare, and manufacturing sectors
- Aligned threat profiles with organizational risk models by developing risk assessment frameworks and generating prioritized mitigation strategies
- Generated actionable intelligence reports that can be used by security teams to enhance their defensive posture

The threat profiles and risk alignments you created provide a structured approach to understanding and defending against advanced persistent threats in enterprise environments. These materials can be used to inform security strategy, guide investment decisions, and improve incident response capabilities.

### 🏆 Key Accomplishments
- ✅ Parsed the live MITRE ATT&CK Enterprise matrix directly from its STIX data source
- ✅ Built a reusable threat-profile generator scored by likelihood × impact
- ✅ Produced three industry-specific threat profiles (Financial, Healthcare, Manufacturing)
- ✅ Aligned each profile with organizational context and prioritized mitigations
- ✅ Consolidated everything into a single threat intelligence dashboard

### 🌍 Real-World Applications
- 📌 Standardizing threat communication using ATT&CK's common vocabulary across security teams
- 📌 Tailoring threat profiles to sector-specific regulatory and risk contexts
- 📌 Driving security investment and control prioritization from risk-scored tactics
- 📌 Feeding mitigation priorities into detection engineering and SOC playbooks
- 📌 Establishing a repeatable cadence for refreshing profiles as ATT&CK and the threat landscape evolve

> 💡 **Key Takeaways:** The ATT&CK framework provides a standardized threat intelligence language; threat profiles must be tailored to specific organizational contexts; risk alignment ensures security investments address the most critical threats; and regular updates to threat profiles are essential for maintaining effectiveness.

---

<div align="center">

### 🎓 Al Nafi — Practical Cybersecurity Training

![Al Nafi](https://img.shields.io/badge/Al_Nafi-Cybersecurity_Training-1976D2?style=for-the-badge)

</div>
