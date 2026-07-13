<div align="center">

# 🎯 Build an Intelligence Requirements Matrix (IRM)

### Cyber Threat Intelligence · Prioritized Collection Planning · Stakeholder-Driven Review

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-Shell_Scripting-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-Data_Handling-150458?style=for-the-badge&logo=pandas&logoColor=white)
![LibreOffice](https://img.shields.io/badge/LibreOffice-Calc-18A303?style=for-the-badge&logo=libreoffice&logoColor=white)
![YAML](https://img.shields.io/badge/YAML-Config-CB171E?style=for-the-badge&logo=yaml&logoColor=white)
![JSON](https://img.shields.io/badge/JSON-Data_Format-000000?style=for-the-badge&logo=json&logoColor=white)
![Threat Intelligence](https://img.shields.io/badge/Domain-Threat_Intelligence-8A2BE2?style=for-the-badge&logo=shieldsdotio&logoColor=white)
![Difficulty](https://img.shields.io/badge/Difficulty-Intermediate-orange?style=for-the-badge)
![Duration](https://img.shields.io/badge/Duration-~2_Hours-informational?style=for-the-badge)

</div>

---

## 📖 Overview

This lab walks through building a complete **Intelligence Requirements Matrix (IRM)** — the foundational planning artifact that drives any Cyber Threat Intelligence (CTI) program. You'll define intelligence requirements aligned to organizational needs, score and prioritize them, enrich them with concrete collection methods and data sources, and produce stakeholder-ready review packages — all using lightweight open-source Python tooling.

---

## 📑 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [✅ Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🧩 Task 1: Define Intelligence Requirements Based on Organizational Needs](#-task-1-define-intelligence-requirements-based-on-organizational-needs)
- [📊 Task 2: Develop an IRM for Prioritizing Intelligence Gathering](#-task-2-develop-an-irm-for-prioritizing-intelligence-gathering)
- [🤝 Task 3: Review IRM with Relevant Stakeholders](#-task-3-review-irm-with-relevant-stakeholders)
- [🔍 Verification Commands](#-verification-commands)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

By completing this lab, you will:

| # | Objective |
|---|-----------|
| 1 | 🧠 Understand the structure and purpose of an Intelligence Requirements Matrix |
| 2 | 🛠️ Create a comprehensive IRM using open-source tools |
| 3 | ⚖️ Prioritize intelligence requirements based on organizational needs |
| 4 | 🤝 Develop stakeholder review processes for intelligence gathering |

---

## ✅ Prerequisites

| Requirement | Details |
|-------------|---------|
| 🐧 Linux CLI | Basic command-line knowledge |
| 🔐 Cybersecurity Fundamentals | Understanding of core concepts and terminology |
| 📝 Text Editors | Familiarity with `nano` / `vim` |
| 📉 Risk Assessment | Basic knowledge of organizational risk assessment |

---

## 🖥️ Lab Environment

> 💡 **Al Nafi provides Linux-based cloud machines for this lab.** Simply click **Start Lab** to access your dedicated Linux machine. The provided machine is bare metal with no pre-installed tools — you will install every required tool yourself during the lab.

---

## 🧩 Task 1: Define Intelligence Requirements Based on Organizational Needs

### 🔧 Subtask 1.1: Install Required Tools

```bash
# 🔄 Update system packages
sudo apt update && sudo apt upgrade -y

# 📦 Install essential tools
sudo apt install -y python3 python3-pip git curl wget

# 🐍 Install Python libraries for data handling
pip3 install pandas openpyxl jinja2

# 📊 Install LibreOffice for spreadsheet management
sudo apt install -y libreoffice-calc
```

### 📁 Subtask 1.2: Create Project Structure

```bash
# 📂 Create project directory
mkdir ~/irm-lab
cd ~/irm-lab

# 🗂️ Create subdirectories
mkdir templates data output scripts

# ⚙️ Create initial configuration file
cat > config.yaml << 'EOF'
organization:
  name: "Sample Organization"
  sector: "Technology"
  threat_level: "Medium"

intelligence_categories:
  - "Threat Intelligence"
  - "Vulnerability Intelligence"
  - "Asset Intelligence"
  - "Compliance Intelligence"
  - "Business Intelligence"
EOF
```

> 📝 **TODO:** Replace the sample organization name, sector, and threat level in `config.yaml` with your own organization's profile.

### 🧠 Subtask 1.3: Define Intelligence Requirements Framework

```python
#!/usr/bin/env python3
# 📄 scripts/define_requirements.py — models and seeds baseline intelligence requirements

import json
import yaml
from datetime import datetime

class IntelligenceRequirement:
    def __init__(self, req_id, category, description, priority, frequency, stakeholder):
        self.req_id = req_id
        self.category = category
        self.description = description
        self.priority = priority
        self.frequency = frequency
        self.stakeholder = stakeholder
        self.created_date = datetime.now().strftime("%Y-%m-%d")

def load_config():
    # 📥 Load organization profile from config.yaml
    with open('config.yaml', 'r') as file:
        return yaml.safe_load(file)

def define_sample_requirements():
    # 🧾 Seed requirements — one per intelligence category
    requirements = [
        IntelligenceRequirement("IR-001", "Threat Intelligence",
                              "Monitor emerging malware targeting our industry",
                              "High", "Daily", "CISO"),
        IntelligenceRequirement("IR-002", "Vulnerability Intelligence",
                              "Track critical vulnerabilities in our tech stack",
                              "High", "Weekly", "Security Team"),
        IntelligenceRequirement("IR-003", "Asset Intelligence",
                              "Inventory of internet-facing assets",
                              "Medium", "Monthly", "IT Operations"),
        IntelligenceRequirement("IR-004", "Compliance Intelligence",
                              "Monitor regulatory changes affecting operations",
                              "Medium", "Quarterly", "Compliance Officer"),
        IntelligenceRequirement("IR-005", "Business Intelligence",
                              "Competitor security posture analysis",
                              "Low", "Quarterly", "Business Strategy")
    ]
    # TODO: Add your own intelligence requirements based on your organization's actual threat landscape
    return requirements

def save_requirements(requirements):
    # 💾 Serialize requirements to JSON
    req_data = []
    for req in requirements:
        req_data.append({
            'ID': req.req_id,
            'Category': req.category,
            'Description': req.description,
            'Priority': req.priority,
            'Frequency': req.frequency,
            'Stakeholder': req.stakeholder,
            'Created': req.created_date
        })

    with open('data/requirements.json', 'w') as file:
        json.dump(req_data, file, indent=2)

    print(f"Saved {len(req_data)} intelligence requirements to data/requirements.json")

if __name__ == "__main__":
    config = load_config()
    requirements = define_sample_requirements()
    save_requirements(requirements)

    print(f"Intelligence Requirements defined for: {config['organization']['name']}")
    print(f"Sector: {config['organization']['sector']}")
    print(f"Threat Level: {config['organization']['threat_level']}")
```

```bash
# ✅ Make script executable and run it
chmod +x scripts/define_requirements.py
python3 scripts/define_requirements.py
```

---

## 📊 Task 2: Develop an IRM for Prioritizing Intelligence Gathering

### 🏗️ Subtask 2.1: Create IRM Template

```python
#!/usr/bin/env python3
# 📄 scripts/create_irm.py — scores, schedules, and exports the IRM

import json
import pandas as pd
from datetime import datetime, timedelta

def load_requirements():
    # 📥 Pull the seeded requirements
    with open('data/requirements.json', 'r') as file:
        return json.load(file)

def calculate_priority_score(priority, frequency):
    # ⚖️ Weighted score = priority weight × frequency weight
    priority_weights = {'High': 3, 'Medium': 2, 'Low': 1}
    frequency_weights = {'Daily': 4, 'Weekly': 3, 'Monthly': 2, 'Quarterly': 1}

    return priority_weights.get(priority, 1) * frequency_weights.get(frequency, 1)

def create_irm_matrix():
    requirements = load_requirements()

    irm_data = []
    for req in requirements:
        priority_score = calculate_priority_score(req['Priority'], req['Frequency'])

        # 📅 Calculate next collection date based on frequency
        today = datetime.now()
        if req['Frequency'] == 'Daily':
            next_collection = today + timedelta(days=1)
        elif req['Frequency'] == 'Weekly':
            next_collection = today + timedelta(weeks=1)
        elif req['Frequency'] == 'Monthly':
            next_collection = today + timedelta(days=30)
        else:  # Quarterly
            next_collection = today + timedelta(days=90)

        irm_data.append({
            'Requirement_ID': req['ID'],
            'Category': req['Category'],
            'Description': req['Description'],
            'Priority': req['Priority'],
            'Frequency': req['Frequency'],
            'Priority_Score': priority_score,
            'Stakeholder': req['Stakeholder'],
            'Collection_Method': 'TBD',
            'Data_Sources': 'TBD',
            'Next_Collection': next_collection.strftime("%Y-%m-%d"),
            'Status': 'Active',
            'Last_Updated': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    # 🔽 Sort by priority score (descending)
    irm_data.sort(key=lambda x: x['Priority_Score'], reverse=True)

    return irm_data

def save_irm_matrix(irm_data):
    # 💾 Save as JSON
    with open('output/irm_matrix.json', 'w') as file:
        json.dump(irm_data, file, indent=2)

    # 💾 Save as CSV for easy viewing
    df = pd.DataFrame(irm_data)
    df.to_csv('output/irm_matrix.csv', index=False)

    # 💾 Save as Excel
    df.to_excel('output/irm_matrix.xlsx', index=False, sheet_name='IRM')

    print("IRM Matrix saved in multiple formats:")
    print("- JSON: output/irm_matrix.json")
    print("- CSV: output/irm_matrix.csv")
    print("- Excel: output/irm_matrix.xlsx")

def display_irm_summary(irm_data):
    # 📈 Console summary
    print("\n=== Intelligence Requirements Matrix Summary ===")
    print(f"Total Requirements: {len(irm_data)}")

    priority_counts = {}
    for item in irm_data:
        priority = item['Priority']
        priority_counts[priority] = priority_counts.get(priority, 0) + 1

    print("\nPriority Distribution:")
    for priority, count in priority_counts.items():
        print(f"  {priority}: {count}")

    print("\nTop 3 Priority Requirements:")
    for i, item in enumerate(irm_data[:3], 1):
        print(f"  {i}. {item['Requirement_ID']}: {item['Description'][:50]}...")

if __name__ == "__main__":
    irm_data = create_irm_matrix()
    save_irm_matrix(irm_data)
    display_irm_summary(irm_data)
```

```bash
# ▶️ Run the IRM creation script
python3 scripts/create_irm.py
```

### 🔗 Subtask 2.2: Add Collection Methods and Data Sources

```python
#!/usr/bin/env python3
# 📄 scripts/enhance_irm.py — fills in collection methods and data sources by category

import json
import pandas as pd

def load_irm():
    with open('output/irm_matrix.json', 'r') as file:
        return json.load(file)

def enhance_with_methods():
    irm_data = load_irm()

    # 🗺️ Collection methods and data sources, mapped per intelligence category
    enhancement_map = {
        'Threat Intelligence': {
            'Collection_Method': 'Automated feeds, Manual analysis',
            'Data_Sources': 'OSINT feeds, Threat intel platforms, Security blogs'
        },
        'Vulnerability Intelligence': {
            'Collection_Method': 'Vulnerability scanners, CVE monitoring',
            'Data_Sources': 'NVD, Vendor advisories, Security scanners'
        },
        'Asset Intelligence': {
            'Collection_Method': 'Network scanning, Asset discovery tools',
            'Data_Sources': 'Network scanners, CMDB, Cloud APIs'
        },
        'Compliance Intelligence': {
            'Collection_Method': 'Regulatory monitoring, Legal research',
            'Data_Sources': 'Regulatory websites, Legal databases, Industry reports'
        },
        'Business Intelligence': {
            'Collection_Method': 'Market research, Competitive analysis',
            'Data_Sources': 'Industry reports, News feeds, Social media'
        }
    }
    # TODO: Swap in the specific feeds, scanners, and platforms your organization actually has access to

    for item in irm_data:
        category = item['Category']
        if category in enhancement_map:
            item['Collection_Method'] = enhancement_map[category]['Collection_Method']
            item['Data_Sources'] = enhancement_map[category]['Data_Sources']

    return irm_data

def save_enhanced_irm(irm_data):
    # 💾 Save enhanced version
    with open('output/enhanced_irm_matrix.json', 'w') as file:
        json.dump(irm_data, file, indent=2)

    df = pd.DataFrame(irm_data)
    df.to_excel('output/enhanced_irm_matrix.xlsx', index=False, sheet_name='Enhanced_IRM')

    print("Enhanced IRM Matrix saved:")
    print("- JSON: output/enhanced_irm_matrix.json")
    print("- Excel: output/enhanced_irm_matrix.xlsx")

if __name__ == "__main__":
    enhanced_irm = enhance_with_methods()
    save_enhanced_irm(enhanced_irm)
    print("IRM enhanced with collection methods and data sources")
```

```bash
# ▶️ Run the enhancement script
python3 scripts/enhance_irm.py
```

---

## 🤝 Task 3: Review IRM with Relevant Stakeholders

### 📰 Subtask 3.1: Generate Stakeholder Review Report

```python
#!/usr/bin/env python3
# 📄 scripts/generate_review.py — builds an HTML review report and a Markdown checklist

import json
from datetime import datetime

def load_enhanced_irm():
    with open('output/enhanced_irm_matrix.json', 'r') as file:
        return json.load(file)

def generate_stakeholder_report():
    irm_data = load_enhanced_irm()

    # 👥 Group requirements by stakeholder
    stakeholder_groups = {}
    for item in irm_data:
        stakeholder = item['Stakeholder']
        if stakeholder not in stakeholder_groups:
            stakeholder_groups[stakeholder] = []
        stakeholder_groups[stakeholder].append(item)

    # 🎨 Build HTML report with priority-based color coding
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Intelligence Requirements Matrix - Stakeholder Review</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .high {{ background-color: #ffebee; }}
        .medium {{ background-color: #fff3e0; }}
        .low {{ background-color: #e8f5e8; }}
        .header {{ background-color: #1976d2; color: white; padding: 20px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Intelligence Requirements Matrix</h1>
        <p>Stakeholder Review Document</p>
        <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
"""

    for stakeholder, requirements in stakeholder_groups.items():
        html_content += f"""
    <h2>Requirements for: {stakeholder}</h2>
    <table>
        <tr>
            <th>ID</th>
            <th>Category</th>
            <th>Description</th>
            <th>Priority</th>
            <th>Frequency</th>
            <th>Collection Method</th>
            <th>Next Collection</th>
        </tr>
"""
        for req in requirements:
            priority_class = req['Priority'].lower()
            html_content += f"""
        <tr class="{priority_class}">
            <td>{req['Requirement_ID']}</td>
            <td>{req['Category']}</td>
            <td>{req['Description']}</td>
            <td>{req['Priority']}</td>
            <td>{req['Frequency']}</td>
            <td>{req['Collection_Method']}</td>
            <td>{req['Next_Collection']}</td>
        </tr>
"""
        html_content += "    </table>\n"

    html_content += """
    <h2>Review Instructions</h2>
    <ul>
        <li>Review each requirement assigned to your role</li>
        <li>Verify the priority and frequency are appropriate</li>
        <li>Confirm collection methods are feasible</li>
        <li>Provide feedback on resource requirements</li>
        <li>Suggest additional requirements if needed</li>
    </ul>
</body>
</html>
"""

    with open('output/stakeholder_review.html', 'w') as file:
        file.write(html_content)

    print("Stakeholder review report generated: output/stakeholder_review.html")

def create_review_checklist():
    # 📋 Markdown checklist for the review meeting
    checklist = """
# Intelligence Requirements Matrix Review Checklist

## Pre-Review Preparation
- [ ] All stakeholders have received the IRM document
- [ ] Review meeting scheduled with key stakeholders
- [ ] Current threat landscape assessment completed

## Review Criteria

### For Each Requirement:
- [ ] Priority level is appropriate for current threat environment
- [ ] Collection frequency aligns with business needs
- [ ] Data sources are accessible and reliable
- [ ] Collection methods are technically feasible
- [ ] Resource requirements are realistic
- [ ] Stakeholder assignment is correct

### Overall IRM Assessment:
- [ ] Coverage of all critical intelligence areas
- [ ] Balance between high/medium/low priority items
- [ ] Alignment with organizational risk appetite
- [ ] Integration with existing security processes
- [ ] Scalability for future growth

## Post-Review Actions:
- [ ] Document stakeholder feedback
- [ ] Update IRM based on review comments
- [ ] Establish regular review schedule
- [ ] Define success metrics for intelligence collection
- [ ] Create implementation timeline

## Stakeholder Sign-off:
- [ ] CISO approval
- [ ] Security Team lead approval
- [ ] IT Operations approval
- [ ] Compliance Officer approval
- [ ] Business Strategy approval

Review Date: _______________
Next Review Date: _______________
"""

    with open('output/review_checklist.md', 'w') as file:
        file.write(checklist)

    print("Review checklist created: output/review_checklist.md")

if __name__ == "__main__":
    generate_stakeholder_report()
    create_review_checklist()
```

```bash
# ▶️ Run the review generation script
python3 scripts/generate_review.py
```

### 💬 Subtask 3.2: Create Review Feedback System

```python
#!/usr/bin/env python3
# 📄 scripts/collect_feedback.py — builds a feedback template and simulates stakeholder responses

import json
from datetime import datetime

def create_feedback_template():
    # 🧾 Blank feedback structure per requirement
    feedback_template = {
        "review_date": datetime.now().strftime("%Y-%m-%d"),
        "reviewer_info": {
            "name": "",
            "role": "",
            "department": ""
        },
        "requirement_feedback": [],
        "general_feedback": {
            "overall_assessment": "",
            "missing_requirements": [],
            "resource_concerns": [],
            "implementation_suggestions": []
        },
        "approval_status": "pending"
    }

    with open('output/enhanced_irm_matrix.json', 'r') as file:
        irm_data = json.load(file)

    for req in irm_data:
        feedback_item = {
            "requirement_id": req['Requirement_ID'],
            "current_priority": req['Priority'],
            "suggested_priority": "",
            "current_frequency": req['Frequency'],
            "suggested_frequency": "",
            "feasibility_rating": "",
            "comments": "",
            "approved": ""
        }
        feedback_template["requirement_feedback"].append(feedback_item)

    with open('templates/feedback_template.json', 'w') as file:
        json.dump(feedback_template, file, indent=2)

    print("Feedback template created: templates/feedback_template.json")

def simulate_stakeholder_feedback():
    # 👥 Sample feedback from three representative stakeholders
    stakeholders = [
        {"name": "John Smith", "role": "CISO", "department": "Security"},
        {"name": "Jane Doe", "role": "Security Analyst", "department": "Security"},
        {"name": "Bob Johnson", "role": "IT Manager", "department": "IT Operations"}
    ]
    # TODO: Replace simulated stakeholders with feedback collected from your real reviewers

    for stakeholder in stakeholders:
        with open('templates/feedback_template.json', 'r') as file:
            feedback = json.load(file)

        feedback["reviewer_info"] = stakeholder
        feedback["general_feedback"]["overall_assessment"] = "Good coverage of intelligence requirements"
        feedback["approval_status"] = "approved"

        for req_feedback in feedback["requirement_feedback"][:2]:
            req_feedback["feasibility_rating"] = "High"
            req_feedback["comments"] = "Looks good, no changes needed"
            req_feedback["approved"] = "yes"

        filename = f"data/feedback_{stakeholder['role'].lower().replace(' ', '_')}.json"
        with open(filename, 'w') as file:
            json.dump(feedback, file, indent=2)

        print(f"Sample feedback created for {stakeholder['name']}: {filename}")

if __name__ == "__main__":
    create_feedback_template()
    simulate_stakeholder_feedback()
```

```bash
# ▶️ Run the feedback collection script
python3 scripts/collect_feedback.py
```

### 👁️ Subtask 3.3: View and Verify Results

```bash
# 📊 View the enhanced IRM matrix
echo "=== Enhanced Intelligence Requirements Matrix ==="
python3 -c "
import json
import pandas as pd

with open('output/enhanced_irm_matrix.json', 'r') as f:
    data = json.load(f)

df = pd.DataFrame(data)
print(df[['Requirement_ID', 'Category', 'Priority', 'Frequency', 'Stakeholder']].to_string(index=False))
"

# 📂 List all generated files
echo -e "\n=== Generated Files ==="
find ~/irm-lab -name "*.json" -o -name "*.csv" -o -name "*.xlsx" -o -name "*.html" -o -name "*.md" | sort

# 📏 Display file sizes
echo -e "\n=== File Details ==="
ls -la output/ templates/ data/
```

---

## 🔍 Verification Commands

```bash
# ✅ Check if all required files exist
echo "Checking required files..."
files=("output/irm_matrix.json" "output/enhanced_irm_matrix.xlsx" "output/stakeholder_review.html" "output/review_checklist.md")

for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo "✓ $file exists"
    else
        echo "✗ $file missing"
    fi
done

# 🧪 Validate JSON files
echo -e "\nValidating JSON files..."
for json_file in $(find . -name "*.json"); do
    if python3 -m json.tool "$json_file" > /dev/null 2>&1; then
        echo "✓ $json_file is valid JSON"
    else
        echo "✗ $json_file has JSON errors"
    fi
done

# 📈 Count requirements by priority
echo -e "\nRequirement Summary:"
python3 -c "
import json
with open('output/enhanced_irm_matrix.json', 'r') as f:
    data = json.load(f)

priorities = {}
for item in data:
    p = item['Priority']
    priorities[p] = priorities.get(p, 0) + 1

for priority, count in sorted(priorities.items()):
    print(f'{priority} Priority: {count} requirements')
"
```

---

## 🗺️ MITRE ATT&CK Mapping

The IRM's intelligence categories map to the adversary lifecycle stages they help defenders anticipate and detect:

| Intelligence Category | Related ATT&CK Tactic(s) | Example Technique(s) | Why It Matters |
|---|---|---|---|
| 🦠 Threat Intelligence | Resource Development, Initial Access | T1583 (Acquire Infrastructure), T1566 (Phishing) | Early warning on malware/campaigns targeting the sector |
| 🐞 Vulnerability Intelligence | Initial Access, Execution | T1190 (Exploit Public-Facing Application), T1203 (Exploitation for Client Execution) | Prioritizes patching against actively-exploited CVEs |
| 🖥️ Asset Intelligence | Reconnaissance, Discovery | T1595 (Active Scanning), T1046 (Network Service Discovery) | Reduces unmanaged attack surface an adversary could enumerate |
| 📜 Compliance Intelligence | Defense Evasion (indirect) | N/A — regulatory driver | Keeps controls aligned with mandated safeguards |
| 🏢 Business Intelligence | Reconnaissance | T1591 (Gather Victim Org Information) | Anticipates how adversaries research the organization pre-attack |

> 📝 **TODO:** Refine this mapping using your own organization's ATT&CK Navigator layer and known adversary profiles.

---

## 🛠️ Troubleshooting

<details>
<summary>❓ <code>ModuleNotFoundError: No module named 'pandas'</code> or <code>'yaml'</code></summary>

The Python libraries weren't installed correctly, or you're using a different Python interpreter than `pip3`.

```bash
pip3 install --upgrade pandas openpyxl jinja2 pyyaml
python3 -m pip show pandas
```
</details>

<details>
<summary>❓ Excel export fails with an <code>openpyxl</code> engine error</summary>

`pandas.to_excel()` requires the `openpyxl` engine explicitly on some environments.

```bash
pip3 install --upgrade openpyxl
```

If it still fails, pass the engine explicitly in the script: `df.to_excel(path, engine='openpyxl')`.
</details>

<details>
<summary>❓ <code>FileNotFoundError</code> when running <code>create_irm.py</code> or later scripts</summary>

Each script depends on output from the previous one. Run them strictly in order from inside `~/irm-lab`:

```bash
cd ~/irm-lab
python3 scripts/define_requirements.py
python3 scripts/create_irm.py
python3 scripts/enhance_irm.py
python3 scripts/generate_review.py
python3 scripts/collect_feedback.py
```
</details>

<details>
<summary>❓ <code>output/stakeholder_review.html</code> renders with broken styling</summary>

Open the file directly in a browser rather than `cat`-ing it in the terminal — the inline `<style>` block only applies in an actual browser rendering context.

```bash
# On a desktop environment:
xdg-open output/stakeholder_review.html
```
</details>

<details>
<summary>❓ <code>json.tool</code> validation reports errors</summary>

Usually caused by editing a JSON file by hand and leaving a trailing comma or unquoted key. Re-generate the file from its source script instead of hand-editing it:

```bash
python3 -m json.tool output/enhanced_irm_matrix.json
```
</details>

---

## 🏁 Conclusion

You have successfully built a complete **Intelligence Requirements Matrix (IRM)** that:

- Defined intelligence requirements based on organizational needs across five key categories
- Developed a prioritized IRM with scoring mechanisms, collection methods, and data sources
- Created stakeholder review processes with HTML reports, checklists, and feedback templates

This IRM provides a structured approach to intelligence gathering that aligns with business objectives and enables effective resource allocation. It should be treated as a living document, reviewed and updated regularly as threats evolve and the organization changes.

### 🏆 Key Accomplishments
- ✅ Built a five-category intelligence requirements framework from scratch
- ✅ Implemented a repeatable priority-scoring algorithm (priority × frequency)
- ✅ Automated multi-format exports (JSON, CSV, Excel) for different audiences
- ✅ Generated stakeholder-specific HTML review reports and sign-off checklists
- ✅ Stood up a structured feedback-collection workflow

### 🌍 Real-World Applications
- 📌 Anchoring a CTI program's Priority Intelligence Requirements (PIRs)
- 📌 Driving SOC and threat-hunting collection priorities from business risk, not guesswork
- 📌 Giving CISOs a defensible, auditable record of *why* intelligence resources are allocated where they are
- 📌 Structuring recurring stakeholder review cycles (quarterly IRM refresh meetings)
- 📌 Feeding prioritized requirements into vendor/feed selection and budget justification

---

<div align="center">

### 🎓 Al Nafi — Practical Cybersecurity Training

![Al Nafi](https://img.shields.io/badge/Al_Nafi-Cybersecurity_Training-1976D2?style=for-the-badge)

</div>
