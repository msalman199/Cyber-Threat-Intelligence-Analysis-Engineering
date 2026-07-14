<div align="center">

# 🔥 Build Campaign Heatmaps with Kibana & ATT&CK Navigator

### Interactive Campaign Visualization & High-Risk Area Correlation

![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.11-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)
![Kibana](https://img.shields.io/badge/Kibana-Dashboards-005571?style=for-the-badge&logo=kibana&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Navigator-D6202D?style=for-the-badge&logo=mitre&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-18.x-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![Java](https://img.shields.io/badge/Java-OpenJDK%2011-437291?style=for-the-badge&logo=openjdk&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Cloud%20Lab-FCC624?style=for-the-badge&logo=linux&logoColor=black)

</div>

---

## 📖 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [✅ Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [📊 Task 1: Set Up Kibana Dashboards to Track Attack Activity](#-task-1-set-up-kibana-dashboards-to-track-attack-activity)
- [🔥 Task 2: Build Heatmaps for Campaign Data Visualization](#-task-2-build-heatmaps-for-campaign-data-visualization)
- [🗺️ Task 3: Correlate Activity to Identify High-Risk Areas](#️-task-3-correlate-activity-to-identify-high-risk-areas)
- [🧪 Verification Steps](#-verification-steps)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | Set up **Kibana** dashboards to track and visualize attack activity |
| 2 | Build interactive heatmaps for campaign data visualization |
| 3 | Use **ATT&CK Navigator** to correlate activities and identify high-risk areas |
| 4 | Analyze threat patterns using open-source intelligence tools |

## ✅ Prerequisites

| Requirement | Details |
|---|---|
| 🛡️ Cybersecurity Basics | Basic understanding of cybersecurity concepts |
| 🐧 Linux CLI | Familiarity with Linux command line |
| 🗺️ ATT&CK Fundamentals | Knowledge of MITRE ATT&CK framework fundamentals |
| 🧾 JSON | Understanding of JSON data structures |

## 🖥️ Lab Environment

> ☁️ **Al Nafi Cloud Lab** — Click **Start Lab** to spin up your dedicated Linux machine. The environment is bare metal with no pre-installed tools — every tool in this lab is installed from scratch as you go.

---

## 📊 Task 1: Set Up Kibana Dashboards to Track Attack Activity

### ☕ Subtask 1.1: Install Elasticsearch and Kibana

Install Java (required for Elasticsearch):

```bash
# ☕ Install OpenJDK 11
sudo apt update
sudo apt install -y openjdk-11-jdk
java -version
```

Download and install Elasticsearch:

```bash
# 📥 Download and install the Elasticsearch .deb package
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.11.0-amd64.deb
sudo dpkg -i elasticsearch-8.11.0-amd64.deb
```

Configure Elasticsearch for a single-node setup:

```bash
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Add these configurations:

```yaml
# ⚙️ Single-node cluster config with security disabled for lab use
cluster.name: attack-analysis
node.name: node-1
network.host: localhost
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
```

# TODO: Re-enable `xpack.security.enabled` and configure authentication before running this outside an isolated lab

Start Elasticsearch:

```bash
# ▶️ Enable and start the Elasticsearch service
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
sudo systemctl status elasticsearch
```

Download and install Kibana:

```bash
# 📥 Download and install the Kibana .deb package
wget https://artifacts.elastic.co/downloads/kibana/kibana-8.11.0-amd64.deb
sudo dpkg -i kibana-8.11.0-amd64.deb
```

Configure Kibana:

```bash
sudo nano /etc/kibana/kibana.yml
```

Add these settings:

```yaml
# ⚙️ Point Kibana at the local Elasticsearch node
server.port: 5601
server.host: "localhost"
elasticsearch.hosts: ["http://localhost:9200"]
```

Start Kibana:

```bash
# ▶️ Enable and start the Kibana service
sudo systemctl enable kibana
sudo systemctl start kibana
sudo systemctl status kibana
```

### 🗃️ Subtask 1.2: Create Sample Attack Data

Create a directory for lab data:

```bash
mkdir ~/attack-lab
cd ~/attack-lab
```

Generate sample attack data:

```bash
# 🗃️ Seed newline-delimited JSON records simulating two campaigns
cat > sample_attacks.json << 'EOF'
{"timestamp":"2024-01-15T10:30:00","technique_id":"T1566.001","technique_name":"Spearphishing Attachment","tactic":"Initial Access","severity":"high","campaign":"APT29","source_ip":"192.168.1.100","target_ip":"10.0.0.50"}
{"timestamp":"2024-01-15T10:35:00","technique_id":"T1059.001","technique_name":"PowerShell","tactic":"Execution","severity":"medium","campaign":"APT29","source_ip":"192.168.1.100","target_ip":"10.0.0.50"}
{"timestamp":"2024-01-15T10:40:00","technique_id":"T1055","technique_name":"Process Injection","tactic":"Defense Evasion","severity":"high","campaign":"APT29","source_ip":"192.168.1.100","target_ip":"10.0.0.50"}
{"timestamp":"2024-01-15T11:00:00","technique_id":"T1003.001","technique_name":"LSASS Memory","tactic":"Credential Access","severity":"critical","campaign":"APT29","source_ip":"192.168.1.100","target_ip":"10.0.0.50"}
{"timestamp":"2024-01-15T11:15:00","technique_id":"T1021.001","technique_name":"Remote Desktop Protocol","tactic":"Lateral Movement","severity":"medium","campaign":"APT29","source_ip":"192.168.1.100","target_ip":"10.0.0.51"}
{"timestamp":"2024-01-15T12:00:00","technique_id":"T1041","technique_name":"Exfiltration Over C2 Channel","tactic":"Exfiltration","severity":"critical","campaign":"APT29","source_ip":"192.168.1.100","target_ip":"10.0.0.51"}
{"timestamp":"2024-01-16T09:30:00","technique_id":"T1566.002","technique_name":"Spearphishing Link","tactic":"Initial Access","severity":"high","campaign":"Lazarus","source_ip":"203.0.113.50","target_ip":"10.0.0.75"}
{"timestamp":"2024-01-16T09:45:00","technique_id":"T1204.002","technique_name":"Malicious File","tactic":"Execution","severity":"high","campaign":"Lazarus","source_ip":"203.0.113.50","target_ip":"10.0.0.75"}
{"timestamp":"2024-01-16T10:00:00","technique_id":"T1112","technique_name":"Modify Registry","tactic":"Defense Evasion","severity":"medium","campaign":"Lazarus","source_ip":"203.0.113.50","target_ip":"10.0.0.75"}
{"timestamp":"2024-01-16T10:30:00","technique_id":"T1083","technique_name":"File and Directory Discovery","tactic":"Discovery","severity":"low","campaign":"Lazarus","source_ip":"203.0.113.50","target_ip":"10.0.0.75"}
EOF
```

# TODO: Replace this sample dataset with real EDR/SIEM export data mapped to ATT&CK technique IDs

### 📥 Subtask 1.3: Index Data into Elasticsearch

Install curl for API interactions:

```bash
sudo apt install -y curl
```

Create an index mapping:

```bash
# 🗂️ Define explicit field types for the attack-data index
curl -X PUT "localhost:9200/attack-data" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "timestamp": {"type": "date"},
      "technique_id": {"type": "keyword"},
      "technique_name": {"type": "text"},
      "tactic": {"type": "keyword"},
      "severity": {"type": "keyword"},
      "campaign": {"type": "keyword"},
      "source_ip": {"type": "ip"},
      "target_ip": {"type": "ip"}
    }
  }
}'
```

Index the sample data:

```bash
# 📤 Push each JSON line into the attack-data index
while IFS= read -r line; do
  curl -X POST "localhost:9200/attack-data/_doc" -H 'Content-Type: application/json' -d "$line"
done < sample_attacks.json
```

Verify data indexing:

```bash
# ✅ Confirm documents were indexed successfully
curl -X GET "localhost:9200/attack-data/_search?pretty"
```

---

## 🔥 Task 2: Build Heatmaps for Campaign Data Visualization

### 🗂️ Subtask 2.1: Access Kibana and Create Index Pattern

Wait for Kibana to fully start (may take 2–3 minutes):

```bash
# ⏱️ Poll until Kibana responds
curl -I http://localhost:5601
```

> 🌐 Open a web browser and navigate to `http://localhost:5601`

Create an index pattern:

1. Click **Stack Management → Index Patterns**
2. Click **Create index pattern**
3. Enter `attack-data*` as the index pattern
4. Click **Next step**
5. Select `timestamp` as the time field
6. Click **Create index pattern**

### 📈 Subtask 2.2: Create Campaign Activity Dashboard

Navigate to **Dashboard** and click **Create dashboard**.

Add a **Data Table** visualization:

1. Click **Create visualization**
2. Select **Data table**
3. Configure:
   - Rows: Add `campaign.keyword`
   - Rows: Add `tactic.keyword`
   - Metrics: Count
4. Save as **"Campaign Tactics Overview"**

Add a **Heat Map** visualization:

1. Click **Create visualization**
2. Select **Heat map**
3. Configure:
   - Y-axis: `campaign.keyword`
   - X-axis: `tactic.keyword`
   - Value: Count of records
4. Save as **"Campaign-Tactic Heatmap"**

### 🌡️ Subtask 2.3: Create Technique Frequency Heatmap

Create another heatmap:

1. Click **Create visualization**
2. Select **Heat map**
3. Configure:
   - Y-axis: `technique_name.keyword`
   - X-axis: `severity.keyword`
   - Value: Count
   - Apply color scheme: Red for high values
4. Save as **"Technique Severity Heatmap"**

Add a timeline visualization:

1. Click **Create visualization**
2. Select **Line**
3. Configure:
   - X-axis: `timestamp` (Date Histogram, Interval: Hour)
   - Y-axis: Count
   - Split series: `campaign.keyword`
4. Save as **"Campaign Timeline"**

# TODO: Add a saved search filter for `severity: critical` to make the timeline easier to triage at a glance

---

## 🗺️ Task 3: Correlate Activity to Identify High-Risk Areas

### 📦 Subtask 3.1: Install ATT&CK Navigator

Install Node.js and npm:

```bash
# 🟢 Install Node.js 18.x and npm
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
node --version
npm --version
```

Clone ATT&CK Navigator:

```bash
# 📥 Clone the Navigator app
cd ~/attack-lab
git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator/nav-app
```

Install dependencies and build:

```bash
# 🔨 Install dependencies and build the Navigator
npm install
npm run build
```

Start the Navigator:

```bash
# ▶️ Launch the Navigator dev server in the background
npm start &
```

### 🧮 Subtask 3.2: Generate ATT&CK Layer from Kibana Data

Create a script to export Kibana data:

```bash
cd ~/attack-lab
```

```python
#!/usr/bin/env python3
# 🧮 Turn indexed technique frequency into an ATT&CK Navigator layer file
import json
import requests
from collections import defaultdict

# 🔍 Query Elasticsearch for attack data
response = requests.get('http://localhost:9200/attack-data/_search?size=1000')
data = response.json()

# 🧮 Process data for ATT&CK Navigator
techniques = defaultdict(int)
for hit in data['hits']['hits']:
    source = hit['_source']
    technique_id = source.get('technique_id', '')
    if technique_id:
        techniques[technique_id] += 1

# 🗺️ Create ATT&CK Navigator layer
layer = {
    "name": "Campaign Analysis",
    "versions": {
        "attack": "14",
        "navigator": "4.9.1",
        "layer": "4.5"
    },
    "domain": "enterprise-attack",
    "description": "Heatmap showing technique frequency from campaign data",
    "techniques": []
}

# ➕ Add techniques with scores
for technique_id, count in techniques.items():
    layer["techniques"].append({
        "techniqueID": technique_id,
        "score": min(count * 20, 100),  # Scale score (max 100)
        "color": "",
        "comment": f"Observed {count} times",
        "enabled": True,
        "metadata": [],
        "links": [],
        "showSubtechniques": False
    })

# 💾 Save layer file
with open('campaign_layer.json', 'w') as f:
    json.dump(layer, f, indent=2)

print(f"Created ATT&CK layer with {len(techniques)} techniques")
print("Layer saved as campaign_layer.json")
```

```bash
chmod +x export_attack_data.py
```

Install the Python requests library and run the script:

```bash
sudo apt install -y python3-pip
pip3 install requests
python3 export_attack_data.py
```

# TODO: Replace the linear `count * 20` scoring formula with a weighting that also accounts for severity

### ⚠️ Subtask 3.3: Analyze High-Risk Areas

View the generated layer file:

```bash
cat campaign_layer.json
```

Create a risk analysis script:

```python
#!/usr/bin/env python3
# ⚠️ Compute a weighted risk score from severity distribution across campaigns
import json
import requests
from collections import Counter

# 🔍 Get data from Elasticsearch
response = requests.get('http://localhost:9200/attack-data/_search?size=1000')
data = response.json()

# 📊 Analyze risk patterns
campaigns = Counter()
tactics = Counter()
severity_counts = Counter()
high_risk_techniques = []

for hit in data['hits']['hits']:
    source = hit['_source']
    campaigns[source.get('campaign', 'Unknown')] += 1
    tactics[source.get('tactic', 'Unknown')] += 1
    severity_counts[source.get('severity', 'Unknown')] += 1

    if source.get('severity') in ['high', 'critical']:
        high_risk_techniques.append({
            'technique': source.get('technique_name', 'Unknown'),
            'campaign': source.get('campaign', 'Unknown'),
            'tactic': source.get('tactic', 'Unknown')
        })

print("=== RISK ANALYSIS REPORT ===")
print(f"\nTop Campaigns by Activity:")
for campaign, count in campaigns.most_common():
    print(f"  {campaign}: {count} activities")

print(f"\nMost Active Tactics:")
for tactic, count in tactics.most_common():
    print(f"  {tactic}: {count} techniques")

print(f"\nSeverity Distribution:")
for severity, count in severity_counts.most_common():
    print(f"  {severity}: {count} incidents")

print(f"\nHigh-Risk Techniques ({len(high_risk_techniques)} total):")
for technique in high_risk_techniques[:5]:  # Show top 5
    print(f"  {technique['technique']} ({technique['campaign']}) - {technique['tactic']}")

# 🧮 Calculate risk score
critical_count = severity_counts.get('critical', 0)
high_count = severity_counts.get('high', 0)
total_incidents = sum(severity_counts.values())
risk_score = ((critical_count * 3) + (high_count * 2)) / total_incidents * 100

print(f"\nOverall Risk Score: {risk_score:.1f}/100")
if risk_score > 70:
    print("⚠️  HIGH RISK - Immediate attention required")
elif risk_score > 40:
    print("⚠️  MEDIUM RISK - Monitor closely")
else:
    print("✓ LOW RISK - Continue monitoring")
```

```bash
python3 risk_analysis.py
```

# TODO: Guard against a `ZeroDivisionError` when `total_incidents` is 0 (e.g. an empty index)

### 📊 Subtask 3.4: Create Correlation Dashboard

Return to Kibana and create a correlation dashboard:

1. Navigate to **Dashboard → Create dashboard**
2. Add visualizations:
   - Metric: Total incidents count
   - Pie chart: Severity distribution
   - Bar chart: Top techniques by campaign
   - Tag cloud: Most frequent technique names
3. Configure a **Controls** visualization:
   - Add **Options list** control for `campaign.keyword`
   - Add **Range slider** for `timestamp`
4. Save dashboard as **"Campaign Correlation Analysis"**
5. Create alerts by adding a **Threshold** visualization:
   - Set threshold for critical severity > 2 incidents
   - Configure red color for threshold breach
6. Save as **"Critical Alert Monitor"**

---

## 🧪 Verification Steps

Verify your setup by checking:

```bash
# 🩺 Elasticsearch status
curl -X GET "localhost:9200/_cluster/health?pretty"
```

```bash
# 🌐 Kibana accessibility
curl -I http://localhost:5601
```

```bash
# 🔢 Data indexing count
curl -X GET "localhost:9200/attack-data/_count?pretty"
```

> 🗺️ **ATT&CK Navigator:** Navigate to `http://localhost:4200` and load the generated `campaign_layer.json` file.

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Campaign Observed |
|---|---|---|---|
| T1566.001 | Spearphishing Attachment | Initial Access | APT29 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | APT29 |
| T1055 | Process Injection | Defense Evasion | APT29 |
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access | APT29 |
| T1021.001 | Remote Services: Remote Desktop Protocol | Lateral Movement | APT29 |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | APT29 |
| T1566.002 | Spearphishing Link | Initial Access | Lazarus |
| T1204.002 | User Execution: Malicious File | Execution | Lazarus |
| T1112 | Modify Registry | Defense Evasion | Lazarus |
| T1083 | File and Directory Discovery | Discovery | Lazarus |

---

## 🛠️ Troubleshooting

<details>
<summary>❌ Elasticsearch fails to start or <code>systemctl status elasticsearch</code> shows failed</summary>

Check available memory — Elasticsearch's default heap size can exceed small lab VMs. Review `/var/log/elasticsearch/attack-analysis.log` for JVM heap or permission errors.
</details>

<details>
<summary>❌ Kibana shows "Kibana server is not ready yet"</summary>

Kibana can take 2–3 minutes to fully initialize after `systemctl start kibana`. Re-run `curl -I http://localhost:5601` after waiting, and confirm Elasticsearch is healthy first with the cluster health check.
</details>

<details>
<summary>❌ Heat map visualization shows no data in Kibana</summary>

Confirm the index pattern `attack-data*` was created with `timestamp` as the time field, and that the dashboard's time range picker covers `2024-01-15` to `2024-01-16` — the sample data's dates are fixed, not relative to today.
</details>

<details>
<summary>❌ ATT&CK Navigator build fails or `npm start` doesn't serve on port 4200</summary>

Confirm Node.js 18.x installed correctly with `node --version`, re-run `npm install` inside `attack-navigator/nav-app` if `npm run build` failed partway, and check for port conflicts with `sudo lsof -i :4200`.
</details>

---

## 🏁 Conclusion

### ✅ Key Accomplishments

- 📊 Set up Elasticsearch and Kibana for security data analysis
- 🔥 Created interactive heatmaps to visualize attack patterns
- 🗺️ Used ATT&CK Navigator to map techniques to the MITRE framework
- 🧩 Correlated activities across campaigns to identify high-risk areas
- ⚠️ Generated automated risk assessments and alerts

### 🌍 Real-World Applications

This approach enables security analysts to quickly identify threat patterns, prioritize response efforts, and understand the scope of ongoing campaigns. The combination of Kibana's visualization capabilities with ATT&CK Navigator's framework mapping provides a powerful platform for threat intelligence analysis and incident response planning.

---

<div align="center">

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cybersecurity%20Training-1E90FF?style=for-the-badge)

</div>
