<div align="center">

# 🧬 Cluster Intrusions into Activity Groups with ATT&CK + ThreatHunter Playbook

### Machine-Learning-Assisted Activity Group Clustering & Attack Path Mapping

![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Navigator-D6202D?style=for-the-badge&logo=mitre&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![scikit--learn](https://img.shields.io/badge/scikit--learn-Clustering-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)
![NetworkX](https://img.shields.io/badge/NetworkX-Graph%20Analysis-FF6F00?style=for-the-badge&logo=graphql&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-Data%20Analysis-150458?style=for-the-badge&logo=pandas&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-18.x-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Cloud%20Lab-FCC624?style=for-the-badge&logo=linux&logoColor=black)

</div>

---

## 📖 Table of Contents

- [🎯 Learning Objectives](#-learning-objectives)
- [✅ Prerequisites](#-prerequisites)
- [🖥️ Lab Environment](#️-lab-environment)
- [🧰 Task 1: Set Up Analysis Environment and Install Tools](#-task-1-set-up-analysis-environment-and-install-tools)
- [🧩 Task 2: Apply ATT&CK Techniques to Cluster Intrusion Sets](#-task-2-apply-attck-techniques-to-cluster-intrusion-sets)
- [📓 Task 3: Use ThreatHunter Playbook for Incident Tracking](#-task-3-use-threathunter-playbook-for-incident-tracking)
- [🗺️ Task 4: Map Attack Paths and Group Activities](#️-task-4-map-attack-paths-and-group-activities)
- [🧪 Verification and Results](#-verification-and-results)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🏁 Conclusion](#-conclusion)

---

## 🎯 Learning Objectives

| # | Objective |
|---|-----------|
| 1 | Apply the **MITRE ATT&CK** framework to cluster related intrusion activities |
| 2 | Use **ThreatHunter Playbook** methodology for systematic incident tracking |
| 3 | Map attack paths and group activities using open-source tools |
| 4 | Analyze threat intelligence data to identify activity group patterns |

## ✅ Prerequisites

| Requirement | Details |
|---|---|
| 🛡️ Cybersecurity Basics | Basic understanding of cybersecurity concepts |
| 🐧 Linux CLI | Familiarity with Linux command line |
| 📡 Protocols & Logs | Knowledge of network protocols and log analysis |
| 🧠 Threat Intel Fundamentals | Understanding of threat intelligence fundamentals |

## 🖥️ Lab Environment

> ☁️ **Al Nafi Cloud Lab** — Click **Start Lab** to spin up your dedicated Linux machine. The environment is bare metal with no pre-installed tools — every tool in this lab is installed from scratch as you go.

---

## 🧰 Task 1: Set Up Analysis Environment and Install Tools

### 📦 Subtask 1.1: Update System and Install Dependencies

```bash
# 🔄 Update system packages
sudo apt update && sudo apt upgrade -y

# 🧰 Install required dependencies
sudo apt install -y python3 python3-pip git curl wget jq unzip
sudo apt install -y build-essential libssl-dev libffi-dev python3-dev

# 📊 Install additional analysis tools
sudo apt install -y sqlite3 graphviz
```

### 🗺️ Subtask 1.2: Install MITRE ATT&CK Navigator

```bash
# 📥 Clone ATT&CK Navigator
cd /opt
sudo git clone https://github.com/mitre-attack/attack-navigator.git
cd attack-navigator

# 🟢 Install Node.js and npm
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# 📦 Install Navigator dependencies
sudo npm install
sudo npm run build
```

# TODO: Confirm the Node.js 18.x setup script URL still matches the LTS release you intend to install

### 📓 Subtask 1.3: Set Up ThreatHunter Playbook Environment

```bash
# 🗂️ Create working directory
mkdir -p ~/threat-analysis
cd ~/threat-analysis

# 🐍 Install Python libraries for threat analysis
pip3 install pandas numpy matplotlib seaborn networkx
pip3 install requests beautifulsoup4 python-dateutil
pip3 install stix2 taxii2-client

# 📥 Download sample threat intelligence data
wget https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

---

## 🧩 Task 2: Apply ATT&CK Techniques to Cluster Intrusion Sets

### 🗃️ Subtask 2.1: Create Sample Intrusion Data

```bash
# 🗃️ Build a sample dataset of intrusions with observed techniques and indicators
cat > ~/threat-analysis/intrusion_data.json << 'EOF'
{
  "intrusions": [
    {
      "id": "INT001",
      "timestamp": "2024-01-15T10:30:00Z",
      "techniques": ["T1566.001", "T1059.001", "T1055", "T1083"],
      "indicators": ["malicious.exe", "192.168.1.100", "suspicious.dll"],
      "target_sector": "financial"
    },
    {
      "id": "INT002", 
      "timestamp": "2024-01-16T14:20:00Z",
      "techniques": ["T1566.001", "T1059.003", "T1055", "T1070.004"],
      "indicators": ["phish.doc", "192.168.1.100", "cleanup.bat"],
      "target_sector": "financial"
    },
    {
      "id": "INT003",
      "timestamp": "2024-01-18T09:15:00Z", 
      "techniques": ["T1190", "T1505.003", "T1083", "T1041"],
      "indicators": ["webshell.php", "10.0.0.50", "data.zip"],
      "target_sector": "healthcare"
    },
    {
      "id": "INT004",
      "timestamp": "2024-01-20T16:45:00Z",
      "techniques": ["T1566.002", "T1059.001", "T1055", "T1083"],
      "indicators": ["malware.exe", "192.168.1.100", "recon.dll"],
      "target_sector": "financial"
    }
  ]
}
EOF
```

# TODO: Swap this sample dataset for real intrusion telemetry from your SIEM/EDR once the pipeline is validated

### 🧮 Subtask 2.2: Create Clustering Analysis Script

```python
#!/usr/bin/env python3
# 🧮 Vectorize ATT&CK techniques per intrusion and cluster with K-means
import json
import pandas as pd
from collections import Counter
import numpy as np
from sklearn.cluster import KMeans
from sklearn.feature_extraction.text import TfidfVectorizer
import matplotlib.pyplot as plt

def load_intrusion_data(file_path):
    """Load intrusion data from JSON file"""
    with open(file_path, 'r') as f:
        data = json.load(f)
    return pd.DataFrame(data['intrusions'])

def create_technique_features(df):
    """Create feature vectors based on ATT&CK techniques"""
    # 🔤 Convert techniques list to string for vectorization
    df['technique_string'] = df['techniques'].apply(lambda x: ' '.join(x))

    # 📊 Create TF-IDF vectors for techniques
    vectorizer = TfidfVectorizer()
    technique_vectors = vectorizer.fit_transform(df['technique_string'])

    return technique_vectors, vectorizer

def cluster_intrusions(df, n_clusters=2):
    """Cluster intrusions based on technique similarity"""
    technique_vectors, vectorizer = create_technique_features(df)

    # 🧠 Apply K-means clustering
    kmeans = KMeans(n_clusters=n_clusters, random_state=42)
    clusters = kmeans.fit_predict(technique_vectors.toarray())

    df['cluster'] = clusters
    return df, kmeans, vectorizer

def analyze_clusters(df):
    """Analyze cluster characteristics"""
    print("=== CLUSTER ANALYSIS RESULTS ===\n")

    for cluster_id in df['cluster'].unique():
        cluster_data = df[df['cluster'] == cluster_id]
        print(f"CLUSTER {cluster_id}:")
        print(f"  Intrusions: {len(cluster_data)}")

        # 🔝 Most common techniques
        all_techniques = []
        for techniques in cluster_data['techniques']:
            all_techniques.extend(techniques)
        common_techniques = Counter(all_techniques).most_common(3)
        print(f"  Top Techniques: {common_techniques}")

        # 🏭 Target sectors
        sectors = cluster_data['target_sector'].value_counts()
        print(f"  Target Sectors: {sectors.to_dict()}")

        # 🔍 Common indicators
        all_indicators = []
        for indicators in cluster_data['indicators']:
            all_indicators.extend(indicators)
        common_indicators = Counter(all_indicators).most_common(3)
        print(f"  Common Indicators: {common_indicators}")
        print()

def main():
    # 📂 Load and analyze data
    df = load_intrusion_data('intrusion_data.json')
    print(f"Loaded {len(df)} intrusion records\n")

    # 🧮 Perform clustering
    clustered_df, kmeans, vectorizer = cluster_intrusions(df)

    # 📊 Analyze results
    analyze_clusters(clustered_df)

    # 💾 Save results
    clustered_df.to_csv('clustered_intrusions.csv', index=False)
    print("Results saved to clustered_intrusions.csv")

if __name__ == "__main__":
    main()
```

```bash
chmod +x ~/threat-analysis/cluster_analysis.py
```

# TODO: Make `n_clusters` a CLI argument instead of the hardcoded default of 2

### ▶️ Subtask 2.3: Run Clustering Analysis

```bash
cd ~/threat-analysis

# 📦 Install required Python packages
pip3 install scikit-learn

# 🧮 Run clustering analysis
python3 cluster_analysis.py
```

---

## 📓 Task 3: Use ThreatHunter Playbook for Incident Tracking

### 🗂️ Subtask 3.1: Create ThreatHunter Playbook Structure

```bash
# 🗂️ Create playbook directory structure
mkdir -p ~/threat-analysis/playbooks/{templates,active,completed}

# 📝 Create playbook template
cat > ~/threat-analysis/playbooks/templates/activity_group_template.json << 'EOF'
{
  "playbook_id": "",
  "activity_group": "",
  "creation_date": "",
  "status": "active",
  "hypothesis": "",
  "techniques_observed": [],
  "indicators": [],
  "timeline": [],
  "evidence": [],
  "conclusions": "",
  "confidence_level": "",
  "next_actions": []
}
EOF
```

### 📘 Subtask 3.2: Create Playbook Management Script

```python
#!/usr/bin/env python3
# 📘 Create, update, and list ThreatHunter-style activity group playbooks
import json
import os
from datetime import datetime
import uuid

class ThreatHunterPlaybook:
    def __init__(self, base_dir="playbooks"):
        self.base_dir = base_dir
        self.template_dir = os.path.join(base_dir, "templates")
        self.active_dir = os.path.join(base_dir, "active")
        self.completed_dir = os.path.join(base_dir, "completed")

    def create_playbook(self, activity_group, hypothesis, techniques):
        """Create new threat hunting playbook"""
        playbook_id = str(uuid.uuid4())[:8]

        # 📄 Load template
        with open(os.path.join(self.template_dir, "activity_group_template.json"), 'r') as f:
            playbook = json.load(f)

        # ✏️ Fill template
        playbook.update({
            "playbook_id": playbook_id,
            "activity_group": activity_group,
            "creation_date": datetime.now().isoformat(),
            "hypothesis": hypothesis,
            "techniques_observed": techniques
        })

        # 💾 Save active playbook
        filename = f"{activity_group}_{playbook_id}.json"
        filepath = os.path.join(self.active_dir, filename)

        with open(filepath, 'w') as f:
            json.dump(playbook, f, indent=2)

        print(f"Created playbook: {filename}")
        return playbook_id

    def update_playbook(self, playbook_id, updates):
        """Update existing playbook"""
        # 🔍 Find playbook file
        for filename in os.listdir(self.active_dir):
            if playbook_id in filename:
                filepath = os.path.join(self.active_dir, filename)

                with open(filepath, 'r') as f:
                    playbook = json.load(f)

                playbook.update(updates)

                with open(filepath, 'w') as f:
                    json.dump(playbook, f, indent=2)

                print(f"Updated playbook: {filename}")
                return True

        print(f"Playbook {playbook_id} not found")
        return False

    def list_active_playbooks(self):
        """List all active playbooks"""
        print("=== ACTIVE THREAT HUNTING PLAYBOOKS ===\n")

        for filename in os.listdir(self.active_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.active_dir, filename)

                with open(filepath, 'r') as f:
                    playbook = json.load(f)

                print(f"ID: {playbook['playbook_id']}")
                print(f"Group: {playbook['activity_group']}")
                print(f"Status: {playbook['status']}")
                print(f"Hypothesis: {playbook['hypothesis']}")
                print(f"Techniques: {', '.join(playbook['techniques_observed'])}")
                print("-" * 50)

def main():
    # 🚀 Initialize playbook manager
    pb_manager = ThreatHunterPlaybook()

    # 📓 Create playbooks based on clustering results
    print("Creating threat hunting playbooks...\n")

    # 🏦 Cluster 0 - Financial sector attacks
    pb_id1 = pb_manager.create_playbook(
        activity_group="APT-Financial-001",
        hypothesis="Coordinated spear-phishing campaign targeting financial institutions",
        techniques=["T1566.001", "T1059.001", "T1055", "T1083"]
    )

    # 🌐 Cluster 1 - Web-based attacks
    pb_id2 = pb_manager.create_playbook(
        activity_group="WebShell-Group-001", 
        hypothesis="Web application exploitation for persistent access",
        techniques=["T1190", "T1505.003", "T1083", "T1041"]
    )

    # ➕ Update playbooks with additional evidence
    pb_manager.update_playbook(pb_id1, {
        "indicators": ["192.168.1.100", "malicious.exe", "suspicious.dll"],
        "confidence_level": "Medium",
        "evidence": ["Multiple intrusions from same IP", "Similar malware families"]
    })

    pb_manager.update_playbook(pb_id2, {
        "indicators": ["10.0.0.50", "webshell.php", "data.zip"],
        "confidence_level": "High", 
        "evidence": ["Web shell deployment", "Data exfiltration patterns"]
    })

    # 📋 List all active playbooks
    pb_manager.list_active_playbooks()

if __name__ == "__main__":
    main()
```

```bash
chmod +x ~/threat-analysis/playbook_manager.py
```

### ▶️ Subtask 3.3: Execute Playbook Management

```bash
cd ~/threat-analysis

# 📓 Run playbook manager
python3 playbook_manager.py
```

# TODO: Add a `close_playbook()` method that moves a finished playbook from `active/` to `completed/`

---

## 🗺️ Task 4: Map Attack Paths and Group Activities

### 🕸️ Subtask 4.1: Create Attack Path Visualization

```python
#!/usr/bin/env python3
# 🕸️ Build a directed graph of technique sequences per activity group
import json
import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict

def load_attack_data():
    """Load ATT&CK technique data"""
    attack_techniques = {
        "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access"},
        "T1566.002": {"name": "Spearphishing Link", "tactic": "Initial Access"},
        "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
        "T1059.003": {"name": "Windows Command Shell", "tactic": "Execution"},
        "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
        "T1505.003": {"name": "Web Shell", "tactic": "Persistence"},
        "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
        "T1070.004": {"name": "File Deletion", "tactic": "Defense Evasion"},
        "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"}
    }
    return attack_techniques

def create_attack_graph(intrusion_data, attack_techniques):
    """Create attack path graph"""
    G = nx.DiGraph()

    # 📂 Load intrusion data
    with open(intrusion_data, 'r') as f:
        data = json.load(f)

    # 🗂️ Group techniques by cluster
    cluster_techniques = defaultdict(list)

    # 📄 Read clustered results
    import pandas as pd
    df = pd.read_csv('clustered_intrusions.csv')

    for _, row in df.iterrows():
        cluster = row['cluster']
        techniques = eval(row['techniques'])  # Convert string back to list
        cluster_techniques[cluster].extend(techniques)

    # 🎨 Create nodes and edges for each cluster
    colors = ['lightblue', 'lightcoral', 'lightgreen', 'lightyellow']

    for cluster_id, techniques in cluster_techniques.items():
        # 🧹 Remove duplicates and sort by typical attack sequence
        unique_techniques = list(set(techniques))

        # ➕ Add nodes
        for technique in unique_techniques:
            if technique in attack_techniques:
                G.add_node(technique, 
                          name=attack_techniques[technique]['name'],
                          tactic=attack_techniques[technique]['tactic'],
                          cluster=cluster_id,
                          color=colors[cluster_id % len(colors)])

        # ➕ Add edges based on typical attack flow
        for i in range(len(unique_techniques) - 1):
            if unique_techniques[i] in attack_techniques and unique_techniques[i+1] in attack_techniques:
                G.add_edge(unique_techniques[i], unique_techniques[i+1])

    return G

def visualize_attack_paths(G):
    """Visualize attack paths"""
    plt.figure(figsize=(15, 10))

    # 📍 Create layout
    pos = nx.spring_layout(G, k=3, iterations=50)

    # 🎨 Get node colors by cluster
    node_colors = [G.nodes[node].get('color', 'lightgray') for node in G.nodes()]

    # 🖼️ Draw graph
    nx.draw(G, pos, 
            node_color=node_colors,
            node_size=2000,
            font_size=8,
            font_weight='bold',
            arrows=True,
            arrowsize=20,
            edge_color='gray',
            with_labels=True)

    # 🔤 Add technique names as labels
    labels = {node: f"{node}\n{G.nodes[node].get('name', '')[:20]}" 
              for node in G.nodes()}

    plt.title("Attack Path Mapping by Activity Groups", fontsize=16, fontweight='bold')
    plt.axis('off')
    plt.tight_layout()
    plt.savefig('attack_paths.png', dpi=300, bbox_inches='tight')
    plt.show()

    print("Attack path visualization saved as 'attack_paths.png'")

def generate_attack_report(G):
    """Generate attack path analysis report"""
    print("=== ATTACK PATH ANALYSIS REPORT ===\n")

    # 🗂️ Cluster analysis
    clusters = defaultdict(list)
    for node in G.nodes():
        cluster = G.nodes[node].get('cluster', 'unknown')
        clusters[cluster].append(node)

    for cluster_id, techniques in clusters.items():
        print(f"ACTIVITY GROUP {cluster_id}:")
        print(f"  Techniques Used: {len(techniques)}")

        # 🧭 Group by tactic
        tactics = defaultdict(list)
        for technique in techniques:
            tactic = G.nodes[technique].get('tactic', 'Unknown')
            tactics[tactic].append(technique)

        print("  Tactics Coverage:")
        for tactic, techs in tactics.items():
            print(f"    {tactic}: {len(techs)} techniques")

        # 🎯 Calculate centrality
        subgraph = G.subgraph(techniques)
        if len(subgraph.nodes()) > 1:
            centrality = nx.degree_centrality(subgraph)
            most_central = max(centrality, key=centrality.get)
            print(f"  Key Technique: {most_central} ({G.nodes[most_central]['name']})")

        print()

def main():
    # 📂 Load attack technique data
    attack_techniques = load_attack_data()

    # 🕸️ Create attack graph
    G = create_attack_graph('intrusion_data.json', attack_techniques)

    # 📊 Generate analysis report
    generate_attack_report(G)

    # 🖼️ Create visualization
    visualize_attack_paths(G)

if __name__ == "__main__":
    main()
```

```bash
chmod +x ~/threat-analysis/attack_path_mapper.py
```

# TODO: Replace the naive sequential-edge assumption with actual observed technique ordering from the intrusion timeline

### ▶️ Subtask 4.2: Execute Attack Path Analysis

```bash
cd ~/threat-analysis

# 📦 Install additional visualization libraries
pip3 install networkx matplotlib

# 🕸️ Run attack path mapping
python3 attack_path_mapper.py
```

### 📋 Subtask 4.3: Create Activity Group Summary

```python
#!/usr/bin/env python3
# 📋 Roll clustering + attack path results into a final analyst-facing summary
import json
import pandas as pd
from datetime import datetime

def generate_activity_group_summary():
    """Generate comprehensive activity group analysis summary"""

    print("=" * 60)
    print("THREAT INTELLIGENCE ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # 📂 Load clustered data
    df = pd.read_csv('clustered_intrusions.csv')

    print("IDENTIFIED ACTIVITY GROUPS:")
    print("-" * 30)

    for cluster in df['cluster'].unique():
        cluster_data = df[df['cluster'] == cluster]

        print(f"\nActivity Group {cluster}:")
        print(f"  Intrusion Count: {len(cluster_data)}")
        print(f"  Time Range: {cluster_data['timestamp'].min()} to {cluster_data['timestamp'].max()}")

        # 🔍 Extract unique techniques
        all_techniques = []
        for techniques_str in cluster_data['techniques']:
            techniques = eval(techniques_str)
            all_techniques.extend(techniques)
        unique_techniques = list(set(all_techniques))

        print(f"  Unique Techniques: {len(unique_techniques)}")
        print(f"  Technique List: {', '.join(unique_techniques)}")

        # 🎯 Target analysis
        targets = cluster_data['target_sector'].value_counts()
        print(f"  Primary Targets: {targets.to_dict()}")

        # ⚠️ Threat level assessment
        if len(cluster_data) >= 3 and len(unique_techniques) >= 4:
            threat_level = "HIGH"
        elif len(cluster_data) >= 2:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        print(f"  Threat Level: {threat_level}")

    print("\n" + "=" * 60)
    print("RECOMMENDATIONS:")
    print("=" * 60)
    print("1. Implement monitoring for identified techniques")
    print("2. Enhance detection rules for clustered activity patterns")
    print("3. Share IOCs with threat intelligence community")
    print("4. Update incident response playbooks")
    print("5. Conduct threat hunting based on identified patterns")

if __name__ == "__main__":
    generate_activity_group_summary()
```

```bash
python3 ~/threat-analysis/generate_summary.py
```

# TODO: Replace the fixed thresholds in the threat-level assessment (`>= 3`, `>= 4`) with values tuned to your own intrusion set size

---

## 🧪 Verification and Results

### 👀 View Analysis Results

```bash
cd ~/threat-analysis

# 📁 List all generated files
echo "=== GENERATED ANALYSIS FILES ==="
ls -la *.csv *.png *.json

# 📓 View playbook structure
echo -e "\n=== ACTIVE PLAYBOOKS ==="
ls -la playbooks/active/

# 📊 Display final summary
echo -e "\n=== FINAL ANALYSIS ==="
python3 generate_summary.py
```

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Activity Group Observed |
|---|---|---|---|
| T1566.001 | Spearphishing Attachment | Initial Access | APT-Financial-001 |
| T1566.002 | Spearphishing Link | Initial Access | APT-Financial-001 |
| T1190 | Exploit Public-Facing Application | Initial Access | WebShell-Group-001 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | APT-Financial-001 |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Execution | APT-Financial-001 |
| T1055 | Process Injection | Defense Evasion | APT-Financial-001 |
| T1070.004 | Indicator Removal: File Deletion | Defense Evasion | APT-Financial-001 |
| T1505.003 | Server Software Component: Web Shell | Persistence | WebShell-Group-001 |
| T1083 | File and Directory Discovery | Discovery | Both activity groups |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | WebShell-Group-001 |

---

## 🛠️ Troubleshooting

<details>
<summary>❌ ATT&CK Navigator fails to build (<code>npm run build</code> errors)</summary>

Confirm Node.js 18.x installed correctly with `node --version`, and re-run `sudo npm install` before `sudo npm run build` if dependencies were only partially installed.
</details>

<details>
<summary>❌ <code>cluster_analysis.py</code> fails with a scikit-learn import error</summary>

Ensure `scikit-learn` was installed in Subtask 2.3 — it's a separate install from the Subtask 1.3 package list:

```bash
pip3 install scikit-learn
```
</details>

<details>
<summary>❌ <code>attack_path_mapper.py</code> errors on <code>eval(row['techniques'])</code></summary>

This expects `clustered_intrusions.csv` from `cluster_analysis.py` to exist first — run Task 2 before Task 4, and confirm the `techniques` column still contains Python list syntax (e.g. `['T1566.001', 'T1059.001']`) rather than a reformatted string.
</details>

<details>
<summary>❌ Matplotlib visualization window doesn't display in a headless lab environment</summary>

`plt.show()` requires a display backend. If running over SSH without X11 forwarding, rely on the saved `attack_paths.png` file instead — it's written before the `plt.show()` call.
</details>

---

## 🏁 Conclusion

### ✅ Key Accomplishments

- 🧮 Clustered intrusion activities using MITRE ATT&CK techniques and machine learning algorithms
- 📓 Implemented ThreatHunter Playbook methodology for systematic incident tracking and analysis
- 🕸️ Mapped attack paths and visualized activity group behaviors using network analysis
- 📊 Generated comprehensive threat intelligence reports linking related intrusions to activity groups

### 🌍 Real-World Applications

This approach enables security analysts to identify patterns in threat actor behavior, improve detection capabilities, and develop targeted defense strategies. The combination of ATT&CK framework mapping and systematic playbook methodology provides a structured approach to threat intelligence analysis that scales across enterprise environments. The skills developed in this lab are essential for threat intelligence analysts, security researchers, and incident response teams working to understand and counter advanced persistent threats.

---

<div align="center">

![Al Nafi](https://img.shields.io/badge/Al%20Nafi-Cybersecurity%20Training-1E90FF?style=for-the-badge)

</div>
