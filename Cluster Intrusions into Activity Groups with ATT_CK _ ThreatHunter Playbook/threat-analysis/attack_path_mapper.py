#!/usr/bin/env python3
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
    
    # Load intrusion data
    with open(intrusion_data, 'r') as f:
        data = json.load(f)
    
    # Group techniques by cluster
    cluster_techniques = defaultdict(list)
    
    # Read clustered results
    import pandas as pd
    df = pd.read_csv('clustered_intrusions.csv')
    
    for _, row in df.iterrows():
        cluster = row['cluster']
        techniques = eval(row['techniques'])  # Convert string back to list
        cluster_techniques[cluster].extend(techniques)
    
    # Create nodes and edges for each cluster
    colors = ['lightblue', 'lightcoral', 'lightgreen', 'lightyellow']
    
    for cluster_id, techniques in cluster_techniques.items():
        # Remove duplicates and sort by typical attack sequence
        unique_techniques = list(set(techniques))
        
        # Add nodes
        for technique in unique_techniques:
            if technique in attack_techniques:
                G.add_node(technique, 
                          name=attack_techniques[technique]['name'],
                          tactic=attack_techniques[technique]['tactic'],
                          cluster=cluster_id,
                          color=colors[cluster_id % len(colors)])
        
        # Add edges based on typical attack flow
        for i in range(len(unique_techniques) - 1):
            if unique_techniques[i] in attack_techniques and unique_techniques[i+1] in attack_techniques:
                G.add_edge(unique_techniques[i], unique_techniques[i+1])
    
    return G

def visualize_attack_paths(G):
    """Visualize attack paths"""
    plt.figure(figsize=(15, 10))
    
    # Create layout
    pos = nx.spring_layout(G, k=3, iterations=50)
    
    # Get node colors by cluster
    node_colors = [G.nodes[node].get('color', 'lightgray') for node in G.nodes()]
    
    # Draw graph
    nx.draw(G, pos, 
            node_color=node_colors,
            node_size=2000,
            font_size=8,
            font_weight='bold',
            arrows=True,
            arrowsize=20,
            edge_color='gray',
            with_labels=True)
    
    # Add technique names as labels
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
    
    # Cluster analysis
    clusters = defaultdict(list)
    for node in G.nodes():
        cluster = G.nodes[node].get('cluster', 'unknown')
        clusters[cluster].append(node)
    
    for cluster_id, techniques in clusters.items():
        print(f"ACTIVITY GROUP {cluster_id}:")
        print(f"  Techniques Used: {len(techniques)}")
        
        # Group by tactic
        tactics = defaultdict(list)
        for technique in techniques:
            tactic = G.nodes[technique].get('tactic', 'Unknown')
            tactics[tactic].append(technique)
        
        print("  Tactics Coverage:")
        for tactic, techs in tactics.items():
            print(f"    {tactic}: {len(techs)} techniques")
        
        # Calculate centrality
        subgraph = G.subgraph(techniques)
        if len(subgraph.nodes()) > 1:
            centrality = nx.degree_centrality(subgraph)
            most_central = max(centrality, key=centrality.get)
            print(f"  Key Technique: {most_central} ({G.nodes[most_central]['name']})")
        
        print()

def main():
    # Load attack technique data
    attack_techniques = load_attack_data()
    
    # Create attack graph
    G = create_attack_graph('intrusion_data.json', attack_techniques)
    
    # Generate analysis report
    generate_attack_report(G)
    
    # Create visualization
    visualize_attack_paths(G)

if __name__ == "__main__":
    main()
