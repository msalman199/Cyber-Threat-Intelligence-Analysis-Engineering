#!/usr/bin/env python3
import json
import pandas as pd
from collections import defaultdict, Counter
import networkx as nx
import matplotlib.pyplot as plt

def load_all_data():
    """Load all certificate and network data"""
    data = {
        'crtsh_certs': [],
        'zeek_certs': []
    }
    
    # Load crt.sh data
    for filename in os.listdir('analysis'):
        if filename.endswith('_details.json') and 'zeek' not in filename:
            with open(f'analysis/{filename}', 'r') as f:
                data['crtsh_certs'].extend(json.load(f))
    
    # Load Zeek data
    zeek_file = 'analysis/zeek_cert_info.json'
    if os.path.exists(zeek_file):
        with open(zeek_file, 'r') as f:
            data['zeek_certs'] = json.load(f)
    
    return data

def find_infrastructure_patterns(data):
    """Identify common infrastructure patterns"""
    patterns = {
        'common_issuers': defaultdict(set),
        'timing_clusters': defaultdict(list),
        'cert_authorities': Counter(),
        'domain_clusters': defaultdict(set)
    }
    
    # Analyze crt.sh data
    for cert in data['crtsh_certs']:
        issuer = cert.get('issuer_name', 'Unknown')
        domain = cert.get('domain_searched', 'Unknown')
        
        patterns['common_issuers'][issuer].add(domain)
        patterns['cert_authorities'][issuer] += 1
        
        # Group domains by issuer
        patterns['domain_clusters'][issuer].add(domain)
    
    # Analyze Zeek data
    for cert in data['zeek_certs']:
        issuer = cert.get('issuer', 'Unknown')
        server = cert.get('server_name', 'Unknown')
        
        patterns['common_issuers'][issuer].add(server)
        patterns['cert_authorities'][issuer] += 1
    
    return patterns

def create_infrastructure_graph(patterns):
    """Create network graph of infrastructure relationships"""
    G = nx.Graph()
    
    # Add nodes and edges based on common issuers
    for issuer, domains in patterns['common_issuers'].items():
        if len(domains) > 1:  # Only include issuers with multiple domains
            G.add_node(issuer, node_type='issuer')
            
            for domain in domains:
                G.add_node(domain, node_type='domain')
                G.add_edge(issuer, domain)
    
    return G

def generate_attribution_report(patterns, data):
    """Generate comprehensive attribution report"""
    report = {
        'summary': {},
        'high_confidence_links': [],
        'medium_confidence_links': [],
        'infrastructure_reuse': []
    }
    
    # Summary statistics
    report['summary'] = {
        'total_certificates': len(data['crtsh_certs']) + len(data['zeek_certs']),
        'unique_issuers': len(patterns['common_issuers']),
        'domains_analyzed': len(set([cert.get('domain_searched') for cert in data['crtsh_certs']])),
        'most_common_issuer': patterns['cert_authorities'].most_common(1)[0] if patterns['cert_authorities'] else ('None', 0)
    }
    
    # High confidence links (same issuer, close timing)
    for issuer, domains in patterns['common_issuers'].items():
        if len(domains) > 1:
            report['high_confidence_links'].append({
                'issuer': issuer,
                'linked_domains': list(domains),
                'confidence': 'high' if len(domains) > 2 else 'medium'
            })
    
    # Infrastructure reuse analysis
    issuer_usage = [(issuer, len(domains)) for issuer, domains in patterns['common_issuers'].items()]
    issuer_usage.sort(key=lambda x: x[1], reverse=True)
    
    report['infrastructure_reuse'] = issuer_usage[:5]  # Top 5
    
    return report

def visualize_infrastructure(G):
    """Create visualization of infrastructure relationships"""
    plt.figure(figsize=(12, 8))
    
    # Position nodes
    pos = nx.spring_layout(G, k=1, iterations=50)
    
    # Separate node types
    issuer_nodes = [node for node, attr in G.nodes(data=True) if attr.get('node_type') == 'issuer']
    domain_nodes = [node for node, attr in G.nodes(data=True) if attr.get('node_type') == 'domain']
    
    # Draw nodes
    nx.draw_networkx_nodes(G, pos, nodelist=issuer_nodes, node_color='red', 
                          node_size=500, alpha=0.7, label='Certificate Issuers')
    nx.draw_networkx_nodes(G, pos, nodelist=domain_nodes, node_color='blue', 
                          node_size=300, alpha=0.7, label='Domains')
    
    # Draw edges
    nx.draw_networkx_edges(G, pos, alpha=0.5)
    
    # Draw labels
    nx.draw_networkx_labels(G, pos, font_size=8)
    
    plt.title('Certificate Infrastructure Correlation Map')
    plt.legend()
    plt.axis('off')
    plt.tight_layout()
    plt.savefig('analysis/infrastructure_map.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    print("Infrastructure map saved to analysis/infrastructure_map.png")

if __name__ == "__main__":
    print("Loading all certificate data...")
    data = load_all_data()
    
    print("Analyzing infrastructure patterns...")
    patterns = find_infrastructure_patterns(data)
    
    print("Creating infrastructure graph...")
    G = create_infrastructure_graph(patterns)
    
    print("Generating attribution report...")
    report = generate_attribution_report(patterns, data)
    
    # Save report
    with open('analysis/attribution_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("\n=== INFRASTRUCTURE ATTRIBUTION REPORT ===")
    print(f"Total Certificates Analyzed: {report['summary']['total_certificates']}")
    print(f"Unique Certificate Issuers: {report['summary']['unique_issuers']}")
    print(f"Domains Analyzed: {report['summary']['domains_analyzed']}")
    print(f"Most Common Issuer: {report['summary']['most_common_issuer'][0]} ({report['summary']['most_common_issuer'][1]} certs)")
    
    print("\n=== HIGH CONFIDENCE INFRASTRUCTURE LINKS ===")
    for link in report['high_confidence_links']:
        print(f"Issuer: {link['issuer']}")
        print(f"  Linked Domains: {', '.join(link['linked_domains'])}")
        print(f"  Confidence: {link['confidence']}")
        print()
    
    print("=== TOP INFRASTRUCTURE REUSE ===")
    for issuer, count in report['infrastructure_reuse']:
        print(f"{issuer}: {count} domains")
    
    # Create visualization
    if len(G.nodes()) > 0:
        visualize_infrastructure(G)
    else:
        print("No infrastructure relationships found for visualization")
    
    print(f"\nFull report saved to analysis/attribution_report.json")
