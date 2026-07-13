#!/usr/bin/env python3

import json
from datetime import datetime

class DiamondModel:
    def __init__(self):
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
    # Initialize Diamond Model
    diamond = DiamondModel()
    
    # Populate Aurora data
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
    
    # Generate analysis report
    diamond.generate_report()
    
    # Export to JSON
    diamond.export_json('../analysis/aurora_diamond_model.json')
