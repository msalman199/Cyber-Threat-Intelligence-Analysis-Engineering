#!/usr/bin/env python3
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
