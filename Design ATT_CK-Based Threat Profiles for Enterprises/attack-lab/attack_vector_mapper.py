#!/usr/bin/env python3
import json
from attack_analyzer import AttackAnalyzer

class AttackVectorMapper:
    def __init__(self, attack_data_file):
        self.analyzer = AttackAnalyzer(attack_data_file)
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
    
    # Print summary
    print("\nATTACK VECTOR MAPPING SUMMARY")
    print("=" * 40)
    for vector, tactics in mapping.items():
        print(f"\n{vector}:")
        for tactic, techniques in tactics.items():
            print(f"  {tactic}: {len(techniques)} techniques")
