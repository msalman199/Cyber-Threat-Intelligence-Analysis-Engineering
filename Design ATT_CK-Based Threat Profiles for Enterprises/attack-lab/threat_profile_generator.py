#!/usr/bin/env python3
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
        
        # Map attack vectors to ATT&CK techniques
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
    # Example usage
    generator = ThreatProfileGenerator('enterprise-attack.json')
    generator.create_enterprise_profile(
        'APT-Finance-Hunter',
        'Financial Services',
        ['Initial Access', 'Persistence', 'Credential Access', 'Lateral Movement', 'Exfiltration']
    )
    generator.add_risk_assessment(4, 5)  # High likelihood, Critical impact
    generator.export_profile('financial_threat_profile.json')
    print(generator.generate_report())
