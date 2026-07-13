#!/usr/bin/env python3
import json
import pandas as pd

class RiskAlignmentTool:
    def __init__(self):
        self.risk_factors = {
            'asset_criticality': {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4},
            'threat_likelihood': {'Very Low': 1, 'Low': 2, 'Medium': 3, 'High': 4, 'Very High': 5},
            'vulnerability_severity': {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4},
            'impact_magnitude': {'Minimal': 1, 'Minor': 2, 'Moderate': 3, 'Major': 4, 'Severe': 5}
        }
        
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
        
        # Calculate aligned risk scores for each attack vector
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
        
        # Generate mitigation priorities
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
        
        # Generate readable report
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
    
    # Align financial services threat profile
    alignment = tool.align_threat_with_organization(
        'financial_threat_profile.json',
        'Financial Services'
    )
    tool.export_alignment_report(alignment, 'financial_risk_alignment.json')
