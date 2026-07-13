#!/usr/bin/env python3
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
    with open('config.yaml', 'r') as file:
        return yaml.safe_load(file)

def define_sample_requirements():
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
    return requirements

def save_requirements(requirements):
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
