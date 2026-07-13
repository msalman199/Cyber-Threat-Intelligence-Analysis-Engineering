#!/usr/bin/env python3
import json
import yaml
import re
from datetime import datetime

def load_sigma_rule(rule_file):
    with open(rule_file, 'r') as f:
        return yaml.safe_load(f)

def check_event_against_rule(event, rule):
    detection = rule.get('detection', {})
    selection = detection.get('selection', {})
    
    matches = []
    for field, criteria in selection.items():
        if '|' in field:
            field_name, modifier = field.split('|', 1)
        else:
            field_name, modifier = field, None
        
        if field_name in event:
            event_value = event[field_name]
            
            if isinstance(criteria, list):
                for criterion in criteria:
                    if modifier == 'contains':
                        if criterion.lower() in event_value.lower():
                            matches.append(f"{field_name} contains '{criterion}'")
                    elif criterion.lower() == event_value.lower():
                        matches.append(f"{field_name} equals '{criterion}'")
            elif isinstance(criteria, str):
                if modifier == 'contains':
                    if criteria.lower() in event_value.lower():
                        matches.append(f"{field_name} contains '{criteria}'")
                elif criteria.lower() == event_value.lower():
                    matches.append(f"{field_name} equals '{criteria}'")
    
    return matches

def analyze_with_sigma():
    rules = [
        ('rules/dns_tunneling.yml', 'analysis/dns_events.json'),
        ('rules/http_beaconing.yml', 'analysis/http_events.json')
    ]
    
    total_detections = 0
    
    for rule_file, event_file in rules:
        print(f"\n=== Analyzing {event_file} with {rule_file} ===")
        
        try:
            rule = load_sigma_rule(rule_file)
            print(f"Rule: {rule['title']}")
            print(f"Description: {rule['description']}")
            
            detections = 0
            with open(event_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        event = json.loads(line.strip())
                        matches = check_event_against_rule(event, rule)
                        
                        if matches:
                            detections += 1
                            total_detections += 1
                            print(f"  DETECTION #{detections} (Line {line_num}):")
                            for match in matches:
                                print(f"    - {match}")
                            print(f"    - Event: {json.dumps(event, indent=6)}")
                    
                    except json.JSONDecodeError:
                        continue
            
            print(f"Total detections for this rule: {detections}")
        
        except FileNotFoundError as e:
            print(f"File not found: {e}")
    
    print(f"\n=== SUMMARY ===")
    print(f"Total detections across all rules: {total_detections}")

if __name__ == "__main__":
    analyze_with_sigma()
