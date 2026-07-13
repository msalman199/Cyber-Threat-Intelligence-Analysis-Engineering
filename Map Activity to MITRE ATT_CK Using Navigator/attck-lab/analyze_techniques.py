#!/usr/bin/env python3
import json
import sys

def analyze_ransomware_ttps(filename):
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
        
        print(f"Analysis of: {data['name']}")
        print("=" * 50)
        
        # Group techniques by tactic
        tactics = {}
        for technique in data['techniques']:
            tactic = technique['tactic']
            if tactic not in tactics:
                tactics[tactic] = []
            tactics[tactic].append(technique)
        
        # Analyze each tactic
        for tactic, techniques in tactics.items():
            print(f"\n{tactic.upper().replace('-', ' ')}:")
            for tech in techniques:
                print(f"  - {tech['techniqueID']}: Score {tech['score']}")
                print(f"    Comment: {tech['comment']}")
        
        # Identify critical techniques (score >= 90)
        critical = [t for t in data['techniques'] if t['score'] >= 90]
        print(f"\nCRITICAL TECHNIQUES ({len(critical)} found):")
        for tech in critical:
            print(f"  - {tech['techniqueID']}: {tech['comment']}")
        
        # Attack chain analysis
        print(f"\nATTACK CHAIN ANALYSIS:")
        print(f"Total techniques mapped: {len(data['techniques'])}")
        print(f"Tactics covered: {len(tactics)}")
        print(f"Average severity score: {sum(t['score'] for t in data['techniques']) / len(data['techniques']):.1f}")
        
    except Exception as e:
        print(f"Error analyzing file: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 analyze_techniques.py <json_file>")
        sys.exit(1)
    
    analyze_ransomware_ttps(sys.argv[1])
