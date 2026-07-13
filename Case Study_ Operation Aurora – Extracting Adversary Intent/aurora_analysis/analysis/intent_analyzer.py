#!/usr/bin/env python3

import json
import re
from datetime import datetime

class IntentAnalyzer:
    def __init__(self):
        self.intent_indicators = {
            'espionage': ['intellectual property', 'source code', 'gmail accounts', 'human rights'],
            'persistence': ['backdoor', 'long-term access', 'lateral movement'],
            'stealth': ['zero-day', 'spear-phishing', 'targeted'],
            'attribution_masking': ['legitimate domains', 'typosquatting', 'infrastructure']
        }
    
    def analyze_text(self, text):
        results = {}
        text_lower = text.lower()
        
        for intent_type, keywords in self.intent_indicators.items():
            matches = []
            for keyword in keywords:
                if keyword in text_lower:
                    matches.append(keyword)
            
            if matches:
                results[intent_type] = {
                    'confidence': len(matches) / len(keywords),
                    'indicators': matches
                }
        
        return results
    
    def generate_report(self, analysis_results):
        print("ADVERSARY INTENT ANALYSIS")
        print("=" * 25)
        
        for intent_type, data in analysis_results.items():
            confidence_pct = int(data['confidence'] * 100)
            print(f"\n{intent_type.upper()}: {confidence_pct}% confidence")
            print(f"Indicators: {', '.join(data['indicators'])}")

if __name__ == "__main__":
    analyzer = IntentAnalyzer()
    
    # Read case study data
    with open('../reports/aurora_summary.txt', 'r') as f:
        case_data = f.read()
    
    # Analyze intent
    results = analyzer.analyze_text(case_data)
    analyzer.generate_report(results)
