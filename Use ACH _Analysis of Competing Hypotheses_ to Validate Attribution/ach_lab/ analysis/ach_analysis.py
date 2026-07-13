#!/usr/bin/env python3

import json
import pandas as pd
import sys
import os
sys.path.append('../templates')
from ach_template import ACHAnalysis

def load_data():
    """Load case study data"""
    with open('../data/hypotheses.json', 'r') as f:
        hypotheses_data = json.load(f)
    
    with open('../data/evidence_items.json', 'r') as f:
        evidence_data = json.load(f)
        
    with open('../data/attack_scenario.json', 'r') as f:
        scenario_data = json.load(f)
        
    return hypotheses_data, evidence_data, scenario_data

def setup_ach_analysis():
    """Initialize ACH analysis with hypotheses and evidence"""
    hypotheses_data, evidence_data, scenario_data = load_data()
    
    ach = ACHAnalysis()
    
    # Add hypotheses
    for h in hypotheses_data['hypotheses']:
        ach.add_hypothesis(h['name'], h['description'])
    
    # Add evidence
    for e in evidence_data['evidence']:
        ach.add_evidence(e['name'], e['description'], e['reliability'])
    
    return ach, hypotheses_data, evidence_data, scenario_data

def populate_matrix(ach):
    """Populate ACH matrix with evidence evaluations"""
    matrix = ach.create_matrix()
    
    # Evidence evaluation against each hypothesis
    # ++ = Strongly supports, + = Supports, N = Neutral, - = Contradicts, -- = Strongly contradicts
    
    evaluations = {
        'Malware Code Similarity': {'APT29': '+', 'Lazarus': '++', 'FIN7': '+', 'Unknown Actor': 'N'},
        'Infrastructure Overlap': {'APT29': '-', 'Lazarus': '+', 'FIN7': '++', 'Unknown Actor': 'N'},
        'TTP Matching': {'APT29': '++', 'Lazarus': '++', 'FIN7': '++', 'Unknown Actor': '+'},
        'Target Selection': {'APT29': '++', 'Lazarus': '++', 'FIN7': '++', 'Unknown Actor': '+'},
        'Timing Patterns': {'APT29': '+', 'Lazarus': '-', 'FIN7': 'N', 'Unknown Actor': 'N'},
        'Language Artifacts': {'APT29': 'N', 'Lazarus': '+', 'FIN7': 'N', 'Unknown Actor': 'N'},
        'Operational Security': {'APT29': '+', 'Lazarus': '+', 'FIN7': '++', 'Unknown Actor': 'N'}
    }
    
    for evidence, hypothesis_scores in evaluations.items():
        for hypothesis, score in hypothesis_scores.items():
            matrix.loc[evidence, hypothesis] = score
    
    ach.matrix = matrix
    return matrix

def main():
    print("=== ACH Analysis for Threat Attribution ===\n")
    
    # Setup analysis
    ach, hypotheses_data, evidence_data, scenario_data = setup_ach_analysis()
    
    # Populate matrix
    matrix = populate_matrix(ach)
    
    print("ACH Matrix:")
    print(matrix)
    print("\n")
    
    # Calculate scores
    scores = ach.calculate_scores()
    
    print("Hypothesis Evaluation Results:")
    print("-" * 50)
    
    for hypothesis, score_data in scores.items():
        print(f"\n{hypothesis}:")
        print(f"  Inconsistent Evidence Count: {score_data['inconsistent_count']}")
        print(f"  Consistent Evidence Count: {score_data['consistent_count']}")
        print(f"  Weighted Score: {score_data['weighted_score']:.2f}")
    
    # Rank hypotheses
    ranked = sorted(scores.items(), key=lambda x: x[1]['weighted_score'], reverse=True)
    
    print(f"\nHypothesis Ranking (by weighted score):")
    print("-" * 40)
    for i, (hypothesis, score_data) in enumerate(ranked, 1):
        print(f"{i}. {hypothesis}: {score_data['weighted_score']:.2f}")
    
    # Save results
    results = {
        'matrix': matrix.to_dict(),
        'scores': scores,
        'ranking': [(h, s['weighted_score']) for h, s in ranked]
    }
    
    with open('../reports/ach_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to reports/ach_results.json")

if __name__ == "__main__":
    main()
