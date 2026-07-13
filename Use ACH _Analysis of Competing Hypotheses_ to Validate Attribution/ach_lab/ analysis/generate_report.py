#!/usr/bin/env python3

import json
import pandas as pd
from datetime import datetime

def generate_detailed_report():
    """Generate comprehensive ACH analysis report"""
    
    # Load results
    with open('../reports/ach_results.json', 'r') as f:
        results = json.load(f)
    
    with open('../data/hypotheses.json', 'r') as f:
        hypotheses_data = json.load(f)
    
    with open('../data/evidence_items.json', 'r') as f:
        evidence_data = json.load(f)
    
    report = []
    report.append("# ACH Analysis Report: Threat Actor Attribution")
    report.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")
    
    # Executive Summary
    report.append("## Executive Summary")
    report.append("")
    top_hypothesis = results['ranking'][0]
    report.append(f"Based on ACH analysis, **{top_hypothesis[0]}** is the most likely attribution ")
    report.append(f"with a weighted score of {top_hypothesis[1]:.2f}.")
    report.append("")
    
    # Methodology
    report.append("## Methodology")
    report.append("")
    report.append("The Analysis of Competing Hypotheses (ACH) method was used to evaluate ")
    report.append("threat actor attribution by:")
    report.append("1. Identifying competing hypotheses")
    report.append("2. Collecting relevant evidence")
    report.append("3. Evaluating evidence against each hypothesis")
    report.append("4. Calculating weighted scores based on evidence reliability")
    report.append("")
    
    # Hypotheses Overview
    report.append("## Competing Hypotheses")
    report.append("")
    for h in hypotheses_data['hypotheses']:
        report.append(f"**{h['name']}:** {h['description']}")
    report.append("")
    
    # Evidence Analysis
    report.append("## Evidence Analysis")
    report.append("")
    
    # Create matrix display
    matrix_df = pd.DataFrame(results['matrix'])
    report.append("### Evidence vs Hypothesis Matrix")
    report.append("```")
    report.append(matrix_df.to_string())
    report.append("```")
    report.append("")
    
    report.append("**Legend:**")
    report.append("- `++` = Strongly supports hypothesis")
    report.append("- `+` = Supports hypothesis")  
    report.append("- `N` = Neutral/No impact")
    report.append("- `-` = Contradicts hypothesis")
    report.append("- `--` = Strongly contradicts hypothesis")
    report.append("")
    
    # Detailed Results
    report.append("## Detailed Results")
    report.append("")
    
    for i, (hypothesis, score) in enumerate(results['ranking'], 1):
        score_data = results['scores'][hypothesis]
        report.append(f"### {i}. {hypothesis}")
        report.append(f"- **Weighted Score:** {score:.2f}")
        report.append(f"- **Supporting Evidence:** {score_data['consistent_count']} items")
        report.append(f"- **Contradicting Evidence:** {score_data['inconsistent_count']} items")
        report.append("")
    
    # Key Findings
    report.append("## Key Findings")
    report.append("")
    
    # Identify strongest evidence
    strongest_evidence = []
    for evidence_name, hypothesis_scores in results['matrix'].items():
        for hypothesis, score in hypothesis_scores.items():
            if score in ['++', '--']:
                strongest_evidence.append((evidence_name, hypothesis, score))
    
    report.append("### Strongest Evidence Indicators:")
    for evidence, hypothesis, score in strongest_evidence:
        direction = "supports" if score == '++' else "contradicts"
        report.append(f"- **{evidence}** strongly {direction} **{hypothesis}**")
    report.append("")
    
    # Recommendations
    report.append("## Recommendations")
    report.append("")
    report.append("1. **Primary Attribution:** Focus investigation on top-ranked hypothesis")
    report.append("2. **Additional Evidence:** Collect more data for low-reliability evidence items")
    report.append("3. **Alternative Scenarios:** Consider combination of actors or false flag operations")
    report.append("4. **Confidence Level:** Assess overall confidence based on evidence quality")
    report.append("")
    
    # Save report
    with open('../reports/detailed_report.md', 'w') as f:
        f.write('\n'.join(report))
    
    print("Detailed report generated: reports/detailed_report.md")
    
    # Display summary
    print("\n=== ACH Analysis Summary ===")
    print(f"Top Attribution: {results['ranking'][0][0]} (Score: {results['ranking'][0][1]:.2f})")
    print(f"Evidence Items Analyzed: {len(results['matrix'])}")
    print(f"Hypotheses Evaluated: {len(results['ranking'])}")

if __name__ == "__main__":
    generate_detailed_report()
