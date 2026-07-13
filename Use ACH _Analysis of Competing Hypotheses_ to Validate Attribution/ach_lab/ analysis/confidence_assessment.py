#!/usr/bin/env python3

import json
import statistics

def assess_confidence():
    """Assess confidence level in attribution conclusion"""
    
    with open('../reports/ach_results.json', 'r') as f:
        results = json.load(f)
    
    with open('../data/evidence_items.json', 'r') as f:
        evidence_data = json.load(f)
    
    # Calculate confidence metrics
    scores = [score for _, score in results['ranking']]
    score_spread = max(scores) - min(scores)
    
    # Evidence reliability assessment
    reliabilities = [e['reliability'] for e in evidence_data['evidence']]
    avg_reliability = statistics.mean(reliabilities)
    
    # Consistency check
    top_hypothesis = results['ranking'][0][0]
    top_score_data = results['scores'][top_hypothesis]
    consistency_ratio = top_score_data['consistent_count'] / (
        top_score_data['consistent_count'] + top_score_data['inconsistent_count']
    ) if (top_score_data['consistent_count'] + top_score_data['inconsistent_count']) > 0 else 0
    
    # Overall confidence calculation
    confidence_factors = {
        'score_separation': min(score_spread / 10, 1.0),  # Higher separation = higher confidence
        'evidence_reliability': avg_reliability,
        'consistency': consistency_ratio
    }
    
    overall_confidence = statistics.mean(confidence_factors.values())
    
    print("=== Confidence Assessment ===")
    print(f"Score Separation: {score_spread:.2f}")
    print(f"Average Evidence Reliability: {avg_reliability:.2f}")
    print(f"Top Hypothesis Consistency: {consistency_ratio:.2f}")
    print(f"Overall Confidence Level: {overall_confidence:.2f}")
    
    # Confidence interpretation
    if overall_confidence >= 0.8:
        confidence_level = "HIGH"
        interpretation = "Strong evidence supports the attribution conclusion"
    elif overall_confidence >= 0.6:
        confidence_level = "MEDIUM"
        interpretation = "Moderate evidence supports the attribution conclusion"
    else:
        confidence_level = "LOW"
        interpretation = "Limited evidence; attribution conclusion is tentative"
    
    print(f"\nConfidence Level: {confidence_level}")
    print(f"Interpretation: {interpretation}")
    
    # Save confidence assessment
    confidence_report = {
        'confidence_level': confidence_level,
        'overall_score': overall_confidence,
        'factors': confidence_factors,
        'interpretation': interpretation,
        'recommendations': []
    }
    
    # Add recommendations based on confidence level
    if overall_confidence < 0.7:
        confidence_report['recommendations'].extend([
            "Collect additional high-reliability evidence",
            "Validate existing evidence through independent sources",
            "Consider alternative attribution scenarios"
        ])
    
    with open('../reports/confidence_assessment.json', 'w') as f:
        json.dump(confidence_report, f, indent=2)
    
    print(f"\nConfidence assessment saved to reports/confidence_assessment.json")

if __name__ == "__main__":
    assess_confidence()
