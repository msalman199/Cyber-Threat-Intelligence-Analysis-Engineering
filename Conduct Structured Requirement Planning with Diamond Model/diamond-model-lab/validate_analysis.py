#!/usr/bin/env python3
import os

def validate_diamond_model():
    required_files = [
        "reports/diamond_model_report.txt",
        "reports/adversary_profile.txt",
        "reports/capability_infrastructure.txt",
        "reports/victim_gaps_analysis.txt",
        "reports/final_diamond_analysis.txt"
    ]
    
    validation_results = {}
    
    for file_path in required_files:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                content = f.read()
                validation_results[file_path] = {
                    'exists': True,
                    'size': len(content),
                    'has_content': len(content) > 100
                }
        else:
            validation_results[file_path] = {
                'exists': False,
                'size': 0,
                'has_content': False
            }
    
    print("DIAMOND MODEL VALIDATION RESULTS")
    print("="*40)
    
    all_valid = True
    for file_path, results in validation_results.items():
        status = "✓ PASS" if results['exists'] and results['has_content'] else "✗ FAIL"
        print(f"{status} {file_path}")
        if not (results['exists'] and results['has_content']):
            all_valid = False
    
    print(f"\nOverall Status: {'✓ ALL COMPONENTS VALIDATED' if all_valid else '✗ VALIDATION FAILED'}")
    
    return all_valid

if __name__ == "__main__":
    validate_diamond_model()
