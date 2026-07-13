#!/usr/bin/env python3
import os
import json

def validate_lab_completion():
    print("=== LAB VALIDATION CHECKLIST ===\n")
    
    checks = [
        ("Zeek installation", "which zeek"),
        ("Sigma rules created", "ls rules/*.yml"),
        ("Log analysis completed", "ls analysis/*.json"),
        ("Detection report generated", "ls analysis/detection_report.json")
    ]
    
    passed = 0
    total = len(checks)
    
    for check_name, command in checks:
        result = os.system(f"{command} >/dev/null 2>&1")
        if result == 0:
            print(f"✅ {check_name}: PASSED")
            passed += 1
        else:
            print(f"❌ {check_name}: FAILED")
    
    print(f"\nValidation Results: {passed}/{total} checks passed")
    
    if passed == total:
        print("🎉 LAB COMPLETED SUCCESSFULLY!")
        print("\nKey Accomplishments:")
        print("- Successfully analyzed Zeek logs for suspicious behavior")
        print("- Applied custom Sigma rules to detect anomalies")
        print("- Identified adversary tradecraft evolution over time")
        print("- Generated comprehensive detection report")
    else:
        print("⚠️  Some components need attention. Review failed checks above.")
    
    # Display final statistics
    print(f"\n=== FINAL STATISTICS ===")
    try:
        with open('analysis/detection_report.json', 'r') as f:
            report = json.load(f)
            summary = report['summary']
            print(f"Total Detections: {summary['total_detections']}")
            print(f"Tradecraft Shifts Identified: {summary['tradecraft_shifts_identified']}")
            print(f"Risk Assessment: {summary['risk_level']}")
    except:
        print("Detection report not available")

if __name__ == "__main__":
    validate_lab_completion()
