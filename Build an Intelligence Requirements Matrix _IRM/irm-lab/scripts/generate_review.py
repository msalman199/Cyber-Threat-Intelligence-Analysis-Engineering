#!/usr/bin/env python3
import json
from datetime import datetime

def load_enhanced_irm():
    with open('output/enhanced_irm_matrix.json', 'r') as file:
        return json.load(file)

def generate_stakeholder_report():
    irm_data = load_enhanced_irm()
    
    # Group by stakeholder
    stakeholder_groups = {}
    for item in irm_data:
        stakeholder = item['Stakeholder']
        if stakeholder not in stakeholder_groups:
            stakeholder_groups[stakeholder] = []
        stakeholder_groups[stakeholder].append(item)
    
    # Generate HTML report
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Intelligence Requirements Matrix - Stakeholder Review</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .high {{ background-color: #ffebee; }}
        .medium {{ background-color: #fff3e0; }}
        .low {{ background-color: #e8f5e8; }}
        .header {{ background-color: #1976d2; color: white; padding: 20px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Intelligence Requirements Matrix</h1>
        <p>Stakeholder Review Document</p>
        <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
"""
    
    for stakeholder, requirements in stakeholder_groups.items():
        html_content += f"""
    <h2>Requirements for: {stakeholder}</h2>
    <table>
        <tr>
            <th>ID</th>
            <th>Category</th>
            <th>Description</th>
            <th>Priority</th>
            <th>Frequency</th>
            <th>Collection Method</th>
            <th>Next Collection</th>
        </tr>
"""
        
        for req in requirements:
            priority_class = req['Priority'].lower()
            html_content += f"""
        <tr class="{priority_class}">
            <td>{req['Requirement_ID']}</td>
            <td>{req['Category']}</td>
            <td>{req['Description']}</td>
            <td>{req['Priority']}</td>
            <td>{req['Frequency']}</td>
            <td>{req['Collection_Method']}</td>
            <td>{req['Next_Collection']}</td>
        </tr>
"""
        
        html_content += "    </table>\n"
    
    html_content += """
    <h2>Review Instructions</h2>
    <ul>
        <li>Review each requirement assigned to your role</li>
        <li>Verify the priority and frequency are appropriate</li>
        <li>Confirm collection methods are feasible</li>
        <li>Provide feedback on resource requirements</li>
        <li>Suggest additional requirements if needed</li>
    </ul>
</body>
</html>
"""
    
    with open('output/stakeholder_review.html', 'w') as file:
        file.write(html_content)
    
    print("Stakeholder review report generated: output/stakeholder_review.html")

def create_review_checklist():
    checklist = """
# Intelligence Requirements Matrix Review Checklist

## Pre-Review Preparation
- [ ] All stakeholders have received the IRM document
- [ ] Review meeting scheduled with key stakeholders
- [ ] Current threat landscape assessment completed

## Review Criteria

### For Each Requirement:
- [ ] Priority level is appropriate for current threat environment
- [ ] Collection frequency aligns with business needs
- [ ] Data sources are accessible and reliable
- [ ] Collection methods are technically feasible
- [ ] Resource requirements are realistic
- [ ] Stakeholder assignment is correct

### Overall IRM Assessment:
- [ ] Coverage of all critical intelligence areas
- [ ] Balance between high/medium/low priority items
- [ ] Alignment with organizational risk appetite
- [ ] Integration with existing security processes
- [ ] Scalability for future growth

## Post-Review Actions:
- [ ] Document stakeholder feedback
- [ ] Update IRM based on review comments
- [ ] Establish regular review schedule
- [ ] Define success metrics for intelligence collection
- [ ] Create implementation timeline

## Stakeholder Sign-off:
- [ ] CISO approval
- [ ] Security Team lead approval
- [ ] IT Operations approval
- [ ] Compliance Officer approval
- [ ] Business Strategy approval

Review Date: _______________
Next Review Date: _______________
"""
    
    with open('output/review_checklist.md', 'w') as file:
        file.write(checklist)
    
    print("Review checklist created: output/review_checklist.md")

if __name__ == "__main__":
    generate_stakeholder_report()
    create_review_checklist()
