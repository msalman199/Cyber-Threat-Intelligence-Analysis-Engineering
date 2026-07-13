#!/usr/bin/env python3
import json
from datetime import datetime

def create_feedback_template():
    feedback_template = {
        "review_date": datetime.now().strftime("%Y-%m-%d"),
        "reviewer_info": {
            "name": "",
            "role": "",
            "department": ""
        },
        "requirement_feedback": [],
        "general_feedback": {
            "overall_assessment": "",
            "missing_requirements": [],
            "resource_concerns": [],
            "implementation_suggestions": []
        },
        "approval_status": "pending"
    }
    
    # Load IRM to create feedback structure
    with open('output/enhanced_irm_matrix.json', 'r') as file:
        irm_data = json.load(file)
    
    for req in irm_data:
        feedback_item = {
            "requirement_id": req['Requirement_ID'],
            "current_priority": req['Priority'],
            "suggested_priority": "",
            "current_frequency": req['Frequency'],
            "suggested_frequency": "",
            "feasibility_rating": "",
            "comments": "",
            "approved": ""
        }
        feedback_template["requirement_feedback"].append(feedback_item)
    
    with open('templates/feedback_template.json', 'w') as file:
        json.dump(feedback_template, file, indent=2)
    
    print("Feedback template created: templates/feedback_template.json")

def simulate_stakeholder_feedback():
    # Create sample feedback from different stakeholders
    stakeholders = [
        {"name": "John Smith", "role": "CISO", "department": "Security"},
        {"name": "Jane Doe", "role": "Security Analyst", "department": "Security"},
        {"name": "Bob Johnson", "role": "IT Manager", "department": "IT Operations"}
    ]
    
    for stakeholder in stakeholders:
        with open('templates/feedback_template.json', 'r') as file:
            feedback = json.load(file)
        
        feedback["reviewer_info"] = stakeholder
        feedback["general_feedback"]["overall_assessment"] = "Good coverage of intelligence requirements"
        feedback["approval_status"] = "approved"
        
        # Add some sample feedback
        for req_feedback in feedback["requirement_feedback"][:2]:
            req_feedback["feasibility_rating"] = "High"
            req_feedback["comments"] = "Looks good, no changes needed"
            req_feedback["approved"] = "yes"
        
        filename = f"data/feedback_{stakeholder['role'].lower().replace(' ', '_')}.json"
        with open(filename, 'w') as file:
            json.dump(feedback, file, indent=2)
        
        print(f"Sample feedback created for {stakeholder['name']}: {filename}")

if __name__ == "__main__":
    create_feedback_template()
    simulate_stakeholder_feedback()
