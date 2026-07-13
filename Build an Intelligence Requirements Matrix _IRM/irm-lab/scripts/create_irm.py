#!/usr/bin/env python3
import json
import pandas as pd
from datetime import datetime, timedelta

def load_requirements():
    with open('data/requirements.json', 'r') as file:
        return json.load(file)

def calculate_priority_score(priority, frequency):
    priority_weights = {'High': 3, 'Medium': 2, 'Low': 1}
    frequency_weights = {'Daily': 4, 'Weekly': 3, 'Monthly': 2, 'Quarterly': 1}
    
    return priority_weights.get(priority, 1) * frequency_weights.get(frequency, 1)

def create_irm_matrix():
    requirements = load_requirements()
    
    irm_data = []
    for req in requirements:
        priority_score = calculate_priority_score(req['Priority'], req['Frequency'])
        
        # Calculate next collection date based on frequency
        today = datetime.now()
        if req['Frequency'] == 'Daily':
            next_collection = today + timedelta(days=1)
        elif req['Frequency'] == 'Weekly':
            next_collection = today + timedelta(weeks=1)
        elif req['Frequency'] == 'Monthly':
            next_collection = today + timedelta(days=30)
        else:  # Quarterly
            next_collection = today + timedelta(days=90)
        
        irm_data.append({
            'Requirement_ID': req['ID'],
            'Category': req['Category'],
            'Description': req['Description'],
            'Priority': req['Priority'],
            'Frequency': req['Frequency'],
            'Priority_Score': priority_score,
            'Stakeholder': req['Stakeholder'],
            'Collection_Method': 'TBD',
            'Data_Sources': 'TBD',
            'Next_Collection': next_collection.strftime("%Y-%m-%d"),
            'Status': 'Active',
            'Last_Updated': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    
    # Sort by priority score (descending)
    irm_data.sort(key=lambda x: x['Priority_Score'], reverse=True)
    
    return irm_data

def save_irm_matrix(irm_data):
    # Save as JSON
    with open('output/irm_matrix.json', 'w') as file:
        json.dump(irm_data, file, indent=2)
    
    # Save as CSV for easy viewing
    df = pd.DataFrame(irm_data)
    df.to_csv('output/irm_matrix.csv', index=False)
    
    # Save as Excel
    df.to_excel('output/irm_matrix.xlsx', index=False, sheet_name='IRM')
    
    print("IRM Matrix saved in multiple formats:")
    print("- JSON: output/irm_matrix.json")
    print("- CSV: output/irm_matrix.csv")
    print("- Excel: output/irm_matrix.xlsx")

def display_irm_summary(irm_data):
    print("\n=== Intelligence Requirements Matrix Summary ===")
    print(f"Total Requirements: {len(irm_data)}")
    
    # Priority distribution
    priority_counts = {}
    for item in irm_data:
        priority = item['Priority']
        priority_counts[priority] = priority_counts.get(priority, 0) + 1
    
    print("\nPriority Distribution:")
    for priority, count in priority_counts.items():
        print(f"  {priority}: {count}")
    
    print("\nTop 3 Priority Requirements:")
    for i, item in enumerate(irm_data[:3], 1):
        print(f"  {i}. {item['Requirement_ID']}: {item['Description'][:50]}...")

if __name__ == "__main__":
    irm_data = create_irm_matrix()
    save_irm_matrix(irm_data)
    display_irm_summary(irm_data)
