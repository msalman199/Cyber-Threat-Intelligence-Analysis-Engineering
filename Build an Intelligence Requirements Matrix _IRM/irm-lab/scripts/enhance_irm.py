#!/usr/bin/env python3
import json
import pandas as pd

def load_irm():
    with open('output/irm_matrix.json', 'r') as file:
        return json.load(file)

def enhance_with_methods():
    irm_data = load_irm()
    
    # Define collection methods and data sources by category
    enhancement_map = {
        'Threat Intelligence': {
            'Collection_Method': 'Automated feeds, Manual analysis',
            'Data_Sources': 'OSINT feeds, Threat intel platforms, Security blogs'
        },
        'Vulnerability Intelligence': {
            'Collection_Method': 'Vulnerability scanners, CVE monitoring',
            'Data_Sources': 'NVD, Vendor advisories, Security scanners'
        },
        'Asset Intelligence': {
            'Collection_Method': 'Network scanning, Asset discovery tools',
            'Data_Sources': 'Network scanners, CMDB, Cloud APIs'
        },
        'Compliance Intelligence': {
            'Collection_Method': 'Regulatory monitoring, Legal research',
            'Data_Sources': 'Regulatory websites, Legal databases, Industry reports'
        },
        'Business Intelligence': {
            'Collection_Method': 'Market research, Competitive analysis',
            'Data_Sources': 'Industry reports, News feeds, Social media'
        }
    }
    
    # Enhance each requirement
    for item in irm_data:
        category = item['Category']
        if category in enhancement_map:
            item['Collection_Method'] = enhancement_map[category]['Collection_Method']
            item['Data_Sources'] = enhancement_map[category]['Data_Sources']
    
    return irm_data

def save_enhanced_irm(irm_data):
    # Save enhanced version
    with open('output/enhanced_irm_matrix.json', 'w') as file:
        json.dump(irm_data, file, indent=2)
    
    df = pd.DataFrame(irm_data)
    df.to_excel('output/enhanced_irm_matrix.xlsx', index=False, sheet_name='Enhanced_IRM')
    
    print("Enhanced IRM Matrix saved:")
    print("- JSON: output/enhanced_irm_matrix.json")
    print("- Excel: output/enhanced_irm_matrix.xlsx")

if __name__ == "__main__":
    enhanced_irm = enhance_with_methods()
    save_enhanced_irm(enhanced_irm)
    print("IRM enhanced with collection methods and data sources")
