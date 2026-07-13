#!/usr/bin/env python3

import re
import json

class IOCExtractor:
    def __init__(self):
        self.patterns = {
            'domains': r'[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})',
            'ips': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'md5_hashes': r'\b[a-fA-F0-9]{32}\b',
            'registry_keys': r'HK[A-Z_]+\\[\\a-zA-Z0-9_\s]+',
            'file_paths': r'[A-Za-z]:\\[\\a-zA-Z0-9_\s\.%]+|%[A-Z]+%\\[\\a-zA-Z0-9_\s\.]+'
        }
    
    def extract_iocs(self, text):
        iocs = {}
        
        for ioc_type, pattern in self.patterns.items():
            matches = re.findall(pattern, text)
            if ioc_type == 'domains':
                # Filter out common false positives
                matches = [match[0] + '.' + match[1] if isinstance(match, tuple) else match 
                          for match in matches]
                matches = [m for m in matches if not m.endswith(('.txt', '.py', '.exe'))]
            
            iocs[ioc_type] = list(set(matches)) if matches else []
        
        return iocs
    
    def generate_yara_rule(self, iocs):
        rule = '''rule Operation_Aurora_Indicators {
    meta:
        description = "Operation Aurora IOCs"
        author = "Threat Intelligence Team"
        date = "2024-01-01"
    
    strings:'''
        
        for i, domain in enumerate(iocs.get('domains', [])[:5]):
            rule += f'\n        $domain{i} = "{domain}" nocase'
        
        for i, hash_val in enumerate(iocs.get('md5_hashes', [])[:3]):
            rule += f'\n        $hash{i} = "{hash_val}" nocase'
        
        rule += '''
    
    condition:
        any of them
}'''
        return rule

if __name__ == "__main__":
    extractor = IOCExtractor()
    
    # Read IOC data
    with open('../indicators/iocs.txt', 'r') as f:
        ioc_data = f.read()
    
    # Extract IOCs
    extracted_iocs = extractor.extract_iocs(ioc_data)
    
    print("EXTRACTED INDICATORS OF COMPROMISE")
    print("=" * 35)
    
    for ioc_type, indicators in extracted_iocs.items():
        if indicators:
            print(f"\n{ioc_type.upper()}:")
            for indicator in indicators:
                print(f"  - {indicator}")
    
    # Generate YARA rule
    yara_rule = extractor.generate_yara_rule(extracted_iocs)
    
    with open('../analysis/aurora_detection.yar', 'w') as f:
        f.write(yara_rule)
    
    print(f"\nYARA rule generated: ../analysis/aurora_detection.yar")
