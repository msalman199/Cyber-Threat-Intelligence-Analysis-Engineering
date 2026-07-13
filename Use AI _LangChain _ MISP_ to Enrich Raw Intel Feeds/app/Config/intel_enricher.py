#!/usr/bin/env python3

import json
import re
import requests
from pymisp import PyMISP
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document
from misp_config import MISP_CONFIG
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IntelligenceEnricher:
    def __init__(self):
        self.misp = PyMISP(
            url=MISP_CONFIG['url'],
            key=MISP_CONFIG['key'],
            ssl=MISP_CONFIG['ssl'],
            debug=MISP_CONFIG['debug']
        )
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200
        )
    
    def extract_iocs(self, text):
        """Extract IOCs from raw text using regex patterns"""
        iocs = {
            'ips': [],
            'domains': [],
            'urls': [],
            'hashes': [],
            'emails': []
        }
        
        # IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        iocs['ips'] = re.findall(ip_pattern, text)
        
        # Domain names
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b'
        iocs['domains'] = re.findall(domain_pattern, text)
        iocs['domains'] = ['.'.join(domain) for domain in iocs['domains']]
        
        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        iocs['urls'] = re.findall(url_pattern, text)
        
        # Hash values (MD5, SHA1, SHA256)
        hash_patterns = [
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b',  # SHA1
            r'\b[a-fA-F0-9]{64}\b'   # SHA256
        ]
        for pattern in hash_patterns:
            iocs['hashes'].extend(re.findall(pattern, text))
        
        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        iocs['emails'] = re.findall(email_pattern, text)
        
        return iocs
    
    def enrich_with_misp(self, iocs):
        """Enrich IOCs using MISP database"""
        enriched_data = {}
        
        for ioc_type, ioc_list in iocs.items():
            enriched_data[ioc_type] = []
            for ioc in ioc_list:
                try:
                    # Search for existing IOC in MISP
                    search_result = self.misp.search(value=ioc)
                    if search_result:
                        enriched_data[ioc_type].append({
                            'value': ioc,
                            'misp_data': search_result,
                            'threat_level': 'Known threat' if search_result else 'Unknown'
                        })
                    else:
                        enriched_data[ioc_type].append({
                            'value': ioc,
                            'misp_data': None,
                            'threat_level': 'Unknown'
                        })
                except Exception as e:
                    logger.error(f"Error enriching {ioc}: {str(e)}")
                    enriched_data[ioc_type].append({
                        'value': ioc,
                        'misp_data': None,
                        'threat_level': 'Error',
                        'error': str(e)
                    })
        
        return enriched_data
    
    def create_misp_event(self, enriched_data, event_info="Automated Intel Feed Analysis"):
        """Create a new MISP event with enriched IOCs"""
        try:
            event = self.misp.new_event(
                distribution=0,
                threat_level_id=2,
                analysis=1,
                info=event_info
            )
            
            event_id = event['Event']['id']
            
            # Add attributes to the event
            for ioc_type, ioc_list in enriched_data.items():
                for ioc_data in ioc_list:
                    if ioc_data['value']:
                        attribute_type = self.map_ioc_type_to_misp(ioc_type)
                        if attribute_type:
                            self.misp.add_attribute(
                                event_id,
                                attribute_type,
                                ioc_data['value'],
                                comment=f"Auto-extracted from intel feed - {ioc_data['threat_level']}"
                            )
            
            logger.info(f"Created MISP event {event_id} with enriched IOCs")
            return event_id
            
        except Exception as e:
            logger.error(f"Error creating MISP event: {str(e)}")
            return None
    
    def map_ioc_type_to_misp(self, ioc_type):
        """Map IOC types to MISP attribute types"""
        mapping = {
            'ips': 'ip-dst',
            'domains': 'domain',
            'urls': 'url',
            'hashes': 'md5',  # Default to MD5, could be improved
            'emails': 'email-src'
        }
        return mapping.get(ioc_type)
    
    def process_intel_feed(self, raw_text):
        """Main processing function"""
        logger.info("Starting intelligence feed processing...")
        
        # Extract IOCs
        iocs = self.extract_iocs(raw_text)
        logger.info(f"Extracted IOCs: {sum(len(v) for v in iocs.values())} total")
        
        # Enrich with MISP
        enriched_data = self.enrich_with_misp(iocs)
        
        # Create MISP event
        event_id = self.create_misp_event(enriched_data)
        
        return {
            'extracted_iocs': iocs,
            'enriched_data': enriched_data,
            'misp_event_id': event_id
        }

def main():
    # Sample raw intelligence feed data
    sample_intel_feed = """
    Threat Report: APT Group Activity
    
    Recent analysis has identified malicious activity from IP addresses 192.168.1.100 and 10.0.0.50.
    The threat actors are using domain malicious-site.com and evil-domain.net for C2 communication.
    
    Malware samples with hashes:
    MD5: 5d41402abc4b2a76b9719d911017c592
    SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
    
    Phishing emails observed from attacker@malicious-site.com targeting victims.
    
    Additional IOCs:
    - URL: http://malicious-site.com/payload.exe
    - IP: 203.0.113.42
    """
    
    enricher = IntelligenceEnricher()
    results = enricher.process_intel_feed(sample_intel_feed)
    
    print("\n=== Intelligence Enrichment Results ===")
    print(json.dumps(results, indent=2, default=str))

if __name__ == "__main__":
    main()
