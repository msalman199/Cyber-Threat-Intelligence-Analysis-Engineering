from intel_enricher import IntelligenceEnricher

enricher = IntelligenceEnricher()
test_text = "Malicious IP 192.168.1.1 and domain evil.com detected"
iocs = enricher.extract_iocs(test_text)
print("Extracted IOCs:", iocs)
