#!/bin/bash
echo "=== ADVERSARY INFRASTRUCTURE ANALYSIS REPORT ===" > final_report.txt
echo "Generated on: $(date)" >> final_report.txt
echo "" >> final_report.txt

echo "=== DOMAIN ENUMERATION SUMMARY ===" >> final_report.txt
echo "Total domains discovered: $(wc -l < amass_results.txt)" >> final_report.txt
echo "Passive enumeration results: $(wc -l < amass_passive.txt)" >> final_report.txt
echo "" >> final_report.txt

echo "=== TOP 10 DISCOVERED DOMAINS ===" >> final_report.txt
head -10 amass_results.txt >> final_report.txt
echo "" >> final_report.txt

echo "=== IP ADDRESS MAPPINGS ===" >> final_report.txt
echo "Domain to IP mappings found: $(wc -l < domain_ip_mapping.csv)" >> final_report.txt
head -5 domain_ip_mapping.csv >> final_report.txt
echo "" >> final_report.txt

echo "=== INFRASTRUCTURE CORRELATION ===" >> final_report.txt
head -10 infrastructure_map.csv >> final_report.txt
echo "" >> final_report.txt

echo "=== ANALYSIS COMPLETE ===" >> final_report.txt
