#!/usr/bin/env python
import os
import sys
import time
import re
import subprocess

def find_subdomains(domain):
    print(f"Finding subdomains for {domain}...")
    subdomains = []
    
    # Perform a subdomain enumeration using sublist3r
    print("Performing subdomain enumeration...")
    sublist3r_output = subprocess.check_output(["sublist3r", "-d", domain]).decode("utf-8")
    subdomains = sublist3r_output.split("\n")
    
    return subdomains

def highlight_important_parts(output):
    # Define the patterns to highlight
    patterns = [
        r"Vulnerable|Exploitable",  # Highlight words related to vulnerabilities
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # Highlight IP addresses
        r"\b\d{1,5}\b",  # Highlight numbers
        r"\b(high|critical|medium|low)\b",  # Highlight severity levels
        r"\b(open|closed)\b",  # Highlight port states
    ]
    
    # Compile the patterns into regular expressions
    regexes = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    
    # Highlight the important parts in the output
    highlighted_output = output
    for regex in regexes:
        highlighted_output = regex.sub(lambda match: f"\033[1;31m{match.group(0)}\033[0m", highlighted_output)
    
    return highlighted_output

def search_vulnerabilities(domain):
    print(f"Searching for vulnerabilities in {domain}...")
    
    # Perform a whois lookup
    print("Performing whois lookup...")
    whois_output = os.popen(f"whois {domain}").read()
    whois_output = highlight_important_parts(whois_output)
    
    # Perform a port scan using nmap
    print("Performing port scan...")
    port_scan_output = os.popen(f"nmap -sV {domain}").read()
    port_scan_output = highlight_important_parts(port_scan_output)
    
    # Perform a vulnerability scan using nikto
    print("Performing vulnerability scan...")
    try:
        nikto_output = os.popen(f"nikto -h {domain}").read()
        nikto_output = highlight_important_parts(nikto_output)
    except KeyboardInterrupt:
        print("\nVulnerability scan interrupted by the user.")
        return
    
    # Generate a safe file name for the report
    safe_domain = domain.replace(" ", "_").replace(".", "_")
    report_file_name = f"{safe_domain}_report.txt"
    
    # Generate the report
    report = f"""
    Vulnerability Report for {domain}
    
    Whois Lookup:
    {whois_output}
    
    Port Scan:
    {port_scan_output}
    
    Vulnerability Scan:
    {nikto_output}
    """
    
    # Save the report to a file
    with open(report_file_name, "w") as report_file:
        report_file.write(report)
    
    print("Vulnerability report generated successfully.")

def main():
    if len(sys.argv) < 2:
        print("Usage: hammersearch <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    
    # Introductory message
    print("Welcome to the hammersearch tool!")
    print("Made by Cipherdavy ! ")
    print("This tool helps you search for vulnerabilities in a given domain and its subdomains.")
    print("please dont steal my code [: ")
    print("Please wait while we perform the necessary scans...")
    time.sleep(3)
    
    # Find subdomains
    subdomains = find_subdomains(domain)
    
    # Perform vulnerability scans on the main domain and subdomains
    search_vulnerabilities(domain)
    for subdomain in subdomains:
        if subdomain != "":
            search_vulnerabilities(subdomain)

if __name__ == "__main__":
    main()
