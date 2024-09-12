[![hammer-scan-logo.jpg](https://i.postimg.cc/XY67yg5Y/hammer-scan-logo.jpg)](https://postimg.cc/9r1j6Z16)

# Hammersearch

This project is an advanced vulnerability searching tool that helps penetration testers and security researchers search for vulnerabilities in a given domain and its subdomains. The tool uses various tools and techniques to perform scans and vulnerability assessments, including:

- Whois lookup: Retrieves information about the domain owner.
- Port scan: Identifies open ports and services running on them.
- Vulnerability scan: Checks for known vulnerabilities using tools like Nikto.
- Directory enumeration: Attempts to find web directories and files using tools like Dirb.
- WordPress vulnerability scan: Checks for WordPress-specific vulnerabilities using WPScan.

The tool is designed for ethical and authorized penetration testing and security auditing purposes. It should only be used with proper consent and ethical boundaries in mind.

This tool is intended for use by penetration testers, security researchers, and anyone else interested in conducting security assessments on websites and networks.
## Appendix

Dependencies:

whois,
nmap,
nikto,
sublist3r

* *Permissions*: Use with caution and obtain proper consent
Output

* *Handling*: Handle output carefully in a production environment

* *Error Handling*: Include error handling in a production environment

* *Performance Considerations*: Run on a system with sufficient resources

* *Security Considerations*: Use responsibly and obtain proper consent

* *Maintenance and Updates*: Keep the tool updated with latest patches and vulnerabilities
## Author

- [@cypherdavy](https://github.com/cypherdavy)


## Demo

video tutorial: 
https://streamable.com/9qbv4i

## Features

- whoislookup
- port scan
- vuln scan
- directory enumeration
- wordpress vuln scan
- report 


## Installation

**Clone the repository from GitHub:**

```bash
  git clone https://github.com/cypherdavy/Hammersearch.git
```
**Navigate to the cloned directory:**

    
```bash
   cd Hammersearch
```

**Install the required dependencies:**

*whois: Used for performing whois lookups.
nmap: Used for performing port scans.
nikto: Used for performing vulnerability scans.
sublist3r: Used for finding subdomains (if you want to include the subdomain enumeration feature).*
```bash
  sudo apt-get install whois nmap nikto sublist3r
```
**Make the script executable:**

   
  ```bash
  chmod +x hammersearch.py
```
  **Run the tool:**

  ```bash
  ./hammersearch.py <domain>
```
## Screenshots

[![hammer.jpg](https://i.postimg.cc/VNr8GrnV/hammer.jpg)](https://postimg.cc/gwWQr0MV)

[![hammer-scan.jpg1](https://i.postimg.cc/BQ4JSvfj/hammer-scan.jpg)](https://postimg.cc/Jt6fKMn8)

[![reporthammer.jpg](https://i.postimg.cc/xdwSWfPT/reporthammer.jpg)](https://postimg.cc/rdNb4Lbv)
