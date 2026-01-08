# Reconix

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
```

**Network reconnaissance tool with custom brute force and web fuzzing engines**

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)

---

## Table of Contents

- [About](#about)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Interactive Menu](#interactive-menu)
- [Examples](#examples)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Legal Disclaimer](#legal-disclaimer)

---

## About

Reconix is a comprehensive network scanning framework designed for security professionals and penetration testers. It combines multiple reconnaissance and exploitation techniques into a single interactive tool with automated reporting capabilities.

**Version:** 1.0  
**Platform:** Linux (Kali/Ubuntu/Debian)  
**Requirements:** Python 3.8+, Root privileges

---

## Features

### Network Reconnaissance
- Multi-method host discovery (ICMP, TCP, ARP)
- Full port scanning (TCP/UDP)
- Service version detection
- Operating system fingerprinting
- Customizable timing and intensity

### Vulnerability Assessment
- Built-in vulnerability database
- CVE mapping for detected services
- Integration with searchsploit
- Automated exploit searching

### Exploitation Tools
- Metasploit resource script generation
- SSH/FTP/SMB brute force attacks
- Anonymous access testing
- Credential validation

### SMB Enumeration
- Share discovery and listing
- Permission testing
- Recursive file download
- Anonymous and authenticated access

### Web Application Testing
- Directory fuzzing
- Subdomain enumeration
- Virtual host discovery
- Multi-threaded scanning

### Reporting
- Interactive tree-view network maps
- Detailed HTML reports with charts
- JSON export functionality
- Security hardening recommendations

### Additional Features
- MITM attack capabilities (Responder integration)
- Post-scan interactive menu
- Color-coded output
- Progress indicators

---

## Installation

### Method 1: Automated Installation (Recommended)

```bash
git clone https://github.com/yourusername/reconix.git
cd reconix
chmod +x installer.sh
sudo ./installer.sh
```

The installer will:
- Update system packages
- Install required system tools
- Install Python dependencies
- Optionally install Metasploit and Responder
- Verify all installations

### Method 2: Manual Installation

#### Step 1: Install System Tools

```bash
sudo apt update
sudo apt install -y nmap exploitdb seclists python3 python3-pip git
```

#### Step 2: Install Python Dependencies

```bash
pip3 install -r requirements.txt
```

Or with system packages flag:

```bash
pip3 install -r requirements.txt --break-system-packages
```

#### Step 3: Install Optional Tools

**Metasploit Framework:**
```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
sudo ./msfinstall
```

**Responder:**
```bash
sudo apt install responder
```

Or:
```bash
git clone https://github.com/lgandx/Responder.git /opt/Responder
sudo ln -s /opt/Responder/Responder.py /usr/local/bin/responder
```

---

## Usage

### Basic Syntax

```bash
sudo python3 reconix.py [OPTIONS] <target>
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `<target>` | Target network or IP (e.g., 192.168.1.0/24) |
| `-h, --help` | Display help menu |
| `-sA, --all-ports` | Scan all 65535 ports |
| `-sF, --fast` | Fast scan (top 100 ports) |
| `-PA, --aggressive-discovery` | Aggressive host discovery |
| `-T0` to `-T5` | Timing template (0=paranoid, 5=insane) |
| `-o, --output FILE` | Save results to JSON file |
| `-v, --verbose` | Verbose output |
| `-q, --quiet` | Quiet mode |
| `--vuln-scan` | Enable vulnerability scanning |

---

## Interactive Menu

After completing a scan, Reconix presents an interactive menu:

```
[1] Deep Vulnerability Analysis    - Search exploits with searchsploit
[2] Attempt Exploitation           - Generate Metasploit resource scripts
[3] Brute Force Attacks            - SSH/FTP/SMB password attacks
[4] Generate Security Report       - Create HTML report with charts
[5] SMB Share Enumeration          - List and download SMB shares
[6] Web Application Scanning       - Directory/subdomain/vhost fuzzing
[7] Get Hardening Recommendations  - Security improvement suggestions
[8] Man-in-the-Middle              - Network poisoning with Responder
[9] Re-scan Options                - Restart with new parameters
[0] Exit
```

---

## Examples

### Example 1: Basic Network Scan

```bash
sudo python3 reconix.py 192.168.1.0/24
```

Scans entire subnet with default settings (top 1000 ports).

### Example 2: Fast Scan

```bash
sudo python3 reconix.py -sF 10.0.0.0/24
```

Quick scan of top 100 ports for faster results.

### Example 3: Comprehensive Scan

```bash
sudo python3 reconix.py -sA -T4 192.168.1.0/24
```

Scans all 65535 ports with aggressive timing.

### Example 4: Accurate Host Discovery

```bash
sudo python3 reconix.py -PA 172.16.0.0/24
```

Uses port probing for accurate host detection.

### Example 5: Single Host Deep Scan

```bash
sudo python3 reconix.py -sA --vuln-scan 192.168.1.100
```

Full port scan with vulnerability detection on single host.

### Example 6: Save Results

```bash
sudo python3 reconix.py -o results.json 192.168.1.0/24
```

Saves scan results to JSON file.

### Example 7: Quiet Mode

```bash
sudo python3 reconix.py -q -o scan.json 10.0.0.0/24
```

Minimal output, saves to file only.

---

## Configuration

### Wordlist Locations

Reconix expects SecLists in standard locations:

```
/usr/share/seclists/Discovery/Web-Content/
/usr/share/seclists/Discovery/DNS/
```

Install SecLists:
```bash
sudo apt install seclists
```

### Custom Wordlists

When prompted during fuzzing, you can specify custom wordlist paths:

```
Enter custom wordlist path: /path/to/custom/wordlist.txt
```

### Timing Templates

| Template | Speed | Use Case |
|----------|-------|----------|
| `-T0` | Paranoid | IDS evasion |
| `-T1` | Sneaky | IDS evasion |
| `-T2` | Polite | Low bandwidth |
| `-T3` | Normal | Default |
| `-T4` | Aggressive | Fast networks |
| `-T5` | Insane | Very fast networks |

---

## Troubleshooting

### Common Issues

**Issue: Permission denied**
```bash
# Solution: Run with sudo
sudo python3 reconix.py <target>
```

**Issue: Module not found (python-nmap, impacket, etc.)**
```bash
# Solution: Reinstall dependencies
pip3 install -r requirements.txt --break-system-packages
```

**Issue: searchsploit not found**
```bash
# Solution: Install exploitdb
sudo apt install exploitdb
```

**Issue: SecLists wordlists missing**
```bash
# Solution: Install seclists
sudo apt install seclists
```

**Issue: Impacket SMB errors**
```bash
# Solution: Upgrade impacket
pip3 install impacket --upgrade
```

**Issue: Responder not found**
```bash
# Solution: Install responder
sudo apt install responder
```

**Issue: No hosts discovered**
```bash
# Solution: Try aggressive discovery
sudo python3 reconix.py -PA <target>
```

### Dependency Verification

Check if all dependencies are installed:

```bash
# System tools
which nmap
which searchsploit
which msfconsole
which responder

# Python modules
python3 -c "import nmap; import paramiko; import impacket; import requests"
```

---

## Legal Disclaimer

**IMPORTANT: READ BEFORE USE**

This tool is provided for educational purposes and authorized security testing only.

**You must have explicit written permission before:**
- Scanning any network you do not own
- Testing any system you do not own
- Accessing any computer system without authorization

**Unauthorized access to computer systems is illegal and may result in:**
- Criminal prosecution
- Civil liability
- Fines and imprisonment

**By using this tool, you agree to:**
- Use it only on systems you own or have authorization to test
- Comply with all applicable laws and regulations
- Accept full responsibility for your actions

The author is not responsible for misuse or damage caused by this tool.

---

## Requirements

### System Requirements
- Operating System: Linux (Kali Linux, Ubuntu, Debian)
- Python Version: 3.8 or higher
- Privileges: Root/sudo access

### Network Requirements
- Active network interface
- Internet connection (for exploit database updates)
- Appropriate network permissions

### Software Dependencies
- nmap
- python3-nmap
- paramiko
- impacket
- requests
- exploitdb
- seclists (optional)
- metasploit (optional)
- responder (optional)

---

## Project Structure

```
reconix/
│
├── reconix.py              # Main executable
├── installer.sh            # Automated installation script
├── requirements.txt        # Python dependencies
├── README.md              # This file
│
├── reports/               # Generated reports (created at runtime)
│   ├── reconix_report_*.json
│   └── reconix_report_*.html
│
└── exploits/              # Generated exploit scripts (created at runtime)
    └── reconix_exploit_*.rc
```

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Test your changes thoroughly
4. Submit a pull request with clear description

---

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing issues first
- Provide detailed information about your problem

---

## Acknowledgments

- Nmap Project
- Metasploit Framework
- Impacket Library
- SecLists Project
- Responder Tool

---

## License

This project is provided as-is for educational and authorized security testing purposes.

---

**Author:** [Sawsagee](https://github.com/Aditya-k-Jangid)  
**Version:** 1.0  
**Last Updated:** 2026

---
