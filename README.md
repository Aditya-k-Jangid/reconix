# Reconix 🔍

<div align="center">

```
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗██╗  ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║╚██╗██╔╝
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║ ╚███╔╝ 
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║ ██╔██╗ 
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║██╔╝ ██╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
```

**Advanced Network Reconnaissance & Security Assessment Framework**

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)
[![Kali](https://img.shields.io/badge/Kali-Linux-blue.svg)](https://www.kali.org/)

*A comprehensive toolkit for security professionals and penetration testers*

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Interactive Modules](#-interactive-modules)
- [Examples](#-examples)
- [Contributing](#-contributing)
- [Legal Disclaimer](#%EF%B8%8F-legal-disclaimer)
- [License](#-license)

---

## 🎯 Overview

**Reconix** is a powerful all-in-one network reconnaissance and security assessment framework designed for penetration testers, security researchers, and red team operations. It combines multiple industry-standard security tools into a unified interface with an intuitive command-line experience.

Built with efficiency and extensibility in mind, Reconix automates the entire security assessment workflow - from initial network discovery to vulnerability exploitation and reporting.

### 🌟 Why Reconix?

- **All-in-One Solution** - Integrates 10+ security tools in a single framework
- **Interactive Workflow** - Post-scan menu system for seamless operation flow
- **Professional Reporting** - Generate comprehensive HTML reports for clients
- **Time-Saving** - Automates repetitive reconnaissance tasks
- **Extensible** - Modular architecture for easy customization
- **Beginner-Friendly** - Clear prompts and guidance throughout

---

## ✨ Features

### 🔍 **Network Reconnaissance**
- **Advanced Host Discovery** - Accurate detection with multiple scan modes
- **Port Scanning** - Fast, comprehensive, and customizable scans
- **Service Enumeration** - Identify running services and versions
- **OS Fingerprinting** - Detailed operating system detection
- **Network Topology Mapping** - Visual representation of network structure

### 🛡️ **Vulnerability Assessment**
- **Deep Vulnerability Analysis** - Automated searchsploit integration
- **CVE Database Lookup** - Real-time exploit availability checking
- **Service Version Analysis** - Match detected services against known vulnerabilities
- **Risk Categorization** - Severity-based vulnerability classification
- **Professional Reporting** - Generate detailed HTML security reports

### 🎯 **Exploitation & Offensive Testing**
- **Guided Exploitation** - Step-by-step Metasploit setup assistance
- **Multi-Mode Brute Force**:
  - Password Spray Attack
  - User Enumeration Attack  
  - Full Credential Brute Force
- **SMB/CIFS Enumeration** - Share discovery and automated file extraction
- **Web Application Testing** - Directory brute forcing with custom wordlists
- **MITM Capabilities** - Responder integration for credential interception
- **Protocol Support** - SSH, FTP, SMB, RDP, HTTP/HTTPS

### 🔐 **Defensive Security**
- **Security Hardening Guidance** - Tailored recommendations based on findings
- **Best Practices Assessment** - Industry-standard security checks
- **Configuration Analysis** - Identify misconfigurations and weak settings
- **Remediation Advice** - Actionable steps to improve security posture

### 📊 **Reporting & Output**
- **Multiple Export Formats** - JSON for automation, HTML for presentation
- **Visual Network Maps** - Tree-structure topology diagrams  
- **Detailed Findings** - Comprehensive vulnerability descriptions
- **Executive Summaries** - High-level overview for stakeholders
- **Timestamped Reports** - Organized documentation for compliance

---

## 🚀 Installation

### Prerequisites

- **Operating System**: Linux (Kali Linux, Ubuntu, Debian, Parrot OS)
- **Python**: 3.8 or higher
- **Privileges**: Root/sudo access required
- **Network**: Internet connection for dependency installation

### Automatic Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/reconix.git
cd reconix

# Make installer executable
chmod +x install.sh

# Run automated installation
sudo ./install.sh
```

The installer will automatically:
- ✅ Install Python dependencies
- ✅ Install all required security tools
- ✅ Download and configure wordlists
- ✅ Verify all installations
- ✅ Make Reconix executable

### Manual Installation

<details>
<summary>Click to expand manual installation steps</summary>

```bash
# Update package list
sudo apt update

# Install Python and dependencies
sudo apt install -y python3 python3-pip
pip3 install python-nmap

# Install security tools
sudo apt install -y nmap exploitdb metasploit-framework hydra
sudo apt install -y smbclient enum4linux smbmap gobuster dirb responder

# Install wordlists
sudo apt install -y seclists wordlists

# Extract rockyou.txt if needed
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Make Reconix executable
chmod +x reconix.py
```

</details>

### Verify Installation

```bash
# Check Reconix
python3 reconix.py -h

# Verify installed tools
nmap --version
searchsploit --version
hydra -h
```

---

## 💻 Usage

### Basic Syntax

```bash
sudo python3 reconix.py [OPTIONS] <target>
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Display help menu |
| `-V, --version` | Show version information |
| `-sF, --fast` | Fast scan (top 100 ports) |
| `-sA, --all-ports` | Scan all 65535 ports |
| `-PA, --aggressive-discovery` | Accurate host discovery mode |
| `-T0` to `-T5` | Timing template (0=slowest, 5=fastest) |
| `-sn, --ping-only` | Host discovery only (no port scan) |
| `-o, --output <file>` | Save results to JSON file |
| `-v, --verbose` | Increase output verbosity |
| `-q, --quiet` | Minimal output mode |

### Quick Start Examples

```bash
# Basic network scan
sudo python3 reconix.py 192.168.1.0/24

# Accurate host discovery (recommended)
sudo python3 reconix.py -PA 172.16.8.0/24

# Fast scan with aggressive timing
sudo python3 reconix.py -sF -T4 10.0.0.0/24

# Scan all ports on single target
sudo python3 reconix.py -sA 192.168.1.100

# Quiet mode with JSON output
sudo python3 reconix.py -q -o results.json 192.168.1.0/24

# Host discovery only
sudo python3 reconix.py -sn 10.10.10.0/24
```

---

## 🎮 Interactive Modules

After the initial scan completes, Reconix presents an interactive menu with the following modules:

### Main Menu

```
╔══════════════════════════════════════════════════════════════╗
║              WHAT WOULD YOU LIKE TO DO NEXT?                 ║
╚══════════════════════════════════════════════════════════════╝

[1]  🔍 Deep Vulnerability Analysis (searchsploit)
[2]  🎯 Attempt Exploitation (Metasploit)
[3]  🔨 Brute Force Attacks (SSH/SMB/RDP)
[4]  📊 Generate Security Report (HTML)
[5]  🗂️  SMB Share Enumeration
[6]  🌐 Web Application Scanning
[7]  🛡️  Get Hardening Recommendations
[8]  🔴 Man-in-the-Middle (Responder)
[9]  🔄 Re-scan Options
[0]  🚪 Exit
```

### Module Descriptions

#### 1️⃣ Deep Vulnerability Analysis
- Searches ExploitDB for known exploits
- Matches service versions against vulnerability database
- Displays available exploits with CVE references
- Provides exploit paths and descriptions

#### 2️⃣ Attempt Exploitation
- Lists all discovered vulnerabilities
- Interactive exploit selection
- Guides Metasploit configuration (LHOST, LPORT, etc.)
- Generates ready-to-use Metasploit commands

#### 3️⃣ Brute Force Attacks
Three attack modes available:
- **Password Spray**: Test one password against multiple users
- **User Spray**: Test one username against multiple passwords
- **Full Brute Force**: Test all username/password combinations

Supports: SSH, FTP, SMB, RDP, Telnet

#### 4️⃣ Generate Security Report
- Creates professional HTML report
- Includes all findings and vulnerabilities
- Color-coded risk levels
- Timestamped for documentation
- Ready for client delivery

#### 5️⃣ SMB Share Enumeration
- Lists all available SMB shares
- Checks permissions and access levels
- Option to download shares automatically
- Supports null sessions and guest access

#### 6️⃣ Web Application Scanning
- Directory and file discovery
- Custom wordlist support
- Uses gobuster or dirb
- Identifies hidden resources
- Configurable thread count

#### 7️⃣ Hardening Recommendations
- Service-specific security advice
- Configuration best practices
- Port closure recommendations
- Protocol upgrade suggestions (e.g., FTP → SFTP)
- General security hardening tips

#### 8️⃣ Man-in-the-Middle (Responder)
- Network poisoning attacks
- Credential interception
- Multiple protocol support (HTTP, SMB, SQL)
- Analysis mode for passive monitoring
- Hash collection and cracking

---

## 📚 Examples

### Example 1: Full Network Assessment

```bash
# Step 1: Perform comprehensive scan
sudo python3 reconix.py -PA 192.168.1.0/24

# Step 2: From interactive menu
# - Select [1] for vulnerability analysis
# - Select [4] to generate HTML report
# - Select [7] for hardening recommendations
```

### Example 2: Web Application Testing

```bash
# Step 1: Scan target network
sudo python3 reconix.py 10.10.10.0/24

# Step 2: From interactive menu
# - Select [6] for web scanning
# - Choose discovered web service
# - Provide custom wordlist or use default
```

### Example 3: SMB Enumeration

```bash
# Step 1: Scan for SMB services
sudo python3 reconix.py -PA 172.16.8.0/24

# Step 2: From interactive menu
# - Select [5] for SMB enumeration
# - Choose target host
# - Download all accessible shares
```

### Example 4: Credential Attack

```bash
# Step 1: Identify services
sudo python3 reconix.py -PA 192.168.1.0/24

# Step 2: From interactive menu
# - Select [3] for brute force
# - Choose SSH service
# - Select "Password Spray" mode
# - Provide username list and single password
```

---

## 🔧 Configuration

### Wordlist Locations

Default wordlists installed by `install.sh`:

```
/usr/share/wordlists/rockyou.txt           # Password list
/usr/share/wordlists/dirb/common.txt       # Web directories
/usr/share/seclists/                       # SecLists collection
```

### Custom Wordlists

You can use custom wordlists by providing the full path when prompted:

```bash
# Example: Custom password list
/home/user/custom-passwords.txt

# Example: Custom directory wordlist
/opt/wordlists/web-dirs.txt
```

### Output Files

Reconix generates the following files:

```
reconix_report.json                        # Default JSON output
reconix_report_YYYYMMDD_HHMMSS.html       # Timestamped HTML reports
smb_<IP>_<share>/                         # Downloaded SMB shares
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/AmazingFeature`)
3. **Commit your changes** (`git commit -m 'Add some AmazingFeature'`)
4. **Push to the branch** (`git push origin feature/AmazingFeature`)
5. **Open a Pull Request**

### Development Guidelines

- Follow PEP 8 style guidelines for Python code
- Add comments for complex functions
- Test thoroughly before submitting PR
- Update documentation for new features

---

## ⚠️ Legal Disclaimer

**IMPORTANT - READ CAREFULLY**

This tool is provided for **EDUCATIONAL and AUTHORIZED TESTING PURPOSES ONLY**.

### Legal Usage Requirements

- ✅ You **MUST** have explicit written permission to test target networks
- ✅ Only use on networks you own or have authorization to test
- ✅ Obtain proper consent before conducting any security assessments
- ✅ Comply with all applicable local, state, and federal laws

### Prohibited Activities

- ❌ Unauthorized access to computer systems or networks
- ❌ Scanning networks without permission
- ❌ Using discovered vulnerabilities for malicious purposes
- ❌ Distributing or selling discovered vulnerabilities

### Liability

The authors and contributors of Reconix:
- Are **NOT** responsible for misuse of this tool
- Are **NOT** liable for any damages caused by unauthorized use
- **STRONGLY DISCOURAGE** any illegal activities

**Unauthorized network scanning and penetration testing is ILLEGAL and punishable by law.**

By using Reconix, you agree to use it responsibly and ethically.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 Reconix

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 👨‍💻 Author

**Reconix Development Team**

- GitHub: [@yourusername](https://github.com/yourusername)
- Website: [reconix-tool.com](https://reconix-tool.com) *(Coming Soon)*

---

## 🙏 Acknowledgments

Reconix integrates and builds upon these excellent open-source projects:

- **Nmap** - Network scanning and port discovery
- **Metasploit Framework** - Exploitation framework
- **Hydra** - Network authentication cracker
- **Responder** - LLMNR, NBT-NS and MDNS poisoner
- **Gobuster** - Directory/file brute forcing
- **SearchSploit** - ExploitDB command line search
- **SecLists** - Security testing wordlists

---

## 📞 Support

- **Bug Reports**: Open an issue on GitHub
- **Feature Requests**: Submit via GitHub Issues
- **Security Issues**: Email security@reconix-tool.com

---

## 🗺️ Roadmap

### Planned Features

- [ ] GUI interface with Qt/Tkinter
- [ ] Database integration for result storage
- [ ] API endpoint support
- [ ] Custom module plugin system
- [ ] Automated report scheduling
- [ ] Docker container support
- [ ] Cloud deployment options
- [ ] Integration with Burp Suite
- [ ] Machine learning-based vulnerability prioritization

---

<div align="center">

**⭐ If you find Reconix useful, please consider giving it a star! ⭐**

**Made with ❤️ for the Cybersecurity Community**

</div>
