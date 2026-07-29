# MDIR - Advanced Directory & Endpoint Discovery Framework

<p align="center">
  <img src="https://github.com/MAHABUB122003/MDIR/blob/main/assets/MDIR%20(2).png" alt="MDIR Banner" width="100%">
</p>

<p align="center">
  <b>High-Speed Asynchronous Web Directory and Endpoint Enumeration Framework for Security Testing</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-red?logo=kalilinux">
  <img src="https://img.shields.io/badge/Version-1.0.0-success">
  <img src="https://img.shields.io/badge/License-MIT-green">
  <img src="https://img.shields.io/github/stars/MAHABUB122003/MDIR?style=social">
</p>

---

# Overview

**MDIR (Mahabub Directory Intelligence Recon)** is an advanced asynchronous web discovery framework designed for penetration testers, bug bounty hunters, and cybersecurity researchers.

MDIR performs high-speed directory and endpoint enumeration to identify exposed resources, hidden paths, administrative interfaces, API endpoints, and sensitive files during authorized security assessments.

Built with Python asynchronous technology, MDIR provides efficient scanning performance, customizable wordlist support, and structured security reporting.

---

# Features

## Performance

- High-speed asynchronous scanning
- Concurrent endpoint discovery
- Optimized HTTP request processing
- Large wordlist compatibility
- Lightweight command-line interface

---

## Discovery Capabilities

MDIR supports:

- Directory enumeration
- Hidden endpoint discovery
- API endpoint detection
- Administrative panel discovery
- Sensitive file identification
- Backup file detection
- Custom path discovery

---

## HTTP Response Analysis

Analyze web server responses including:

| Status Code | Description |
|-------------|-------------|
| `200` | Successful Response |
| `301` | Permanent Redirect |
| `302` | Temporary Redirect |
| `401` | Authentication Required |
| `403` | Access Forbidden |

---

## Reporting System

Generate detailed scan reports:

Supported formats:

- HTML
- JSON
- TXT

Example:

```bash
python3 mdir.py \
-u https://target.com \
-o report.html
Security Research Features
Custom wordlist support
Bug bounty workflow integration
Kali Linux optimized environment
Fast endpoint discovery
Flexible scanning options
Professional report generation
Installation
Clone Repository
git clone https://github.com/MAHABUB122003/MDIR.git
Navigate to Directory
cd MDIR
Install Dependencies
pip3 install -r requirements.txt
Requirements
Component	Requirement
Operating System	Kali Linux / Linux
Python Version	3.10+
Dependencies	requirements.txt
Network	Internet Connection
Usage
Basic Directory Scan
python3 mdir.py -u https://target.com
Aggressive Scan

Perform extended endpoint discovery:

python3 mdir.py \
-u https://target.com \
-a
API Discovery

Search for API endpoints:

python3 mdir.py \
-u https://target.com \
-A
Sensitive File Scan

Identify potentially exposed files:

python3 mdir.py \
-u https://target.com \
-S
Custom Wordlist

Use a custom discovery wordlist:

python3 mdir.py \
-u https://target.com \
-w /usr/share/wordlists/dirb/common.txt
Generate HTML Report
python3 mdir.py \
-u https://target.com \
-o report.html
Project Structure
MDIR/

├── mdir.py
├── requirements.txt
├── README.md

├── assets/
│   ├── MDIR.png
│   └── dashboard.png

├── reports/
│   └── scan-results

└── wordlists/
    └── custom-wordlists
Screenshot
<p align="center"> <img src="https://github.com/MAHABUB122003/MDIR/blob/main/assets/dashboard.png" alt="MDIR Screenshot" width="100%"> </p>
Technology Stack
Technology	Purpose
Python 3	Core Framework
AsyncIO	Asynchronous Processing
AIOHTTP	HTTP Request Engine
uvloop	Performance Optimization
JSON	Data Processing
HTML	Report Generation
Use Cases

MDIR can be used for:

Authorized penetration testing
Bug bounty reconnaissance
Web application security assessment
Security research
CTF environments
Internal security auditing
Ethical Usage

MDIR is developed for authorized security testing and defensive research.

Always obtain permission before scanning any website, application, or infrastructure.

Unauthorized security testing may violate laws and regulations.

The developer is not responsible for misuse or illegal activities performed using this tool.

Author
MD MAHABUBUR RAHMAN

Cybersecurity Specialist
Full Stack Developer
Machine Learning Engineer

GitHub:

https://github.com/MAHABUB122003

License

This project is licensed under the MIT License.

<p align="center"> Built for Cybersecurity Research and Defensive Security Testing </p> ```
