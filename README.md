# MDIR

<p align="center">
  <img src="assets/mdir-banner.png" alt="MDIR Banner" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-red">
  <img src="https://img.shields.io/badge/Version-10.0-success">
  <img src="https://img.shields.io/badge/License-MIT-green">
</p>

MDIR is a high-performance **directory and endpoint discovery tool for Kali Linux**, built for penetration testers, bug bounty hunters, and security researchers. It performs fast asynchronous scanning to discover hidden directories, API endpoints, admin panels, and sensitive files while generating professional reports.

---

## Features

- Fast Asynchronous Directory Enumeration
- Hidden Endpoint Discovery
- API Enumeration
- Admin Panel Discovery
- Sensitive File Detection
- HTTP Status Analysis (200, 301, 302, 401, 403)
- Custom Wordlist Support
- Multi-threaded Scanning
- HTML, JSON & TXT Reports
- Designed for Kali Linux
- Bug Bounty Friendly

---

## Requirements

- Kali Linux
- Python 3.10+
- aiohttp
- uvloop (optional)

---

## Installation

```bash
git clone https://github.com/MAHABUB122003/MDIR.git

cd MDIR

pip3 install -r requirements.txt
```

or

```bash
pip3 install aiohttp uvloop
```

---

## Usage

Basic Scan

```bash
python3 mdir.py -u https://example.com
```

Aggressive Scan

```bash
python3 mdir.py -u https://example.com -a
```

API Discovery

```bash
python3 mdir.py -u https://example.com -A
```

Sensitive Scan

```bash
python3 mdir.py -u https://example.com -S
```

Custom Wordlist

```bash
python3 mdir.py -u https://example.com -w /usr/share/wordlists/dirb/common.txt
```

Save HTML Report

```bash
python3 mdir.py -u https://example.com -o report.html
```

---

## Screenshot

<p align="center">
<img src="assets/dashboard.png" width="100%">
</p>

---

## Technologies

- Python
- AsyncIO
- AIOHTTP
- uvloop
- HTML
- JSON

---

## Author

**MD MAHABUBUR RAHMAN**

GitHub: https://github.com/MAHABUB122003

---

## Disclaimer

This tool is intended only for authorized penetration testing, bug bounty programs, and security research. Always obtain permission before testing any target.
