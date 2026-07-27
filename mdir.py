#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MDIR v10.0 - ULTIMATE Discovery Tool
Final Version - Finds Everything
"""

import asyncio
import aiohttp
import argparse
import json
import sys
import os
import time
import random
import re
from datetime import datetime
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse
import signal
from collections import defaultdict

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

# ==============================================
# Configuration
# ==============================================
VERSION = "10.0.0"
MAX_CONCURRENT = 500
TIMEOUT = 4
BATCH_SIZE = 500
CONNECTION_LIMIT = 1000

# ==============================================
# ULTIMATE Colors
# ==============================================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BLACK = '\033[30m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'
    NC = '\033[0m'

DISABLE_COLORS = False

def get_colors():
    if DISABLE_COLORS:
        class NoColors:
            def __getattr__(self, name):
                return ''
        return NoColors()
    return Colors

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]

# ==============================================
# Finding Class
# ==============================================
class Finding:
    __slots__ = ['path', 'url', 'status', 'size', 'time', 'severity', 'status_type']
    
    def __init__(self, path: str, url: str, status: int, size: int, time: float, severity: str):
        self.path = path
        self.url = url
        self.status = status
        self.size = size
        self.time = time
        self.severity = severity
        self.status_type = self.get_status_type(status)
    
    def get_status_type(self, status: int) -> str:
        if status in (200, 201, 202, 203, 204, 205, 206):
            return 'success'
        elif status in (301, 302, 303, 307, 308):
            return 'redirect'
        elif status in (401, 403):
            return 'restricted'
        elif status in (400, 404, 405, 410):
            return 'error'
        else:
            return 'unknown'
    
    def to_dict(self):
        return {
            "path": self.path,
            "url": self.url,
            "status": self.status,
            "size": self.size,
            "time": round(self.time, 3),
            "severity": self.severity,
            "status_type": self.status_type
        }

# ==============================================
# ULTIMATE Scanner
# ==============================================
class UltimateScanner:
    def __init__(self, target: str, output_file: str = None, wordlist: str = None,
                 threads: int = 500, timeout: int = 4, aggressive: bool = False,
                 api_only: bool = False, sensitive: bool = False,
                 verbose: bool = False):
        
        self.target = target
        self.output_file = output_file
        self.wordlist = wordlist
        self.max_concurrent = threads
        self.timeout = timeout
        self.aggressive = aggressive
        self.api_only = api_only
        self.sensitive = sensitive
        self.verbose = verbose
        self.colors = get_colors()
        
        self.base_url = self.normalize_url(target)
        self.domain = urlparse(self.base_url).netloc
        self.findings: List[Finding] = []
        self.found_paths: Set[str] = set()
        self.semaphore = asyncio.Semaphore(threads)
        self.start_time = None
        self.detected_tech = []
        
        # Stats
        self.critical_findings = 0
        self.high_findings = 0
        self.medium_findings = 0
        self.low_findings = 0
        self.status_200 = 0
        self.status_301 = 0
        self.status_302 = 0
        self.status_403 = 0
        self.status_401 = 0
        
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        c = self.colors
        print(f"\n{c.YELLOW}[!] Interrupted. Saving results...{c.NC}")
        self.save_results()
        sys.exit(0)
    
    def normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')
    
    def classify_path(self, path: str) -> str:
        path_lower = path.lower()
        
        # CRITICAL - Red alert
        critical = {
            'admin', 'login', 'auth', 'oauth', 'database', 'db',
            'password', 'secret', 'token', 'apikey', 'api_key', 'key',
            'credential', '.env', '.git', '.svn', 'backup',
            'mysql', 'postgres', 'mongodb', 'redis', 'wp-config',
            'config.php', 'settings.php', 'database.php'
        }
        
        # HIGH - Important
        high = {
            'api', 'v1', 'v2', 'v3', 'graphql', 'rest', 'soap',
            'swagger', 'redoc', 'openapi', 'rpc', 'grpc',
            'server-status', 'actuator', 'health', 'metrics',
            'stats', 'status', 'debug', 'dev', 'test', 'stage',
            'wp-admin', 'wp-login', 'administrator', 'cpanel',
            'webmail', 'cgi-bin', 'cgi-sys', 'mailman',
            'phpmyadmin', 'mysql', 'phpinfo', 'info.php'
        }
        
        # MEDIUM - Interesting
        medium = {
            '.json', '.xml', '.yaml', '.yml', '.properties',
            '.conf', '.config', '.log', '.sql', '.dump',
            '.txt', '.csv', '.ini', '.env', '.htaccess',
            '.htpasswd', 'robots.txt', 'sitemap.xml'
        }
        
        for pattern in critical:
            if pattern in path_lower:
                return 'critical'
        
        for pattern in high:
            if pattern in path_lower:
                return 'high'
        
        for pattern in medium:
            if pattern in path_lower:
                return 'medium'
        
        return 'low'
    
    def generate_ultimate_paths(self) -> List[str]:
        """Generate the most comprehensive path list"""
        paths = set()
        
        # ==== CORE PATHS (Always test) ====
        core_paths = [
            '', 'index', 'index.php', 'index.html', 'index.htm',
            'admin', 'login', 'dashboard', 'home', 'about', 'contact',
            'api', 'v1', 'v2', 'v3', 'api/v1', 'api/v2', 'api/v3', 'graphql',
            'robots.txt', 'sitemap.xml', 'favicon.ico', '.htaccess', '.htpasswd',
            '.env', 'php.ini', 'phpinfo.php', 'info.php', 'test.php',
            'cpanel', 'webmail', 'mailman', 'cgi-bin', 'cgi-sys'
        ]
        
        # ==== ADMIN PATHS ====
        admin_paths = [
            'admin', 'administrator', 'admincp', 'adminpanel', 'admin/login',
            'admin/index', 'admin/home', 'admin/dashboard', 'admin/panel',
            'adm', 'admins', 'manage', 'manager', 'management', 'control',
            'controlpanel', 'cp', 'cpanel', 'webpanel', 'webadmin',
            'backend', 'backoffice', 'sysadmin', 'system', 'system/admin',
            'wp-admin', 'wp-login', 'wp-admin/admin-ajax.php',
            'phpmyadmin', 'pma', 'mysql', 'phpMyAdmin', 'myadmin',
            'webmin', 'cpanel', 'whm', 'plesk', 'directadmin'
        ]
        
        # ==== API PATHS ====
        api_paths = [
            'api', 'api/v1', 'api/v2', 'api/v3', 'api/v4', 'api/v5',
            'api/graphql', 'api/rest', 'api/soap', 'api/json', 'api/xml',
            'graphql', 'rest', 'rest-api', 'rest/v1', 'rest/v2',
            'services', 'service', 'webservice', 'soap', 'wsdl',
            'swagger', 'swagger-ui', 'swagger.json', 'swagger.yaml',
            'api-docs', 'docs/api', 'docs', 'redoc', 'openapi', 'oas',
            'rpc', 'grpc', 'jsonrpc', 'xmlrpc', 'api/health', 'api/status',
            'api/metrics', 'api/info', 'api/ping', 'api/ready', 'api/live',
            'api/auth', 'api/login', 'api/logout', 'api/register',
            'api/user', 'api/users', 'api/profile', 'api/account',
            'api/settings', 'api/config', 'api/upload', 'api/download'
        ]
        
        # ==== SENSITIVE PATHS ====
        sensitive_paths = [
            '.env', '.git', '.svn', '.hg', '.bzr', '.git/config',
            '.git/HEAD', '.git/index', '.git/logs', '.svn/entries',
            'backup', 'backups', 'bak', 'old', 'tmp', 'temp',
            'logs', 'log', 'error_log', 'debug.log', 'access.log',
            'database', 'db', 'mysql', 'postgres', 'mongodb',
            'redis', 'elasticsearch', 'kibana', 'grafana',
            'config', 'configuration', 'settings', 'setup', 'install',
            'password', 'passwords', 'secret', 'secrets', 'token', 'tokens',
            'key', 'keys', 'credential', 'credentials', 'auth', 'oauth',
            'wp-config.php', 'config.php', 'settings.php', 'database.php'
        ]
        
        # ==== WORDPRESS PATHS ====
        wp_paths = [
            'wp-admin', 'wp-login', 'wp-content', 'wp-includes',
            'wp-json', 'wp-json/wp/v2', 'wp-json/wp/v2/posts',
            'xmlrpc.php', 'wp-cron.php', 'wp-config.php',
            'wp-blog-header.php', 'wp-comments-post.php',
            'wp-links-opml.php', 'wp-load.php', 'wp-mail.php',
            'wp-settings.php', 'wp-signup.php', 'wp-trackback.php',
            'wp-activate.php', 'wp-app.php', 'readme.html',
            'license.txt', 'wp-config-sample.php'
        ]
        
        # ==== DISCOVERED PATHS (from previous scans) ====
        discovered_paths = [
            'alumni', 'server-status', 'off', 'vi', 'gallery',
            'architecture', 'get', 'discussion', 'post', 'interactive',
            'well-known', 'opportunistic', 'seminar', 'welcome',
            'offline', 'archive', 'journal', 'webinar', 'faculty',
            'student', 'course', 'courses', 'research', 'academic',
            'department', 'departments', 'staff', 'teacher', 'lecturer',
            'professor', 'program', 'programs', 'news', 'events',
            'blog', 'contact', 'about', 'services', 'products'
        ]
        
        # Combine all paths
        all_paths = (core_paths + admin_paths + api_paths + 
                    sensitive_paths + wp_paths + discovered_paths)
        
        # Add paths with extensions
        extensions = ['', '.php', '.html', '.htm', '.js', '.json', '.xml', '.txt', '.log', '.ini', '.conf', '.config', '.bak', '.old']
        
        for path in all_paths:
            for ext in extensions:
                paths.add(path + ext)
            paths.add(path + '/')
            paths.add('/' + path)
        
        # Filter based on scan type
        if self.api_only:
            paths = {p for p in paths if any(x in p.lower() for x in 
                    ['api', 'v1', 'v2', 'v3', 'graphql', 'rest', 'soap', 'wsdl', 'swagger', 'rpc'])}
        elif self.sensitive:
            paths = {p for p in paths if any(x in p.lower() for x in 
                    ['admin', 'login', 'auth', 'password', 'secret', 'token', 'key', 'backup', 'db', '.env', '.git', 'wp-config'])}
        
        # Aggressive - add more variations
        if self.aggressive:
            aggressive_variations = [
                '_', '-', '~', 'backup-', 'old-', 'temp-', 'new-', 'test-',
                '-backup', '-old', '-temp', '-new', '-test', '_backup', '_old'
            ]
            for path in list(paths)[:200]:
                for var in aggressive_variations:
                    paths.add(var + path)
                    paths.add(path + var)
        
        # If wordlist provided, add those too
        if self.wordlist and os.path.exists(self.wordlist):
            try:
                with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        path = line.strip()
                        if path and not path.startswith('#') and len(path) < 100:
                            paths.add(path)
            except:
                pass
        
        return list(paths)
    
    async def test_path(self, session: aiohttp.ClientSession, path: str) -> Optional[Finding]:
        if path in self.found_paths:
            return None
        
        url = f"{self.base_url}/{path}"
        
        try:
            async with self.semaphore:
                headers = {
                    'User-Agent': random.choice(USER_AGENTS),
                    'Accept': '*/*',
                    'Connection': 'close'
                }
                
                start = time.time()
                
                async with session.get(url, headers=headers, timeout=self.timeout,
                                      ssl=False, allow_redirects=True) as response:
                    
                    # Track status codes
                    if response.status == 200:
                        self.status_200 += 1
                    elif response.status in (301, 302):
                        self.status_301 += 1
                    elif response.status == 403:
                        self.status_403 += 1
                    elif response.status == 401:
                        self.status_401 += 1
                    
                    # Only track successful or restricted responses
                    if response.status in (200, 201, 202, 203, 301, 302, 307, 308, 401, 403):
                        content = await response.read()
                        size = len(content)
                        resp_time = time.time() - start
                        
                        # Classify severity
                        severity = self.classify_path(path)
                        
                        # Update stats
                        if severity == 'critical':
                            self.critical_findings += 1
                        elif severity == 'high':
                            self.high_findings += 1
                        elif severity == 'medium':
                            self.medium_findings += 1
                        else:
                            self.low_findings += 1
                        
                        finding = Finding(path, url, response.status, size, resp_time, severity)
                        self.found_paths.add(path)
                        return finding
                        
        except:
            pass
        
        return None
    
    async def scan(self):
        c = self.colors
        
        print(f"{c.CYAN}╔══════════════════════════════════════════════════════════════╗{c.NC}")
        print(f"{c.CYAN}║        MDIR v{VERSION} - ULTIMATE Discovery Tool           ║{c.NC}")
        print(f"{c.CYAN}║         🏆 Finds EVERYTHING - Including 403s                ║{c.NC}")
        print(f"{c.CYAN}╚══════════════════════════════════════════════════════════════╝{c.NC}")
        print()
        print(f"{c.BLUE}[*] Target: {self.target}{c.NC}")
        print(f"{c.BLUE}[*] Base URL: {self.base_url}{c.NC}")
        print()
        
        # Generate paths
        print(f"{c.BLUE}[*] Generating ultimate paths...{c.NC}")
        paths = self.generate_ultimate_paths()
        print(f"{c.GREEN}[✓] Generated {len(paths)} paths{c.NC}")
        print(f"{c.BLUE}[*] Using {self.max_concurrent} concurrent connections{c.NC}")
        print(f"{c.BLUE}[*] Timeout: {self.timeout}s{c.NC}")
        print(f"{c.YELLOW}[!] Tracking 200, 301, 302, 403, 401 responses{c.NC}")
        print()
        
        self.start_time = time.time()
        
        connector = aiohttp.TCPConnector(
            limit=CONNECTION_LIMIT,
            limit_per_host=CONNECTION_LIMIT,
            ttl_dns_cache=300,
            ssl=False,
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(total=None, sock_read=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            batch_size = min(BATCH_SIZE, len(paths))
            total_batches = (len(paths) + batch_size - 1) // batch_size
            
            for batch_num in range(total_batches):
                start_idx = batch_num * batch_size
                end_idx = min(start_idx + batch_size, len(paths))
                batch_paths = paths[start_idx:end_idx]
                
                tasks = [self.test_path(session, path) for path in batch_paths]
                
                for task in asyncio.as_completed(tasks):
                    result = await task
                    if result:
                        self.findings.append(result)
                        self.print_finding_ultimate(result)
                
                tested = min(end_idx, len(paths))
                elapsed = time.time() - self.start_time
                speed = tested / elapsed if elapsed > 0 else 0
                
                print(f"\r{c.DIM}Progress: {tested}/{len(paths)} | Found: {len(self.findings)} | Speed: {speed:.0f} req/s | 200: {self.status_200} 403: {self.status_403}{c.NC}", end='')
        
        print()
        self.save_results()
        
        elapsed = time.time() - self.start_time
        print(f"\n{c.GREEN}[✓] Scan completed in {elapsed:.2f}s{c.NC}")
        print(f"{c.GREEN}[✓] Tested: {len(paths)} paths{c.NC}")
        print(f"{c.GREEN}[✓] Found: {len(self.findings)} findings{c.NC}")
        print()
        print(f"{c.CYAN}[*] Response Status Summary:{c.NC}")
        print(f"  {c.GREEN}✓ 200 OK: {self.status_200}{c.NC}")
        print(f"  {c.YELLOW}➜ 301/302 Redirect: {self.status_301}{c.NC}")
        print(f"  {c.RED}🔒 403 Forbidden: {self.status_403}{c.NC}")
        print(f"  {c.MAGENTA}🔐 401 Unauthorized: {self.status_401}{c.NC}")
        print()
        
        if len(self.findings) > 0:
            print(f"{c.BOLD}{c.CYAN}[*] Findings by severity:{c.NC}")
            print(f"  {c.BOLD}{c.RED}🔴 CRITICAL: {self.critical_findings}{c.NC}")
            print(f"  {c.BOLD}{c.MAGENTA}🟣 HIGH: {self.high_findings}{c.NC}")
            print(f"  {c.BOLD}{c.YELLOW}🟡 MEDIUM: {self.medium_findings}{c.NC}")
            print(f"  {c.BOLD}{c.CYAN}🔵 LOW: {self.low_findings}{c.NC}")
        else:
            print(f"{c.YELLOW}[!] No findings. Try using -a (aggressive) or with a wordlist{c.NC}")
            print(f"{c.YELLOW}[!] Example: python3 mdir.py -u {self.target} -a -w /usr/share/wordlists/dirb/common.txt{c.NC}")
    
    def print_finding_ultimate(self, finding: Finding):
        c = self.colors
        
        # Status color
        if finding.status == 200:
            status_color = c.GREEN
            status_icon = "✅"
        elif finding.status in (301, 302):
            status_color = c.YELLOW
            status_icon = "➜"
        elif finding.status == 403:
            status_color = c.RED
            status_icon = "🔒"
        elif finding.status == 401:
            status_color = c.MAGENTA
            status_icon = "🔐"
        else:
            status_color = c.WHITE
            status_icon = "📄"
        
        # Severity colors
        if finding.severity == 'critical':
            print(f"\r{c.BG_RED}{c.WHITE}{c.BOLD} 🔴 CRITICAL {c.NC} {c.RED}{finding.url} {status_color}({status_icon} {finding.status}){c.NC}")
        elif finding.severity == 'high':
            print(f"\r{c.BG_MAGENTA}{c.WHITE}{c.BOLD} 🟣 HIGH    {c.NC} {c.MAGENTA}{finding.url} {status_color}({status_icon} {finding.status}){c.NC}")
        elif finding.severity == 'medium':
            print(f"\r{c.BG_YELLOW}{c.BLACK}{c.BOLD} 🟡 MEDIUM  {c.NC} {c.YELLOW}{finding.url} {status_color}({status_icon} {finding.status}){c.NC}")
        else:
            print(f"\r{c.BG_CYAN}{c.BLACK}{c.BOLD} 🔵 LOW     {c.NC} {c.CYAN}{finding.url} {status_color}({status_icon} {finding.status}){c.NC}")
    
    def save_results(self):
        if not self.output_file:
            return
        
        try:
            ext = os.path.splitext(self.output_file)[1].lower()
            
            if ext == '.html':
                self.save_html()
            elif ext == '.json':
                self.save_json()
            else:
                self.save_txt()
            
            c = self.colors
            print(f"{c.GREEN}[✓] Results saved to: {self.output_file}{c.NC}")
            
        except Exception as e:
            c = self.colors
            print(f"{c.RED}[✗] Error saving: {e}{c.NC}")
    
    def save_txt(self):
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(f"MDIR v{VERSION} - ULTIMATE Discovery Report\n")
            f.write(f"Target: {self.base_url}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Response Status Summary:\n")
            f.write(f"  200 OK: {self.status_200}\n")
            f.write(f"  301/302 Redirect: {self.status_301}\n")
            f.write(f"  403 Forbidden: {self.status_403}\n")
            f.write(f"  401 Unauthorized: {self.status_401}\n")
            f.write("\n" + "=" * 70 + "\n\n")
            
            for severity in ['critical', 'high', 'medium', 'low']:
                findings = [f for f in self.findings if f.severity == severity]
                if findings:
                    emoji = {'critical': '🔴', 'high': '🟣', 'medium': '🟡', 'low': '🔵'}[severity]
                    f.write(f"{emoji} {severity.upper()} - {len(findings)} findings\n")
                    f.write("-" * 50 + "\n")
                    for finding in findings:
                        status_icon = "✅" if finding.status == 200 else "🔒" if finding.status == 403 else "➜" if finding.status in (301,302) else "📄"
                        f.write(f"[{status_icon} {finding.status}] {finding.url}\n")
                    f.write("\n")
            
            f.write(f"\nTotal Findings: {len(self.findings)}\n")
    
    def save_json(self):
        data = {
            "scanner": f"MDIR v{VERSION}",
            "target": self.base_url,
            "timestamp": datetime.now().isoformat(),
            "status_summary": {
                "200": self.status_200,
                "301_302": self.status_301,
                "403": self.status_403,
                "401": self.status_401
            },
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings]
        }
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    
    def save_html(self):
        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>MDIR - ULTIMATE Discovery Report</title>
    <style>
        body {{ background: #0a0e17; color: #e0e0e0; font-family: 'Segoe UI', Arial; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: #141b2d; border-radius: 12px; padding: 30px; }}
        h1 {{ color: #00d4ff; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #1a2332; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-card .num {{ font-size: 2.5em; font-weight: bold; }}
        .critical .num {{ color: #ff0055; }}
        .high .num {{ color: #ff00ff; }}
        .medium .num {{ color: #ffd700; }}
        .low .num {{ color: #00ffff; }}
        .stat-card .label {{ color: #8892b0; margin-top: 5px; }}
        
        .status-summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 20px 0; background: #1a2332; padding: 15px; border-radius: 8px; }}
        .status-item {{ text-align: center; }}
        .status-item .num {{ font-size: 1.5em; font-weight: bold; }}
        .status-200 .num {{ color: #34d399; }}
        .status-301 .num {{ color: #fbbf24; }}
        .status-403 .num {{ color: #f87171; }}
        .status-401 .num {{ color: #c084fc; }}
        
        .finding {{ background: #1a2332; padding: 12px 15px; margin: 5px 0; border-radius: 4px; }}
        .finding.critical {{ border-left: 4px solid #ff0055; background: #2a0a0a; }}
        .finding.high {{ border-left: 4px solid #ff00ff; background: #1a0a2a; }}
        .finding.medium {{ border-left: 4px solid #ffd700; background: #2a2a0a; }}
        .finding.low {{ border-left: 4px solid #00ffff; background: #0a1a2a; }}
        .url {{ color: #64ffda; word-break: break-all; }}
        .status {{ font-size: 0.8em; margin-top: 5px; }}
        .status-200 {{ color: #34d399; }}
        .status-301 {{ color: #fbbf24; }}
        .status-403 {{ color: #f87171; }}
        .status-401 {{ color: #c084fc; }}
        .badge {{ display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: 0.7em; font-weight: bold; margin-left: 8px; }}
        .badge-critical {{ background: #ff0055; color: white; }}
        .badge-high {{ background: #ff00ff; color: white; }}
        .badge-medium {{ background: #ffd700; color: black; }}
        .badge-low {{ background: #00ffff; color: black; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #2d3748; text-align: center; color: #8892b0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🏆 MDIR ULTIMATE Discovery Report</h1>
        <p>Target: {self.base_url}</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="status-summary">
            <div class="status-item status-200">
                <div class="num">{self.status_200}</div>
                <div>✅ 200 OK</div>
            </div>
            <div class="status-item status-301">
                <div class="num">{self.status_301}</div>
                <div>➜ 301/302</div>
            </div>
            <div class="status-item status-403">
                <div class="num">{self.status_403}</div>
                <div>🔒 403</div>
            </div>
            <div class="status-item status-401">
                <div class="num">{self.status_401}</div>
                <div>🔐 401</div>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card critical">
                <div class="num">{self.critical_findings}</div>
                <div class="label">🔴 Critical</div>
            </div>
            <div class="stat-card high">
                <div class="num">{self.high_findings}</div>
                <div class="label">🟣 High</div>
            </div>
            <div class="stat-card medium">
                <div class="num">{self.medium_findings}</div>
                <div class="label">🟡 Medium</div>
            </div>
            <div class="stat-card low">
                <div class="num">{self.low_findings}</div>
                <div class="label">🔵 Low</div>
            </div>
        </div>
        
        <h2>📋 All Findings</h2>
'''
        
        for severity in ['critical', 'high', 'medium', 'low']:
            findings = [f for f in self.findings if f.severity == severity]
            if findings:
                emoji = {'critical': '🔴', 'high': '🟣', 'medium': '🟡', 'low': '🔵'}[severity]
                html += f'<h3>{emoji} {severity.upper()}</h3>'
                for finding in findings:
                    status_icon = "✅" if finding.status == 200 else "🔒" if finding.status == 403 else "➜" if finding.status in (301,302) else "📄"
                    html += f'''
                    <div class="finding {severity}">
                        <div class="url">{finding.url}</div>
                        <div class="status status-{finding.status}">
                            {status_icon} HTTP {finding.status} | Size: {finding.size} bytes | Time: {finding.time:.3f}s
                            <span class="badge badge-{severity}">{severity.upper()}</span>
                        </div>
                    </div>
                    '''
        
        html += f'''
        <div class="footer">
            Generated by MDIR v{VERSION} | Total Findings: {len(self.findings)}
        </div>
    </div>
</body>
</html>
        '''
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def run(self):
        asyncio.run(self.scan())

# ==============================================
# Main
# ==============================================
def main():
    global DISABLE_COLORS
    
    parser = argparse.ArgumentParser(description='MDIR - ULTIMATE Discovery Tool', add_help=False)
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-l', '--list', help='File with targets')
    parser.add_argument('-o', '--output', help='Output file (.txt, .html, .json)')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=500, help='Threads (default: 500)')
    parser.add_argument('-T', '--timeout', type=int, default=4, help='Timeout (default: 4)')
    parser.add_argument('-a', '--aggressive', action='store_true', help='Aggressive mode')
    parser.add_argument('-A', '--api-only', action='store_true', help='API only')
    parser.add_argument('-S', '--sensitive', action='store_true', help='Sensitive only')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose')
    parser.add_argument('--no-color', action='store_true', help='No colors')
    parser.add_argument('-h', '--help', action='store_true', help='Help')
    
    args = parser.parse_args()
    
    if args.no_color:
        DISABLE_COLORS = True
    
    colors = get_colors()
    
    if args.help or not (args.url or args.list):
        print(f"""
{colors.CYAN}MDIR v{VERSION} - ULTIMATE Discovery Tool{colors.NC}

{colors.BOLD}Usage:{colors.NC}
  python3 mdir.py -u example.com -o report.html
  python3 mdir.py -u example.com -w wordlist.txt -o results.txt

{colors.BOLD}Options:{colors.NC}
  -u, --url <url>              Target URL
  -l, --list <file>            File with targets
  -o, --output <file>          Output file (.txt, .html, .json)
  -w, --wordlist <file>        Custom wordlist file
  -t, --threads <num>          Threads (default: 500)
  -T, --timeout <sec>          Timeout (default: 4)
  -a, --aggressive             Aggressive mode
  -A, --api-only               API only
  -S, --sensitive              Sensitive only
  -v, --verbose                Verbose
  -h, --help                   This help

{colors.GREEN}Features:{colors.NC}
  • Finds 200, 301, 302, 403, 401 responses
  • 403 is VALUABLE - means path exists!
  • Auto-detects admin panels, APIs, configs
  • Comprehensive path generation

{colors.YELLOW}Examples:{colors.NC}
  # Quick scan
  python3 mdir.py -u https://example.com -o report.html

  # Aggressive with wordlist (finds more)
  python3 mdir.py -u https://example.com -a -w /usr/share/wordlists/dirb/common.txt -o full.html

  # API discovery
  python3 mdir.py -u https://example.com -A -o api.json
""")
        return
    
    try:
        import aiohttp
    except ImportError:
        print(f"{colors.RED}[✗] Install aiohttp: pip install aiohttp{colors.NC}")
        return
    
    if args.url:
        scanner = UltimateScanner(
            target=args.url,
            output_file=args.output,
            wordlist=args.wordlist,
            threads=args.threads,
            timeout=args.timeout,
            aggressive=args.aggressive,
            api_only=args.api_only,
            sensitive=args.sensitive,
            verbose=args.verbose
        )
        scanner.run()
    
    if args.list:
        try:
            with open(args.list, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            for target in targets:
                print(f"\n{colors.CYAN}[*] Target: {target}{colors.NC}")
                output_file = args.output
                if output_file and os.path.isdir(output_file):
                    domain = urlparse(target).netloc or target
                    output_file = os.path.join(output_file, f"{domain}_results.html")
                
                scanner = UltimateScanner(
                    target=target,
                    output_file=output_file,
                    wordlist=args.wordlist,
                    threads=args.threads,
                    timeout=args.timeout,
                    aggressive=args.aggressive,
                    api_only=args.api_only,
                    sensitive=args.sensitive,
                    verbose=args.verbose
                )
                scanner.run()
                
        except FileNotFoundError:
            print(f"{colors.RED}[✗] File not found: {args.list}{colors.NC}")

if __name__ == "__main__":
    main()
