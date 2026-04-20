"""
All tool parsers.  Each class implements:
  can_parse(path) -> bool   — called by detect_parser() for auto-detection
  parse()         -> list[Finding]
"""

import json
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional

from findings import Finding


# ── Registry ──────────────────────────────────────────────────────────────────

def detect_parser(path: Path) -> Optional[type]:
    for cls in (NmapParser, NucleiParser, TestsslParser, NiktoParser, FfufParser):
        if cls.can_parse(path):
            return cls
    return None


# ── Base ──────────────────────────────────────────────────────────────────────

class BaseParser(ABC):
    def __init__(self, path: Path):
        self.path = path

    @abstractmethod
    def parse(self) -> List[Finding]:
        pass

    @classmethod
    def can_parse(cls, path: Path) -> bool:
        return False


# ── Nmap ──────────────────────────────────────────────────────────────────────

_NMAP_SCRIPT_SEVERITY = {
    'ssl-heartbleed':         ('critical', 'CVE-2014-0160'),
    'smb-vuln-ms17-010':      ('critical', 'CVE-2017-0144'),
    'smb-vuln-ms08-067':      ('critical', 'CVE-2008-4250'),
    'smb-vuln-cve-2020-0796': ('critical', 'CVE-2020-0796'),
    'ssl-drown':              ('critical', 'CVE-2016-0800'),
    'http-shellshock':        ('critical', 'CVE-2014-6271'),
    'ssl-poodle':             ('high',     'CVE-2014-3566'),
    'ssl-ccs-injection':      ('high',     'CVE-2014-0224'),
    'smb-vuln-ms10-054':      ('high',     'CVE-2010-2550'),
    'smb-vuln-ms10-061':      ('high',     'CVE-2010-2729'),
    'http-vuln-cve':          ('high',     None),
    'smb-vuln-cve':           ('high',     None),
    'ftp-anon':               ('medium',   None),
    'http-methods':           ('low',      None),
    'ssl-cert':               ('info',     None),
    'ssh-hostkey':            ('info',     None),
}


def _nmap_script_severity(script_id: str):
    for key, val in _NMAP_SCRIPT_SEVERITY.items():
        if script_id.startswith(key):
            return val
    return ('info', None)


def _nmap_host_label(host_el: ET.Element) -> str:
    for hn in host_el.findall('.//hostname'):
        if hn.get('type') == 'user':
            return hn.get('name', '')
    for hn in host_el.findall('.//hostname'):
        return hn.get('name', '')
    addr = host_el.find('address[@addrtype="ipv4"]') or host_el.find('address')
    return addr.get('addr', 'unknown') if addr is not None else 'unknown'


class NmapParser(BaseParser):
    @classmethod
    def can_parse(cls, path: Path) -> bool:
        if path.suffix.lower() != '.xml':
            return False
        try:
            return ET.parse(path).getroot().tag == 'nmaprun'
        except Exception:
            return False

    def parse(self) -> List[Finding]:
        findings: List[Finding] = []
        root = ET.parse(self.path).getroot()

        for host in root.findall('host'):
            status = host.find('status')
            if status is not None and status.get('state') != 'up':
                continue

            label  = _nmap_host_label(host)
            addr   = host.find('address[@addrtype="ipv4"]') or host.find('address')
            ip     = addr.get('addr', label) if addr is not None else label
            ports  = host.find('ports')
            if ports is None:
                continue

            open_ports: List[str] = []

            for port_el in ports.findall('port'):
                state_el = port_el.find('state')
                if state_el is None or state_el.get('state') != 'open':
                    continue

                portid = port_el.get('portid', '?')
                proto  = port_el.get('protocol', 'tcp')
                asset  = f"{label}:{portid}/{proto}"
                svc    = port_el.find('service')
                svc_str = ''
                if svc is not None:
                    name    = svc.get('name', '')
                    product = svc.get('product', '')
                    version = svc.get('version', '')
                    svc_str = f"{name} ({product} {version})".strip('( )') if product else name
                open_ports.append(f"{portid}/{proto}  {svc_str}".strip())

                for script in port_el.findall('script'):
                    sid      = script.get('id', '')
                    output   = script.get('output', '')
                    severity, cve = _nmap_script_severity(sid)
                    refs = [f'https://nvd.nist.gov/vuln/detail/{cve}'] if cve else []
                    findings.append(Finding(
                        title=sid.replace('-', ' ').title(),
                        severity=severity,
                        affected_asset=asset,
                        tool_source='nmap',
                        evidence=f'Script: {sid}\n{output}',
                        references=refs,
                        tags=['nmap-script', sid],
                    ))

            if open_ports:
                findings.append(Finding(
                    title='Open Ports Enumeration',
                    severity='info',
                    affected_asset=ip,
                    tool_source='nmap',
                    evidence='Open ports discovered:\n' + '\n'.join(open_ports),
                    remediation=(
                        'Review each exposed port. Restrict access to administrative '
                        'services using host-based firewall rules or network ACLs. '
                        'Disable or remove services that are not required.'
                    ),
                    tags=['open-ports'],
                ))

        return findings


# ── Nuclei ────────────────────────────────────────────────────────────────────

_NUCLEI_SEV = {
    'critical': 'critical', 'high': 'high', 'medium': 'medium',
    'low': 'low', 'info': 'info', 'unknown': 'info',
}


class NucleiParser(BaseParser):
    @classmethod
    def can_parse(cls, path: Path) -> bool:
        if path.suffix.lower() not in ('.json', '.jsonl'):
            return False
        try:
            with open(path, encoding='utf-8') as fh:
                obj = json.loads(fh.readline().strip())
            return 'template-id' in obj or 'templateID' in obj
        except Exception:
            return False

    def parse(self) -> List[Finding]:
        findings: List[Finding] = []
        with open(self.path, encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                info  = obj.get('info', {})
                clf   = info.get('classification', {})
                severity  = _NUCLEI_SEV.get(info.get('severity', 'info').lower(), 'info')
                matched   = obj.get('matched-at') or obj.get('matched_at', '')

                evidence_parts = []
                if matched:
                    evidence_parts.append(f'Matched at: {matched}')
                ev = obj.get('evidence', {})
                if isinstance(ev, dict):
                    if ev.get('request'):
                        evidence_parts.append('--- Request ---\n' + ev['request'])
                    if ev.get('response'):
                        evidence_parts.append('--- Response ---\n' + ev['response'][:1000])
                elif isinstance(ev, str) and ev:
                    evidence_parts.append(ev)
                if obj.get('curl-command'):
                    evidence_parts.append(f"curl: {obj['curl-command']}")

                refs: List[str] = list(info.get('reference', []) or [])
                cve  = clf.get('cve-id') or clf.get('cve_id', '')
                nvd  = f'https://nvd.nist.gov/vuln/detail/{cve}'
                if cve and nvd not in refs:
                    refs.insert(0, nvd)

                findings.append(Finding(
                    title=info.get('name', obj.get('template-id', 'Unknown')),
                    severity=severity,
                    affected_asset=obj.get('host', matched or 'unknown'),
                    tool_source='nuclei',
                    evidence='\n\n'.join(evidence_parts),
                    cvss_score=clf.get('cvss-score') or clf.get('cvss_score'),
                    cvss_vector=clf.get('cvss-metrics') or clf.get('cvss_metrics'),
                    cwe=clf.get('cwe-id') or clf.get('cwe_id') or None,
                    remediation=info.get('remediation', ''),
                    references=refs,
                    tags=list(info.get('tags', [])),
                    raw=obj,
                ))
        return findings


# ── testssl ───────────────────────────────────────────────────────────────────

_TESTSSL_SEV = {
    'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium',
    'LOW': 'low', 'WARN': 'low', 'NOT OK': 'medium', 'INFO': 'info',
    'OK': None, 'DEBUG': None,
}

_TESTSSL_ID_OVERRIDES = {
    'heartbleed':    ('critical', 'CVE-2014-0160', 'CWE-119'),
    'CCS':           ('high',     'CVE-2014-0224', 'CWE-310'),
    'ticketbleed':   ('high',     'CVE-2016-9244', 'CWE-200'),
    'ROBOT':         ('high',     'CVE-2017-13099','CWE-310'),
    'POODLE_SSL':    ('high',     'CVE-2014-3566', 'CWE-326'),
    'DROWN':         ('critical', 'CVE-2016-0800', 'CWE-310'),
    'LUCKY13':       ('medium',   'CVE-2013-0169', 'CWE-310'),
    'BEAST_CBC_TLS1':('medium',   'CVE-2011-3389', 'CWE-326'),
    'SWEET32':       ('medium',   'CVE-2016-2183', 'CWE-326'),
    'FREAK':         ('high',     'CVE-2015-0204', 'CWE-310'),
    'LOGJAM-common': ('high',     'CVE-2015-4000', 'CWE-310'),
    'SSLv2':         ('critical', None,            'CWE-326'),
    'SSLv3':         ('high',     None,            'CWE-326'),
    'TLS1':          ('medium',   None,            'CWE-326'),
    'TLS1_1':        ('low',      None,            'CWE-326'),
}

_TESTSSL_TITLES = {
    'heartbleed':    'OpenSSL Heartbleed (CVE-2014-0160)',
    'CCS':           'OpenSSL CCS Injection (CVE-2014-0224)',
    'SSLv2':         'SSLv2 Enabled',
    'SSLv3':         'SSLv3 Enabled (POODLE)',
    'TLS1':          'TLS 1.0 Enabled',
    'TLS1_1':        'TLS 1.1 Enabled',
    'POODLE_SSL':    'POODLE Attack (CVE-2014-3566)',
    'DROWN':         'DROWN Attack (CVE-2016-0800)',
    'SWEET32':       'SWEET32 Birthday Attack (CVE-2016-2183)',
    'FREAK':         'FREAK Attack (CVE-2015-0204)',
    'LOGJAM-common': 'LOGJAM (CVE-2015-4000)',
    'ROBOT':         'ROBOT Attack (CVE-2017-13099)',
}


class TestsslParser(BaseParser):
    @classmethod
    def can_parse(cls, path: Path) -> bool:
        if path.suffix.lower() != '.json':
            return False
        try:
            return 'scanResult' in json.load(open(path, encoding='utf-8'))
        except Exception:
            return False

    def parse(self) -> List[Finding]:
        findings: List[Finding] = []
        data = json.load(open(self.path, encoding='utf-8'))

        for scan in data.get('scanResult', []):
            ip       = scan.get('ip', 'unknown')
            port     = scan.get('port', '443')
            hostname = scan.get('hostname') or ip
            asset    = f"{hostname}:{port}"

            for item in scan.get('findings', []):
                fid     = item.get('id', '')
                raw_sev = item.get('severity', 'INFO').upper()
                text    = item.get('finding', '')

                override = _TESTSSL_ID_OVERRIDES.get(fid)
                if override:
                    sev, cve, cwe = override
                else:
                    sev = _TESTSSL_SEV.get(raw_sev)
                    cve = item.get('cve')
                    cwe = item.get('cwe')

                if sev is None:
                    continue

                refs = [f'https://nvd.nist.gov/vuln/detail/{cve}'] if cve else []
                title = _TESTSSL_TITLES.get(fid, fid.replace('_', ' ').replace('-', ' ').title())

                findings.append(Finding(
                    title=title,
                    severity=sev,
                    affected_asset=asset,
                    tool_source='testssl',
                    evidence=f'Finding ID: {fid}\n{text}',
                    cwe=cwe,
                    references=refs,
                    tags=['tls', 'ssl', fid],
                    raw=item,
                ))
        return findings


# ── Nikto ─────────────────────────────────────────────────────────────────────

_NIKTO_HIGH = [
    'sql injection', 'xss', 'cross-site scripting', 'remote code execution',
    'command injection', 'directory traversal', 'path traversal',
    'authentication bypass', 'default password', 'default credential',
]
_NIKTO_MEDIUM = [
    'phpinfo', 'information disclosure', 'version', 'stack trace', 'error message',
    'htpasswd', 'web.config', '.git', '.svn', 'backup', 'server-status', 'server-info',
]


def _nikto_severity(description: str) -> str:
    desc = description.lower()
    if any(kw in desc for kw in _NIKTO_HIGH):
        return 'high'
    if any(kw in desc for kw in _NIKTO_MEDIUM):
        return 'medium'
    return 'low'


class NiktoParser(BaseParser):
    @classmethod
    def can_parse(cls, path: Path) -> bool:
        if path.suffix.lower() != '.xml':
            return False
        try:
            return ET.parse(path).getroot().tag == 'niktoscan'
        except Exception:
            return False

    def parse(self) -> List[Finding]:
        findings: List[Finding] = []
        root = ET.parse(self.path).getroot()

        for scan in root.findall('.//scandetails'):
            ip       = scan.get('targetip', 'unknown')
            hostname = scan.get('targethostname') or ip
            port     = scan.get('targetport', '80')
            asset    = f"{hostname}:{port}"

            for item in scan.findall('item'):
                desc_el = item.find('description')
                uri_el  = item.find('uri')
                desc    = desc_el.text or '' if desc_el is not None else ''
                uri     = uri_el.text or ''  if uri_el  is not None else ''
                if not desc:
                    continue

                findings.append(Finding(
                    title=desc[:120],
                    severity=_nikto_severity(desc),
                    affected_asset=f"{asset}{uri}" if uri else asset,
                    tool_source='nikto',
                    evidence=f'URI: {uri}\n{desc}',
                    tags=['nikto', 'web'],
                ))
        return findings


# ── ffuf ──────────────────────────────────────────────────────────────────────

_FFUF_SENSITIVE = [
    'admin', 'administrator', 'manage', 'dashboard', 'panel',
    'config', 'setup', 'install', 'console', 'api', 'swagger',
    'graphql', 'debug', 'test', 'backup', 'dump', '.git', '.env',
    '.htpasswd', 'wp-admin', 'phpmyadmin', 'phpinfo',
]


def _ffuf_severity(url: str, status: int) -> str:
    url_lower = url.lower()
    if any(p in url_lower for p in _FFUF_SENSITIVE):
        return 'medium' if status == 200 else 'low'
    return 'low' if status == 200 else 'info'


class FfufParser(BaseParser):
    @classmethod
    def can_parse(cls, path: Path) -> bool:
        if path.suffix.lower() != '.json':
            return False
        try:
            obj = json.load(open(path, encoding='utf-8'))
            return 'results' in obj and 'commandline' in obj
        except Exception:
            return False

    def parse(self) -> List[Finding]:
        findings: List[Finding] = []
        data = json.load(open(self.path, encoding='utf-8'))

        for result in data.get('results', []):
            url    = result.get('url', '')
            status = result.get('status', 0)
            if not url:
                continue
            findings.append(Finding(
                title=f'Discovered Endpoint: {url}',
                severity=_ffuf_severity(url, status),
                affected_asset=url,
                tool_source='ffuf',
                evidence=(
                    f"URL:    {url}\n"
                    f"Status: {status}\n"
                    f"Length: {result.get('length', 0)}\n"
                    f"Words:  {result.get('words', 0)}"
                ),
                remediation=(
                    'Review whether this endpoint should be publicly accessible. '
                    'Apply authentication, restrict by IP, or remove if unused.'
                ),
                tags=['ffuf', 'web-content-discovery', f'http-{status}'],
            ))
        return findings
