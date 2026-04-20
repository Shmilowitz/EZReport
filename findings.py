"""
Defines the Finding dataclass and the enrichment logic applied to it.
Everything that answers "what is a finding and how is it processed" lives here.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Optional, List

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


def _normalise_severity(raw: str) -> str:
    s = raw.strip().lower()
    return s if s in SEVERITY_ORDER else 'info'


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    title: str
    severity: str
    affected_asset: str
    tool_source: str
    evidence: str = ''
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe: Optional[str] = None
    remediation: str = ''
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    raw: Optional[dict] = field(default=None, repr=False)

    def __post_init__(self):
        self.severity = _normalise_severity(self.severity)

    @property
    def id(self) -> str:
        key = f"{self.title.lower()}|{self.affected_asset.lower()}"
        return hashlib.sha256(key.encode()).hexdigest()[:12]

    @property
    def severity_order(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'title': self.title,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'cwe': self.cwe,
            'affected_asset': self.affected_asset,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'references': self.references,
            'tags': self.tags,
            'tool_source': self.tool_source,
        }


# ── Enrichment ────────────────────────────────────────────────────────────────

_CVSS_DEFAULT = {
    'critical': 9.5, 'high': 7.5, 'medium': 5.0, 'low': 2.0, 'info': 0.0,
}

CWE_NAMES = {
    'CWE-20':  'Improper Input Validation',
    'CWE-22':  'Path Traversal',
    'CWE-79':  'Cross-Site Scripting (XSS)',
    'CWE-89':  'SQL Injection',
    'CWE-94':  'Code Injection',
    'CWE-119': 'Buffer Overflow / Memory Corruption',
    'CWE-200': 'Information Exposure',
    'CWE-269': 'Improper Privilege Management',
    'CWE-284': 'Improper Access Control',
    'CWE-287': 'Improper Authentication',
    'CWE-306': 'Missing Authentication for Critical Function',
    'CWE-310': 'Cryptographic Issues',
    'CWE-311': 'Missing Encryption of Sensitive Data',
    'CWE-326': 'Inadequate Encryption Strength',
    'CWE-352': 'Cross-Site Request Forgery (CSRF)',
    'CWE-400': 'Uncontrolled Resource Consumption',
    'CWE-434': 'Unrestricted File Upload',
    'CWE-502': 'Deserialization of Untrusted Data',
    'CWE-611': 'XML External Entity (XXE)',
    'CWE-639': 'Insecure Direct Object Reference (IDOR)',
    'CWE-798': 'Use of Hard-coded Credentials',
    'CWE-917': 'Expression Language Injection',
}

_REMEDIATION_BY_CWE = {
    'CWE-89': (
        'Use parameterized queries or prepared statements for all database interactions. '
        'Never concatenate user-supplied input into SQL strings. '
        'Apply an allowlist for any values that must be dynamic (e.g. column names). '
        'Enable a Web Application Firewall (WAF) rule as a defence-in-depth measure, '
        'but do not rely on it as the primary control.'
    ),
    'CWE-79': (
        'Encode all user-controlled output using context-appropriate encoding '
        '(HTML entity encoding for HTML context, JavaScript encoding for JS context). '
        'Implement a strict Content-Security-Policy (CSP) header that disallows '
        "inline scripts and restricts script sources to your own domain. "
        'Set the HttpOnly and Secure flags on session cookies.'
    ),
    'CWE-22': (
        'Canonicalize file paths server-side and verify they resolve to within '
        'the expected directory before opening. Use an allowlist of permitted '
        'filenames or file extensions rather than attempting to block traversal '
        'sequences. Avoid passing user-supplied path components to filesystem '
        'operations wherever possible.'
    ),
    'CWE-119': (
        'Apply the available vendor patch or upgrade to a non-vulnerable version. '
        'Enable OS-level mitigations: ASLR, DEP/NX, and stack canaries. '
        'Where the component is not directly patchable, consider placing it behind '
        'a reverse proxy with request size limits enforced.'
    ),
    'CWE-287': (
        'Enforce multi-factor authentication (MFA) for all user accounts, '
        'particularly administrative interfaces. Implement account lockout after '
        'a configurable number of failed attempts. Log and alert on repeated '
        'authentication failures. Ensure session tokens are securely generated, '
        'not predictable, and are invalidated on logout.'
    ),
    'CWE-306': (
        'Require authentication before granting access to any sensitive function '
        'or data. Apply authentication at the server side — do not rely on '
        "client-side controls or URL obscurity. Implement role-based access control "
        "(RBAC) and validate the caller's role on every request."
    ),
    'CWE-310': (
        'Disable deprecated cryptographic protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) '
        'and weak cipher suites (RC4, DES, 3DES, NULL, EXPORT). '
        'Configure a modern TLS 1.2/1.3-only profile. '
        "Refer to Mozilla's recommended TLS configuration: https://ssl-config.mozilla.org/"
    ),
    'CWE-326': (
        'Upgrade to TLS 1.2 at minimum; prefer TLS 1.3. Remove support for weak '
        'key exchange mechanisms (DH < 2048 bits, export-grade). '
        'Validate the new cipher-suite profile using testssl.sh after reconfiguration.'
    ),
    'CWE-311': (
        'Enforce TLS for all connections that carry sensitive data. '
        'Set the Strict-Transport-Security (HSTS) header with a long max-age '
        'and includeSubDomains. Redirect all HTTP traffic to HTTPS at the '
        'load balancer or reverse proxy level.'
    ),
    'CWE-200': (
        'Remove or restrict access to any endpoint that exposes internal version '
        'strings, stack traces, configuration values, or directory listings. '
        'Configure error handlers to return generic messages to clients. '
        'Audit HTTP response headers and remove X-Powered-By, Server, and similar '
        'disclosure headers.'
    ),
    'CWE-798': (
        'Remove all hard-coded credentials from source code and configuration files. '
        'Store secrets in a secrets manager (HashiCorp Vault, AWS Secrets Manager, '
        'Azure Key Vault). Rotate any credentials that may have been exposed. '
        'Add a pre-commit hook or CI gate to detect secrets before they reach the repository.'
    ),
    'CWE-352': (
        'Include an unpredictable, per-session CSRF token in all state-changing '
        'requests and validate it server-side. Verify the Origin and Referer headers '
        'as a secondary control. Use the SameSite=Strict or SameSite=Lax cookie '
        'attribute to prevent cross-site cookie submission.'
    ),
    'CWE-434': (
        'Validate uploaded file types using server-side magic-byte inspection, '
        'not just the client-supplied MIME type or extension. Store uploads outside '
        'the web root and serve them through a controller that sets a safe '
        'Content-Type header. Scan uploads with antivirus before making them '
        'available to other users.'
    ),
    'CWE-502': (
        'Avoid deserializing data from untrusted sources. If deserialization is '
        'required, validate the data against a strict type allowlist before processing. '
        'Apply the latest vendor patches and monitor advisories for the serialization '
        'library in use.'
    ),
}

_REMEDIATION_BY_KEYWORD = {
    'open port': (
        'Verify each exposed port is required for the application or service. '
        'Use host-based firewall rules (iptables, Windows Firewall, AWS Security Groups) '
        'to restrict access to known source IPs. Disable or uninstall services not in use.'
    ),
    'default credential': (
        'Change all factory-default credentials immediately after deployment. '
        'Implement a provisioning workflow that enforces credential rotation before '
        'a device or service is brought into production. Add default credential '
        'checks to your internal vulnerability scanning cadence.'
    ),
    'tls 1.0': (
        'Disable TLS 1.0 and TLS 1.1. Configure the server to accept TLS 1.2 and '
        'TLS 1.3 only. Validate the change using testssl.sh or SSL Labs.'
    ),
    'tls 1.1': (
        'Disable TLS 1.1. TLS 1.2 and TLS 1.3 should be the only accepted versions. '
        'Validate using testssl.sh after reconfiguration.'
    ),
    'sslv': (
        'Disable SSLv2 and SSLv3 immediately. Both protocols are cryptographically '
        'broken and should not be offered under any circumstances.'
    ),
    'heartbleed': (
        'Upgrade OpenSSL to a patched version (>= 1.0.1g). After patching, '
        'revoke and reissue all TLS certificates that may have been exposed, '
        'and invalidate all active session tokens.'
    ),
    'discovered endpoint': (
        'Review whether this endpoint should be publicly accessible. '
        'Apply authentication controls, restrict by IP allowlist, or remove '
        'the endpoint if it serves no production purpose.'
    ),
    'phpinfo': (
        'Remove or restrict access to phpinfo() pages. These pages disclose '
        'server configuration, PHP extensions, environment variables, and file '
        'paths that facilitate further attacks.'
    ),
    '.git': (
        'Block access to the .git directory at the web server level. '
        'An exposed .git directory can leak full source code, commit history, '
        'and credentials embedded in the codebase.'
    ),
    'backup': (
        'Remove backup files from the web root. Backup files often contain source '
        'code, credentials, or configuration data and should be stored outside '
        'the document root with access controls enforced at the OS level.'
    ),
}


def enrich(findings: List[Finding]) -> None:
    """Fill in CVSS scores and remediation text where parsers left them blank."""
    for f in findings:
        if f.cvss_score is None:
            f.cvss_score = _CVSS_DEFAULT.get(f.severity, 0.0)
        if not f.remediation:
            f.remediation = _remediation_for(f)


def _remediation_for(f: Finding) -> str:
    if f.cwe and f.cwe in _REMEDIATION_BY_CWE:
        return _REMEDIATION_BY_CWE[f.cwe]
    title_lower = f.title.lower()
    for keyword, text in _REMEDIATION_BY_KEYWORD.items():
        if keyword in title_lower:
            return text
    if f.severity == 'critical':
        return (
            'This is a critical-severity finding. Apply the vendor-recommended patch '
            'or mitigation immediately. Escalate to the system owner and track '
            'remediation with a defined deadline (typically 24-72 hours).'
        )
    if f.severity == 'high':
        return (
            'Apply the vendor-recommended patch or configuration fix. '
            'Track remediation within your vulnerability management workflow '
            'with a deadline aligned to your SLA (typically 7-30 days).'
        )
    return (
        'Review the finding details and apply the relevant vendor guidance or '
        'security best-practice configuration for this component.'
    )
