# Offensive Security Certified Professional (OSCP) Exam Report

**Student:** YOUR NAME
**OSID:** OS-XXXXX
**Email:** nithishgurukumar@gmail.com
**Date:** ____-__-__

---

## 1. Introduction
This report documents the methodology and findings for the OSCP certification
exam. All work was performed against the machines provided in the exam
environment within the allotted 24-hour window.

## 2. Objective
Perform an authorized penetration test against the exam network, obtain
`local.txt` and `proof.txt` on each target, and document each step so the
process is fully reproducible.

## 3. Requirements / Passing Score
- 70 points required to pass.
- Standalone hosts: 10 pts local + 10 pts proof (20 each) — partial credit as stated in the control panel.
- Active Directory set: 40 pts (all-or-most, see exam guide for partial rules).
- Every proof must be shown in a screenshot **with the machine's IP visible** (e.g. `type proof.txt & ipconfig` / `cat proof.txt; ip a`).

---

## 4. High-Level Summary / Points Tally

| Target        | IP            | local.txt | proof.txt | Points |
|---------------|---------------|-----------|-----------|--------|
| AD - MS01     |               |           |           |        |
| AD - MS02     |               |           |           |        |
| AD - DC01     |               |           |           |        |
| Standalone 1  |               |           |           |        |
| Standalone 2  |               |           |           |        |
| Standalone 3  |               |           |           |        |
| **TOTAL**     |               |           |           |        |

---

## 5. Standalone Host: <NAME> (<IP>)

### 5.1 Service Enumeration
> Paste the relevant nmap output. Note the open ports and services.

```
<nmap services output>
```

### 5.2 Initial Access / Foothold
**Vulnerability:** ____
**Description:** How it was found and why it is exploitable.

_Steps (reproducible):_
1. ...

```
<commands + output>
```

📸 *Screenshot: initial shell obtained*

**local.txt:**
```
<contents> + ip a / ipconfig showing the target IP
```
📸 *Screenshot: local.txt with IP visible*

### 5.3 Privilege Escalation
**Vulnerability:** ____
**Description:** ____

_Steps:_
1. ...

```
<commands + output>
```

**proof.txt:**
```
<contents> + ip a / ipconfig showing the target IP
```
📸 *Screenshot: proof.txt with IP visible*

---

## 6. Active Directory Set

### 6.1 Enumeration & Initial Foothold (entry host)
...

### 6.2 Lateral Movement
> Credentials/hashes obtained, how they were used (netexec, evil-winrm, RDP, PsExec).

### 6.3 Domain Privilege Escalation (to DC / Domain Admin)
> Kerberoasting, DCSync, ACL abuse, GPO, etc. Include the proof on DC01.

---

## 7. Appendix — Additional Notes / Failed Attempts (optional)

