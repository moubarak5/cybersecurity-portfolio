# Windows Sysmon Log Analysis : Malware Attack Investigation

## Overview

This project demonstrates the analysis of Windows Sysmon logs to identify malicious activity on a compromised Windows host.

Using Sysmon Event Logs, I reconstructed the attack from the initial malware execution through persistence, privilege escalation, defense evasion, credential access, and command-and-control communication.

The objective of this investigation was to determine:

- How the attacker gained execution
- What actions were performed
- Which Sysmon Event IDs provided the evidence
- The overall attack timeline
- Indicators of Compromise (IoCs)
- Recommended remediation actions

---

# Environment

| Item | Value |
|------|-------|
| Operating System | Windows 10 |
| Log Source | Microsoft-Windows-Sysmon/Operational.evtx |
| Analysis Tool | Event Viewer |
| Monitoring Tool | Sysmon |

---

# Attack Summary

The investigation identified a malicious executable named **UnlockAllSubscriptions.exe** that was downloaded from the Internet and executed on the victim machine.

After execution, the malware:

- Collected system information
- Created a hidden administrator account
- Downloaded Mimikatz
- Created persistence through a Scheduled Task
- Established communication with a remote host
- Attempted to remove traces by deleting the created account

The attack successfully achieved persistence and command-and-control capabilities.

---

# Event ID Analysis

## Event ID 1 – Process Creation

### Description

Sysmon Event ID 1 records every process created on the system, including the executable, command line, parent process, hashes, and user.

This event provided the majority of the attack evidence.

### Malicious Activity Identified

#### Malware Execution

Process

UnlockAllSubscriptions.exe

Evidence

- Malware execution
- Initial payload

---

#### System Reconnaissance

Command

systeminfo

Purpose

The malware collected operating system information before continuing the attack.

> <img width="280" height="65" alt="image" src="https://github.com/user-attachments/assets/76ce4249-21f7-4034-92a4-f0126752de80" />


---

#### User Account Creation

Command

net user backdoor password /add

Purpose

Created a new local account named **backdoor**.

> <img width="434" height="60" alt="image" src="https://github.com/user-attachments/assets/3d2f8356-432b-44da-a6fe-e666ca4a5242" />


---

#### Privilege Escalation

Command

net localgroup Administrators backdoor /add

Purpose

Added the newly created account to the Administrators group.

> <img width="497" height="60" alt="image" src="https://github.com/user-attachments/assets/2d83c8d1-4fad-4782-8804-3e60628811db" />


---

#### Credential Access Preparation

Command

certutil -urlcache -split -f

Purpose

Downloaded Mimikatz while disguising it as a text file.

> <img width="745" height="61" alt="image" src="https://github.com/user-attachments/assets/a445526c-b171-48b4-ba82-ea0b341c2a31" />


---

#### Persistence

Command

schtasks /create ...

Purpose

Created a Scheduled Task named **backdoortask** to execute automatically after user logon.

> <img width="767" height="182" alt="image" src="https://github.com/user-attachments/assets/89c8c016-a62b-44d8-ab05-84704e38bc8b" />


---

#### Cleanup

Command

net user backdoor /delete

Purpose

Removed the attacker-created account to reduce evidence.

> <img width="321" height="110" alt="image" src="https://github.com/user-attachments/assets/f8c8e75d-3ee4-402c-ae82-62234d66d49f" />


---

## Event ID 3 – Network Connection

### Description

Event ID 3 records outbound network connections.

### Findings

Source Process

UnlockAllSubscriptions.exe

Destination IP

10.0.2.6

Destination Port

31337

The outbound connection indicates communication with a remote attacker and is consistent with reverse shell or command-and-control behavior.

> <img width="485" height="196" alt="image" src="https://github.com/user-attachments/assets/cbe83172-cc7b-4a3e-9675-6b6d58d114c4" />


---

## Event ID 15 – File Create Stream Hash

### Description

Event ID 15 records downloaded files together with their Zone Identifier.

### Findings

UnlockAllSubscriptions.exe

ZoneId = 3

Origin

Discord CDN

Hashes

MD5

SHA256

This confirms that the executable originated from the Internet.

> <img width="413" height="59" alt="image" src="https://github.com/user-attachments/assets/1fb44e3b-fa3a-4caa-a38a-9dc084509552" />


---

## Event ID 22 – DNS Query

### Description

Event ID 22 records DNS lookups performed by processes.

### Findings

The malicious executable generated DNS requests to external services including:

- Discord CDN
- GitHub

These lookups correspond with downloading the malware and retrieving Mimikatz.

> <img width="745" height="61" alt="image" src="https://github.com/user-attachments/assets/813853fc-1776-478a-8afd-20e2b760acf3" />



---

# Indicators of Compromise

## Files

- UnlockAllSubscriptions.exe

## Hashes

MD5

D0EFB3F71066539A65D3E42E0951CE23

SHA256

68062C61659529A13ED6213DD372BF06DB24924846C7E4616AB00E6B73F4C460

## Accounts

backdoor

## Scheduled Task

backdoortask

## Network

10.0.2.6:31337

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Execution | User Execution |
| Discovery | System Information Discovery |
| Persistence | Scheduled Task |
| Privilege Escalation | Create Account |
| Defense Evasion | Impair Defenses |
| Credential Access | Credential Dumping |
| Command and Control | Application Layer Protocol |

---

# Recommendations

- Isolate the compromised host.
- Remove malicious scheduled tasks.
- Restore Windows Defender settings.
- Reset potentially compromised credentials.
- Scan the system for additional persistence mechanisms.
- Reimage the system if compromise cannot be fully ruled out.

---

# Conclusion

This investigation demonstrates how Sysmon logs can be used to reconstruct the full attack lifecycle of a Windows compromise.

By analyzing Process Creation, Network Connections, Registry Changes, File Creation, and DNS Query events, it was possible to identify the attack chain from initial execution to persistence and command-and-control communication.

The investigation highlights the importance of Sysmon for threat hunting, incident detection, and post-incident analysis in Windows environments.
