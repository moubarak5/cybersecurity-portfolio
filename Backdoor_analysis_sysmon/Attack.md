# Attack Simulation : HTTP Meterpreter Backdoor (Red Team)

## Overview

This project documents a controlled red-team exercise performed against a Windows 10 virtual machine. The objective was to simulate a realistic attack chain and generate Sysmon telemetry for later defensive analysis.

The attack was conducted from a Kali Linux attacker machine using the Metasploit Framework against a Windows 10 target in an isolated lab environment.

## Attack Workflow

### 1. Payload Generation

A 64-bit Windows Meterpreter reverse HTTP payload was generated using `msfvenom`.

**Configuration**

- Payload: `windows/x64/meterpreter/reverse_http`
- LHOST: `10.0.2.15`
- LPORT: `31337`
- Output: `UnlockAllSubscriptions.exe`

This executable served as the initial access payload.

> <img width="809" height="75" alt="image" src="https://github.com/user-attachments/assets/c1ddb0cb-3f1a-41b6-8dc9-e84f57287e03" />



### 2. Command & Control

A Metasploit multi-handler was configured to receive the reverse connection.

After executing the payload on the Windows VM, a Meterpreter session was successfully established, confirming remote code execution and command-and-control communication.

> <img width="492" height="61" alt="image" src="https://github.com/user-attachments/assets/19cde9f8-c356-4dcc-96d6-2c51631c6d75" />



### 3. Post-Exploitation

Once access was obtained, several post-exploitation activities were performed.

#### System Enumeration

Basic reconnaissance commands were executed to identify the host and collect system information.

Examples include:

- `whoami`
- `hostname`
- `systeminfo`

The collected information was redirected to a temporary file for later review.

> <img width="632" height="39" alt="image" src="https://github.com/user-attachments/assets/422a0b0d-bf17-420d-a85d-fc75bf54306d" />



#### Persistence

A local administrator account was created to simulate a common persistence technique.

Commands used:

- `net user`
- `net localgroup Administrators`

A scheduled task was also created to demonstrate another persistence mechanism that could survive user logons.

> <img width="575" height="130" alt="image" src="https://github.com/user-attachments/assets/98f74573-38e8-4e90-93c4-0fcd174815be" />

> <img width="1181" height="59" alt="image" src="https://github.com/user-attachments/assets/f2a65a7f-b51b-476d-b31c-ba8563d071ec" />




#### Cleanup

To simulate attacker operational security (OpSec), the temporary administrator account was removed after testing. The payload remained on disk, allowing defensive tools to detect the compromise.

> <img width="421" height="56" alt="image" src="https://github.com/user-attachments/assets/bdd4e842-b391-46a9-beee-309126858ae5" />
 Cleanup process


## Attack Summary


1. Initial Access: Meterpreter reverse HTTP payload executed 
2. Command & Control: HTTP session established with Metasploit 
3. Enumeration: User and system information collected 
4. Persistence: Local administrator account and scheduled task created 
5. Cleanup: Temporary account removed 

## Detection Opportunities

This attack generates several valuable detection opportunities for defenders, including:

- Process creation events
- Network connections from unexpected processes
- User account creation
- Scheduled task creation
- Command-line activity
- Payload execution from the user's Downloads directory

These artifacts can be analyzed using Sysmon and Windows Event Logs to develop detection rules.

## Conclusion

This lab demonstrates a complete attack lifecycle, from initial payload execution through persistence and cleanup, within a safe virtual environment. The generated telemetry provides realistic data for blue-team analysis and detection engineering.

The companion document (`Defense.md`) analyzes the Sysmon logs produced during this simulation and demonstrates how each stage of the attack can be detected.
