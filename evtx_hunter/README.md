# 🐍 evtx_hunter

**A Python-based threat hunting tool for Windows Event Logs (EVTX).**

Parses `.evtx` files, runs 16 detection modules, and gives you a risk summary in seconds. Built for incident responders, SOC analysts, and anyone who's ever cried over XML namespaces.

---

## ✨ Features

- **🔍 16 Detection Modules** – Brute Force, Password Spray, DCSync, Kerberoasting, LOLBAS, Process Injection, Persistence, Log Tampering, and more.
- **📊 Risk Scoring** – Severity levels: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
- **📤 Export Options** – JSON and CSV export (because flattening nested fields is harder than it should be).
- **🔎 Search Filter** – Filter events by keyword using `--search`.
- **⚡ Fast** – Parses even large EVTX files efficiently (thanks to `python-evtx` + `lxml`).

---

## 🚀 Installation

```bash
pip install python-evtx lxml
````
# 📖 Usage
Basic – Scan a file or directory
```bash
python evtx_hunter.py log5.evtx

python evtx_hunter.py C:\Logs\ 
````

# Export to CSV or JSON
````bash

python evtx_hunter.py log5.evtx --csv report.csv
python evtx_hunter.py log5.evtx --json report.json
````
# Search for a keyword
````bash

python evtx_hunter.py log5.evtx --search "mimikatz"
````
# 🧪 Sample Output

Example:
````text

======================================================================
  DETECTION SUMMARY: 1 findings
    Critical: 1  |  High: 0  |  Medium: 0  |  Low: 0
======================================================================

CRITICAL FINDINGS (1)
----------------------------------------------------------------------

  [CRITICAL] Audit Log Cleared
  Count: 1  |  1 audit log clearing events (EVIDENCE TAMPERING)
      2019-11-15 08:19:02  EID=1102  Audit Log Cleared

````

# 🛡️ Detection Modules
````text
Category	Event IDs / Patterns
Brute Force	4625 failures grouped by IP/User
Password Spray	>3 users from same IP
LOLBAS Execution	Matches known living-off-the-land binaries
Suspicious Commands	Encoded PS, IEX, Mimikatz strings, AMSI bypass
Credential Dumping	LSASS access, SAM/SECURITY hives, procdump/comsvcs
Persistence	Service installs, scheduled tasks, registry run keys
Privilege Escalation	UAC bypass patterns, excessive privileges
Lateral Movement	RDP, PsExec, admin shares, WMI
Kerberoasting	High volume of TGS requests (4769)
DCSync	Directory replication requests (4662)
PowerShell Abuse	Encoded/obfuscated ScriptBlock logs
Log Tampering	Audit log cleared (1102), wevtutil usage
Ransomware Precursors	Shadow copy deletions, recovery disabling
Process Injection	CreateRemoteThread (8), suspicious access rights (10)
Time Anomalies	Logons outside 6am–10pm
Security Changes	Firewall disabled, audit policy changes
````
# 📂 Test Logs

Sample logs are included in the samples/ folder:

    log3.evtx – 2 Sysmon network events (no threats)

    log4.evtx – 1 Sysmon file create (no threats)

    log5.evtx – 3 Security events incl. Audit Log Cleared (1102)

# ⚠️ Limitations & Known Quirks

    CSV Export – Flattening arbitrary nested EventData fields required a dynamic pre-scan. It works, but memory usage can be heavy for massive files. Proceed with caution.

    Hardcoded Thresholds – Brute force triggers at 5 failures, password spray at 3 users. These may need tuning for your environment.

    False Positives – Regex-based detection is powerful but can fire on legitimate admin activity. Always verify findings.

    EventData Inconsistencies – Sysmon and Security logs use different field names (Image vs NewProcessName). The parser handles common ones but may miss obscure fields.

# 🤔 What's Next?

Honestly, not sure yet. I've been playing with ideas like:

    YARA rules for in-memory scanning

    Time-series anomaly detection to catch attack chains

    Real-time monitoring via Windows Event Collector

    A web UI for visual analysis
