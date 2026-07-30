#!/usr/bin/env python3

import sys
import os
import re
import csv
import json
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timedelta

try:
    from Evtx.Evtx import Evtx
    from lxml import etree


# OopCompanion:suppressRename
except ImportError:
    print("[!] Missing dependencies. Run: pip install python-evtx lxml")
    sys.exit(1)


# DETECTION DATABASES

# LOLBAS binaries commonly abused by attackers
LOLBAS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe",
    "mshta.exe", "certutil.exe", "bitsadmin.exe", "regsvr32.exe", "rundll32.exe",
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "csi.exe", "dnx.exe", "fsi.exe", "ieexec.exe", "microsoft.workflow.compiler.exe",
    "msdeploy.exe", "msxsl.exe", "odbcconf.exe", "rcsi.exe", "sc.exe",
    "schtasks.exe", "wmic.exe", "wuauclt.exe", "xwizard.exe", "at.exe",
    "net.exe", "net1.exe", "nltest.exe", "qprocess.exe", "qwinsta.exe",
    "rexec.exe", "runas.exe", "ssh.exe", "telnet.exe", "verclsid.exe",
    "whoami.exe", "vssadmin.exe", "wbadmin.exe", "wce.exe", "procdump.exe",
    "comsvcs.dll", "davsetcookie.exe", "dfsvc.exe", "diskshadow.exe",
    "esentutl.exe", "expand.exe", "extrac32.exe", "findstr.exe", "forfiles.exe",
    "ftp.exe", "gfxdownloadwrapper.exe", "gpscript.exe", "ie4uinit.exe",
    "ieadvpack.dll", "infdefaultinstall.exe", "makecab.exe", "mavinject.exe",
    "mmc.exe", "mpcmdrun.exe", "msdt.exe", "msdtc.exe", "msiexec.exe",
    "pcalua.exe", "pcwrun.exe", "presentationhost.exe", "print.exe",
    "psr.exe", "rasautou.exe", "reg.exe", "register-cimprovider.exe",
    "replace.exe", "robocopy.exe", "rpcping.exe", "runscripthelper.exe",
    "scriptrunner.exe", "settingSyncHost.exe", "setupapi.dll", "shdocvw.dll",
    "shell32.dll", "syncappvpublishingserver.exe", "tracerpt.exe", "tttracer.exe",
    "update.exe", "vbc.exe", "vsjitdebugger.exe", "wab.exe", "winrm.vbs",
    "winword.exe", "wmic.exe", "wscript.exe", "wsreset.exe", "xwizard.exe",
}

# Suspicious command patterns
SUSPICIOUS_PATTERNS = [
    (r"-enc\s+[A-Za-z0-9+/=]{20,}", "Encoded PowerShell command"),
    (r"-encodedcommand\s+[A-Za-z0-9+/=]{20,}", "Encoded PowerShell command"),
    (r"IEX\s*\(", "PowerShell Invoke-Expression"),
    (r"Invoke-Expression", "PowerShell Invoke-Expression"),
    (r"Invoke-Mimikatz", "Mimikatz invocation"),
    (r"DumpCreds", "Credential dumping"),
    (r"sekurlsa::", "Mimikatz sekurlsa module"),
    (r"lsadump::", "Mimikatz lsadump module"),
    (r"kerberos::", "Mimikatz kerberos module"),
    (r"token::elevate", "Privilege escalation attempt"),
    (r"process::list", "Process enumeration"),
    (r"net\s+user\s+.*\s+/add", "User account creation via net"),
    (r"net\s+localgroup\s+administrators", "Admin group modification"),
    (r"reg\s+save\s+HKLM\\SAM", "SAM hive dump"),
    (r"reg\s+save\s+HKLM\\SECURITY", "SECURITY hive dump"),
    (r"vssadmin\s+delete\s+shadows", "Shadow copy deletion (ransomware)"),
    (r"wbadmin\s+delete\s+catalog", "Backup catalog deletion"),
    (r"bcdedit\s+/set\s+\{default\}\s+recoveryenabled\s+No", "Disable recovery"),
    (r"wevtutil\s+cl", "Event log clearing"),
    (r"wevtutil\s+clear-log", "Event log clearing"),
    (r"wmic\s+shadowcopy\s+delete", "Shadow copy deletion"),
    (r"certutil\s+-urlcache\s+-split\s+-f", "Certutil download"),
    (r"certutil\s+-decode", "Certutil decode"),
    (r"bitsadmin\s+/transfer", "BITS download"),
    (r"mshta\s+(http|https|ftp)", "MSHTA remote execution"),
    (r"regsvr32\s+/i:http", "Regsvr32 remote execution"),
    (r"rundll32\s+.*,#", "Rundll32 suspicious call"),
    (r"rundll32\s+javascript:", "Rundll32 JavaScript"),
    (r"powershell\s+.*-nop\s+.*-w\s+hidden", "Hidden PowerShell window"),
    (r"powershell\s+.*-windowstyle\s+hidden", "Hidden PowerShell window"),
    (r"powershell\s+.*downloadstring", "PowerShell download"),
    (r"powershell\s+.*invoke-webrequest", "PowerShell download"),
    (r"powershell\s+.*net.webclient", "PowerShell WebClient"),
    (r"amsiinitfailed", "AMSI bypass"),
    (r"[Reflection.Assembly]::Load", "Assembly loading"),
    (r"System.Reflection.Assembly", "Assembly loading"),
    (r"VirtualAlloc", "Memory allocation (injection)"),
    (r"WriteProcessMemory", "Process memory write"),
    (r"CreateRemoteThread", "Remote thread creation"),
    (r"NtMapViewOfSection", "Process injection"),
    (r"procdump.*lsass", "LSASS dump via procdump"),
    (r"comsvcs.dll,\s*MiniDump", "LSASS dump via comsvcs"),
    (r"taskkill\s+/f\s+/im", "Process termination"),
    (r"sc\s+create", "Service creation"),
    (r"sc\s+start", "Service start"),
    (r"schtasks\s+/create", "Scheduled task creation"),
    (r"at\s+\\\\d+\.\d+\.\d+\.\d+", "Remote scheduled task (at.exe)"),
    (r"wmic\s+/node:", "Remote WMI execution"),
    (r"wmic\s+process\s+call\s+create", "WMI process creation"),
    (r"psexec", "PsExec execution"),
    (r"\$admin", "Admin share access"),
    (r"\\\\[^\\]+\\(c|d|e)\$", "Admin share access"),
    (r"net\s+use\s+.*\\\\.*\\\$", "Admin share mapping"),
    (r"copy\s+.*\\\\.*\admin\$", "File copy to admin share"),
    (r"robocopy\s+.*\\\\.*\\\w+\$", "Robocopy to hidden share"),
]

# Event ID database with descriptions and risk
EVENT_DB = {
    4624: ("Logon Success", "info"),
    4625: ("Logon Failed", "high"),
    4634: ("Logoff", "info"),
    4647: ("User Logoff", "info"),
    4648: ("Explicit Credentials", "high"),
    4657: ("Registry Value Modified", "medium"),
    4672: ("Admin Privileges Assigned", "medium"),
    4673: ("Privileged Service Called", "medium"),
    4674: ("Privileged Object Operation", "medium"),
    4688: ("Process Created", "medium"),
    4697: ("Service Installed", "high"),
    4698: ("Scheduled Task Created", "high"),
    4699: ("Scheduled Task Deleted", "medium"),
    4700: ("Scheduled Task Enabled", "medium"),
    4701: ("Scheduled Task Disabled", "medium"),
    4702: ("Scheduled Task Updated", "medium"),
    4720: ("User Account Created", "high"),
    4722: ("User Account Enabled", "medium"),
    4723: ("Password Change Attempt", "medium"),
    4724: ("Password Reset Attempt", "high"),
    4725: ("User Account Disabled", "medium"),
    4726: ("User Account Deleted", "high"),
    4727: ("Global Group Created", "medium"),
    4728: ("Member Added to Global Group", "high"),
    4729: ("Member Removed from Global Group", "medium"),
    4730: ("Global Group Deleted", "medium"),
    4731: ("Local Group Created", "medium"),
    4732: ("Member Added to Local Group", "high"),
    4733: ("Member Removed from Local Group", "medium"),
    4734: ("Local Group Deleted", "medium"),
    4735: ("Local Group Changed", "medium"),
    4737: ("Global Group Changed", "medium"),
    4738: ("User Account Changed", "medium"),
    4739: ("Domain Policy Changed", "high"),
    4740: ("Account Locked Out", "high"),
    4741: ("Computer Account Created", "medium"),
    4742: ("Computer Account Changed", "medium"),
    4743: ("Computer Account Deleted", "medium"),
    4754: ("Universal Group Created", "medium"),
    4755: ("Universal Group Changed", "medium"),
    4756: ("Member Added to Universal Group", "high"),
    4757: ("Member Removed from Universal Group", "medium"),
    4768: ("Kerberos TGT Requested", "medium"),
    4769: ("Kerberos Service Ticket", "medium"),
    4771: ("Kerberos Pre-auth Failed", "high"),
    4776: ("NTLM Auth", "medium"),
    4778: ("Session Reconnected", "info"),
    4779: ("Session Disconnected", "info"),
    4788: ("Account Deleted", "high"),
    4798: ("Local Group Enumeration", "low"),
    4799: ("Security Group Enumeration", "low"),
    4964: ("Special Group Assigned", "medium"),
    5136: ("Directory Service Object Modified", "medium"),
    5137: ("Directory Service Object Created", "medium"),
    5138: ("Directory Service Object Undeleted", "medium"),
    5139: ("Directory Service Object Moved", "medium"),
    5140: ("Network Share Accessed", "low"),
    5141: ("Directory Service Object Deleted", "medium"),
    5145: ("Network Share File Accessed", "low"),
    5156: ("Network Allowed", "low"),
    5157: ("Network Blocked", "low"),
    7045: ("Service Installed", "high"),
    1102: ("Audit Log Cleared", "critical"),
    6005: ("Event Log Started", "info"),
    6006: ("Event Log Stopped", "info"),
    6008: ("Unexpected Shutdown", "high"),
    1074: ("System Shutdown", "info"),
    4103: ("PowerShell Module", "medium"),
    4104: ("PowerShell ScriptBlock", "high"),
    4105: ("PowerShell Command Start", "medium"),
    4106: ("PowerShell Command Stop", "medium"),
    4689: ("Process Exited", "info"),
    4696: ("Primary Token Assigned", "medium"),
    4719: ("Audit Policy Changed", "high"),
    4816: ("RPC Interface Access", "low"),
    4826: ("Boot Config Changed", "medium"),
    4904: ("Security Log Source Added", "medium"),
    4905: ("Security Log Source Removed", "medium"),
    4907: ("Object Auditing Changed", "medium"),
    4912: ("Per User Audit Policy Changed", "high"),
    5025: ("Firewall Service Stopped", "high"),
    5031: ("Firewall Blocked App", "low"),
    5034: ("Firewall Driver Stopped", "high"),
    5035: ("Firewall Driver Failed", "high"),
    5058: ("Key File Operation", "low"),
    5059: ("Key Migration Operation", "low"),
    5061: ("Cryptographic Operation", "low"),
    1: ("Sysmon ProcessCreate", "medium"),
    3: ("Sysmon Network", "low"),
    5: ("Sysmon ProcessTerminate", "info"),
    6: ("Sysmon DriverLoaded", "high"),
    7: ("Sysmon ImageLoaded", "medium"),
    8: ("Sysmon CreateRemoteThread", "high"),
    9: ("Sysmon RawAccessRead", "medium"),
    10: ("Sysmon ProcessAccess", "high"),
    11: ("Sysmon FileCreate", "medium"),
    12: ("Sysmon RegistryEvent", "medium"),
    13: ("Sysmon RegistrySet", "medium"),
    14: ("Sysmon RegistryRename", "medium"),
    15: ("Sysmon FileCreateStreamHash", "high"),
    16: ("Sysmon ConfigChange", "medium"),
    17: ("Sysmon PipeCreated", "medium"),
    18: ("Sysmon PipeConnected", "medium"),
    19: ("Sysmon WmiEventFilter", "medium"),
    20: ("Sysmon WmiEventConsumer", "medium"),
    21: ("Sysmon WmiEventBinding", "medium"),
    22: ("Sysmon DNSQuery", "medium"),
    23: ("Sysmon FileDelete", "medium"),
    24: ("Sysmon ClipboardChange", "medium"),
    25: ("Sysmon ProcessTampering", "high"),
    26: ("Sysmon FileDeleteDetected", "medium"),
    255: ("Sysmon Error", "high"),
}


# PARSER

def parse_evtx(filepath):
    events = []
    try:
        with Evtx(filepath) as log:
            for record in log.records():
                try:
                    root = etree.fromstring(record.xml().encode())
                    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                    eid = int(root.findtext(".//e:EventID", default="0", namespaces=ns))
                    ts_elem = root.find(".//e:TimeCreated", ns)
                    ts = ts_elem.get("SystemTime") if ts_elem is not None else ""
                    ch = root.findtext(".//e:Channel", default="", namespaces=ns)
                    pc = root.findtext(".//e:Computer", default="", namespaces=ns)
                    data = {}
                    ed = root.find(".//e:EventData", ns)
                    if ed is not None:
                        for child in ed:
                            data[child.get("Name", "?")] = child.text or ""
                    events.append({
                        "eid": eid, "time": ts, "channel": ch,
                        "computer": pc, "data": data,
                        "file": os.path.basename(filepath),
                    })
                except Exception:
                    continue
    except Exception as e:
        print(f"[!] Error reading {filepath}: {e}")
    return events


def find_files(path):
    p = Path(path)
    if p.is_file() and p.suffix.lower() == ".evtx":
        return [str(p)]
    if p.is_dir():
        return [str(f) for f in p.rglob("*.evtx")]
    return []


def parse_time(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except:
        return None


# DETECTION ENGINE

class DetectionEngine:
    def __init__(self, events):
        self.events = events
        self.findings = []

    def add(self, title, severity, description, events_sample, count=None):
        self.findings.append({
            "title": title,
            "severity": severity,
            "description": description,
            "count": count or len(events_sample),
            "sample": events_sample[:5],
        })

    # --- 1. Brute Force Detection ---
    def detect_brute_force(self):
        failed = [e for e in self.events if e["eid"] == 4625]
        by_ip = defaultdict(list)
        by_user = defaultdict(list)
        for e in failed:
            ip = e["data"].get("IpAddress", "?")
            user = e["data"].get("TargetUserName", "?")
            if ip and ip != "?":
                by_ip[ip].append(e)
            if user and user != "?":
                by_user[user].append(e)

        for ip, evts in by_ip.items():
            if len(evts) >= 5:
                self.add(
                    "Brute Force Attack",
                    "critical",
                    f"{len(evts)} failed logons from IP {ip}",
                    evts,
                    len(evts)
                )
        for user, evts in by_user.items():
            if len(evts) >= 5:
                self.add(
                    "Account Under Brute Force",
                    "critical",
                    f"{len(evts)} failed logons targeting user {user}",
                    evts,
                    len(evts)
                )

    # 2. Password Spray
    def detect_password_spray(self):
        failed = [e for e in self.events if e["eid"] == 4625]
        by_ip = defaultdict(set)
        for e in failed:
            ip = e["data"].get("IpAddress", "?")
            user = e["data"].get("TargetUserName", "?")
            if ip != "?" and user != "?":
                by_ip[ip].add(user)
        for ip, users in by_ip.items():
            if len(users) >= 3:
                evts = [e for e in failed if e["data"].get("IpAddress") == ip]
                self.add(
                    "Password Spray Attack",
                    "critical",
                    f"{len(users)} different users targeted from {ip}",
                    evts,
                    len(evts)
                )

    # 3. Suspicious Process Execution (LOLBAS + patterns)
    def detect_suspicious_processes(self):
        proc_events = [e for e in self.events if e["eid"] in (4688, 1)]
        lolbas_hits = []
        pattern_hits = []
        for e in proc_events:
            cmd = e["data"].get("CommandLine", e["data"].get("Commandline", ""))
            img = e["data"].get("NewProcessName", e["data"].get("Image", ""))
            path = (cmd + " " + img).lower()
            for binary in LOLBAS:
                if binary in path:
                    lolbas_hits.append(e)
                    break
            for pattern, desc in SUSPICIOUS_PATTERNS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    e["_pattern_desc"] = desc
                    pattern_hits.append(e)
                    break
        if lolbas_hits:
            self.add(
                "LOLBAS Execution",
                "high",
                f"{len(lolbas_hits)} events involving Living Off The Land binaries",
                lolbas_hits,
                len(lolbas_hits)
            )
        if pattern_hits:
            self.add(
                "Suspicious Command Patterns",
                "critical",
                f"{len(pattern_hits)} events with suspicious command-line patterns",
                pattern_hits,
                len(pattern_hits)
            )

    # 4. Credential Dumping
    def detect_credential_dumping(self):
        # LSASS access
        lsass = [e for e in self.events if e["eid"] == 10
                 and "lsass" in e["data"].get("TargetImage", "").lower()]
        if lsass:
            self.add(
                "LSASS Access (Credential Dumping)",
                "critical",
                f"{len(lsass)} processes accessed LSASS memory",
                lsass,
                len(lsass)
            )


        # SAM/SECURITY hive
        sam = [e for e in self.events if e["eid"] in (4688, 1)
               and any(x in e["data"].get("CommandLine", "").lower()
                       for x in ["sam", "security", "system"])
               and "reg save" in e["data"].get("CommandLine", "").lower()]
        if sam:
            self.add(
                "Registry Hive Dump",
                "critical",
                f"{len(sam)} attempts to dump SAM/SECURITY/SYSTEM hives",
                sam,
                len(sam)
            )
        # Procdump/comsvcs LSASS
        dump = [e for e in self.events if e["eid"] in (4688, 1)
                and any(x in e["data"].get("CommandLine", "").lower()
                        for x in ["procdump", "comsvcs.dll", "minidump", "lsass"])]
        if dump:
            self.add(
                "LSASS Dump via Known Tools",
                "critical",
                f"{len(dump)} events indicating LSASS dump",
                dump,
                len(dump)
            )

    # 5. Persistence
    def detect_persistence(self):
        # Service installs
        svcs = [e for e in self.events if e["eid"] in (7045, 4697)]
        if svcs:
            self.add(
                "Service Installation (Persistence)",
                "high",
                f"{len(svcs)} new services installed",
                svcs,
                len(svcs)
            )
        # Scheduled tasks
        tasks = [e for e in self.events if e["eid"] == 4698]
        if tasks:
            self.add(
                "Scheduled Task Created (Persistence)",
                "high",
                f"{len(tasks)} scheduled tasks created",
                tasks,
                len(tasks)
            )
        # Registry run keys
        reg_persist_paths = ["run", "runonce", "services", "winlogon"]
        reg = [e for e in self.events if e["eid"] in (12, 13, 4657)
               and any(x in e["data"].get("TargetObject", "").lower()
                       for x in reg_persist_paths)]
        if reg:
            self.add(
                "Registry Persistence",
                "high",
                f"{len(reg)} registry modifications in persistence locations",
                reg,
                len(reg)
            )

    # 6. Privilege Escalation
    def detect_privesc(self):
        # Token manipulation
        tokens = [e for e in self.events if e["eid"] == 4672]
        if len(tokens) > 20:
            self.add(
                "Excessive Privilege Use",
                "medium",
                f"{len(tokens)} special privilege assignments -- review for abnormal volume",
                tokens[:10],
                len(tokens)
            )
        # UAC bypass indicators
        uac = [e for e in self.events if e["eid"] in (4688, 1)
               and any(x in e["data"].get("CommandLine", "").lower()
                       for x in ["eventvwr", "fodhelper", "computerdefaults", "sdclt"])]
        if uac:
            self.add(
                "UAC Bypass Attempt",
                "high",
                f"{len(uac)} events indicating UAC bypass techniques",
                uac,
                len(uac)
            )

    # 7. Lateral Movement
    def detect_lateral_movement(self):
        # RDP
        rdp = [e for e in self.events if e["eid"] in (4624, 1149)
               and e["data"].get("LogonType") in ("10", "7")
               or "tsclient" in e["data"].get("ProcessName", "").lower()]
        if rdp:
            self.add(
                "RDP Activity",
                "medium",
                f"{len(rdp)} RDP-related events",
                rdp,
                len(rdp)
            )
        # PsExec / remote services
        psexec = [e for e in self.events if e["eid"] in (4688, 1, 5140, 5145)
                  and any(x in json.dumps(e["data"]).lower()
                          for x in ["psexec", "admin$", "c$", "ipc$"])]
        if psexec:
            self.add(
                "PsExec / Admin Share Usage",
                "high",
                f"{len(psexec)} events indicating lateral movement via shares or PsExec",
                psexec,
                len(psexec)
            )
        # WMI
        wmi = [e for e in self.events if e["eid"] in (4688, 1, 5857, 5858, 5859, 5860, 5861)
               and "wmic" in e["data"].get("CommandLine", "").lower()]
        if wmi:
            self.add(
                "WMI Lateral Movement",
                "high",
                f"{len(wmi)} WMI-based remote execution events",
                wmi,
                len(wmi)
            )

    # 8. Kerberoasting
    def detect_kerberoasting(self):
        # Many TGS requests (4769) in short time = possible Kerberoasting
        tgs = [e for e in self.events if e["eid"] == 4769]
        if len(tgs) >= 10:
            self.add(
                "Possible Kerberoasting",
                "high",
                f"{len(tgs)} Kerberos service ticket requests -- possible Kerberoasting attack",
                tgs,
                len(tgs)
            )

    # 9. DCSync
    def detect_dcsync(self):
        # 4662 with specific properties = DCSync
        dcsync = [e for e in self.events if e["eid"] == 4662
                  and any(x in e["data"].get("Properties", "").lower()
                          for x in ["replicating directory changes", "1131f6ad-9c07-11d1"])]
        if dcsync:
            self.add(
                "DCSync Attack",
                "critical",
                f"{len(dcsync)} DCSync replication requests detected",
                dcsync,
                len(dcsync)
            )

    # 10. PowerShell Abuse
    def detect_powershell_abuse(self):
        ps = [e for e in self.events if e["eid"] in (4103, 4104)
              and e["data"].get("ScriptBlockText", "")]
        encoded = []
        suspicious = []
        for e in ps:
            text = e["data"].get("ScriptBlockText", "")
            if any(x in text.lower() for x in ["-enc", "-encodedcommand", "frombase64string"]):
                encoded.append(e)
            if any(x in text.lower() for x in ["invoke-mimikatz", "iex", "invoke-expression",
                                                  "downloadstring", "net.webclient", "amsi", "reflect"]):
                suspicious.append(e)
        if encoded:
            self.add(
                "Encoded PowerShell Commands",
                "high",
                f"{len(encoded)} encoded or obfuscated PowerShell commands",
                encoded,
                len(encoded)
            )
        if suspicious:
            self.add(
                "Suspicious PowerShell Activity",
                "critical",
                f"{len(suspicious)} PowerShell events with suspicious keywords",
                suspicious,
                len(suspicious)
            )

    # 11. Audit Log Tampering
    def detect_log_tampering(self):
        cleared = [e for e in self.events if e["eid"] == 1102]
        if cleared:
            self.add(
                "Audit Log Cleared",
                "critical",
                f"{len(cleared)} audit log clearing events (EVIDENCE TAMPERING)",
                cleared,
                len(cleared)
            )
        wevt = [e for e in self.events if e["eid"] in (4688, 1)
                and "wevtutil" in e["data"].get("CommandLine", "").lower()]
        if wevt:
            self.add(
                "Event Log Clearing via wevtutil",
                "high",
                f"{len(wevt)} wevtutil executions (possible log clearing)",
                wevt,
                len(wevt)
            )

    # 12. Ransomware Idicators
    def detect_ransomware(self):
        # Shadow copy deletion
        shadow = [e for e in self.events if e["eid"] in (4688, 1)
                  and any(x in e["data"].get("CommandLine", "").lower()
                          for x in ["vssadmin delete shadows", "wmic shadowcopy delete",
                                    "wbadmin delete catalog", "bcdedit /set {default} recoveryenabled no"])]
        if shadow:
            self.add(
                "Ransomware Precursor (Shadow Copy Deletion)",
                "critical",
                f"{len(shadow)} shadow copy / recovery deletion commands",
                shadow,
                len(shadow)
            )

    # 13. Account Anomalies
    def detect_account_anomalies(self):
        # Account created then quickly added to admin group
        created = {e["data"].get("TargetUserName", ""): e for e in self.events if e["eid"] == 4720}
        added = [e for e in self.events if e["eid"] in (4728, 4732, 4756)]
        suspicious_adds = []
        for e in added:
            user = e["data"].get("MemberName", e["data"].get("TargetUserName", ""))
            if user in created:
                suspicious_adds.append(e)
        if suspicious_adds:
            self.add(
                "New Account Elevated to Admin",
                "critical",
                f"{len(suspicious_adds)} newly created accounts added to privileged groups",
                suspicious_adds,
                len(suspicious_adds)
            )
        # Account lockouts
        locks = [e for e in self.events if e["eid"] == 4740]
        if locks:
            self.add(
                "Account Lockouts",
                "medium",
                f"{len(locks)} account lockout events",
                locks,
                len(locks)
            )

    # 14. Firewall / Security Changes
    def detect_security_changes(self):
        fw_stop = [e for e in self.events if e["eid"] in (5025, 5034, 5035)]
        if fw_stop:
            self.add(
                "Firewall Disabled",
                "high",
                f"{len(fw_stop)} firewall service/driver stop events",
                fw_stop,
                len(fw_stop)
            )
        audit = [e for e in self.events if e["eid"] == 4719]
        if audit:
            self.add(
                "Audit Policy Changed",
                "high",
                f"{len(audit)} audit policy modifications",
                audit,
                len(audit)
            )

    # 15. Process Injection
    def detect_process_injection(self):
        inject = [e for e in self.events if e["eid"] == 8]
        if inject:
            self.add(
                "Process Injection (CreateRemoteThread)",
                "critical",
                f"{len(inject)} CreateRemoteThread events",
                inject,
                len(inject)
            )
        # Process access with suspicious rights
        access = [e for e in self.events if e["eid"] == 10
                  and any(x in e["data"].get("GrantedAccess", "").lower()
                          for x in ["0x1010", "0x1fffff", "0x1410", "0x143a"])]
        if access:
            self.add(
                "Suspicious Process Access Rights",
                "high",
                f"{len(access)} process access events with suspicious access rights",
                access,
                len(access)
            )

    # 16. Time-based anomalies
    def detect_time_anomalies(self):
        # Logons outside business hours (before 6am or after 10pm)
        off_hours = []
        for e in self.events:
            if e["eid"] == 4624:
                dt = parse_time(e["time"])
                if dt and (dt.hour < 6 or dt.hour >= 22):
                    off_hours.append(e)
        if len(off_hours) >= 5:
            self.add(
                "After-Hours Logon Activity",
                "medium",
                f"{len(off_hours)} logons outside normal hours (before 6am or after 10pm)",
                off_hours,
                len(off_hours)
            )

    def run_all(self):
        print("[*] Running detection engines...")
        self.detect_brute_force()
        self.detect_password_spray()
        self.detect_suspicious_processes()
        self.detect_credential_dumping()
        self.detect_persistence()
        self.detect_privesc()
        self.detect_lateral_movement()
        self.detect_kerberoasting()
        self.detect_dcsync()
        self.detect_powershell_abuse()
        self.detect_log_tampering()
        self.detect_ransomware()
        self.detect_account_anomalies()
        self.detect_security_changes()
        self.detect_process_injection()
        self.detect_time_anomalies()
        return self.findings


# OUTPUT

def print_findings(findings):
    if not findings:
        print("\n[+] No threats detected. Logs look clean.")
        return

    critical = [f for f in findings if f["severity"] == "critical"]
    high = [f for f in findings if f["severity"] == "high"]
    medium = [f for f in findings if f["severity"] == "medium"]
    low = [f for f in findings if f["severity"] == "low"]

    print(f"\n{'='*70}")
    print(f"  DETECTION SUMMARY: {len(findings)} findings")
    print(f"    Critical: {len(critical)}  |  High: {len(high)}  |  Medium: {len(medium)}  |  Low: {len(low)}")
    print(f"{'='*70}")

    for sev in ["critical", "high", "medium", "low"]:
        group = [f for f in findings if f["severity"] == sev]
        if not group:
            continue

        print(f"\n{sev.upper()} FINDINGS ({len(group)})")
        print("-" * 70)
        for f in group:
            print(f"\n  [{f['severity'].upper()}] {f['title']}")
            print(f"  Count: {f['count']}  |  {f['description']}")
            for e in f["sample"]:
                ts = e["time"].replace("T", " ")[:19] if e["time"] else ""
                eid = e["eid"]
                desc, _ = EVENT_DB.get(eid, ("Unknown", "unknown"))
                extra = ""
                if e["data"]:
                    # Show most relevant field
                    for key in ["CommandLine", "Image", "TargetUserName", "IpAddress", "ServiceName", "ScriptBlockText"]:
                        if key in e["data"] and e["data"][key]:
                            val = e["data"][key]
                            if len(val) > 80:
                                val = val[:77] + "..."
                            extra = f" | {key}={val}"
                            break
                print(f"      {ts}  EID={eid}  {desc}{extra}")
            if f["count"] > len(f["sample"]):
                print(f"      ... and {f['count'] - len(f['sample'])} more")


def print_summary(events):
    counts = Counter(e["eid"] for e in events)
    channels = Counter(e["channel"] for e in events)
    daily = Counter(e["time"][:10] for e in events if len(e["time"]) >= 10)

    print(f"\n{'='*70}")
    print( " " * 15 + f"  TOTAL EVENTS: {len(events)}")
    print(f"{'='*70}")
    print()

    print(" " * 15 + "--- Top Event IDs ---")
    print(f"{'Count':>8}  {'EID':>6}  {'Risk':>6}  {'Description'}")
    print("-" * 60)
    for eid, cnt in counts.most_common(15):
        desc, risk = EVENT_DB.get(eid, ("Unknown", "unknown"))

        print(f"{cnt:>8}  {eid:>6}  [{risk[:4].upper():>4}]  {desc}")
    print()
    print()

    print(" " * 15 + "--- Channels ---")
    for ch, cnt in channels.most_common(8):
        print(f"  {cnt:>7}  {ch}")
    print()
    print()
    
    if daily:
        print(" " * 15 + "--- Daily Timeline ---")
        for day in sorted(daily):
            bar = "#" * min(daily[day] // 100, 50)
            print(f"  {day}  {daily[day]:>7}  {bar}")


def export_json(events, path):
    with open(path, "w") as f:
        json.dump(events, f, indent=2, default=str)
    print(f"\n[+] JSON exported: {path}")


def export_csv(events, path):
    keys = set()
    for e in events:
        keys.update(e["data"].keys())
    keys = sorted(keys)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["time", "eid", "risk", "description", "channel", "computer", "file"] + keys)
        for e in events:
            desc, risk = EVENT_DB.get(e["eid"], ("Unknown", "unknown"))
            row = [e["time"], e["eid"], risk, desc, e["channel"], e["computer"], e["file"]]
            row += [e["data"].get(k, "") for k in keys]
            w.writerow(row)
    print(f"[+] CSV exported: {path}")


# MAIN

def main():
    if len(sys.argv) < 2:
        print("EVTX Threat Hunter")
        print("Usage: python evtx_hunter.py <file_or_directory> [options]")
        print("")
        print("Options:")
        print("  --csv <file>      Export all events to CSV")
        print("  --json <file>     Export all events to JSON")
        print("  --search <term>   Filter events containing keyword")

        sys.exit(0)

    target = sys.argv[1]
    out_csv = out_json = search_term = None


    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--csv" and i + 1 < len(args):
            out_csv = args[i + 1]; i += 2
        elif args[i] == "--json" and i + 1 < len(args):
            out_json = args[i + 1]; i += 2
        elif args[i] == "--search" and i + 1 < len(args):
            search_term = args[i + 1].lower(); i += 2

        else:
            i += 1


    files = find_files(target)
    if not files:
        print(f"[!] No .evtx files found at: {target}")
        sys.exit(1)

    print(f"[*] Found {len(files)} file(s)")
    all_events = []
    for f in files:
        evts = parse_evtx(f)
        all_events.extend(evts)
        print(f"    {os.path.basename(f)} -> {len(evts)} events")

    if search_term:
        all_events = [e for e in all_events if search_term in json.dumps(e, default=str).lower()]
        print(f"[*] Search matched {len(all_events)} events")

    if not all_events:
        print("[!] No events to analyze.")
        sys.exit(0)

    # Run detections
    engine = DetectionEngine(all_events)
    findings = engine.run_all()

    # Print results
    print_findings(findings)
    print_summary(all_events)

    # Export
    if out_json:
        export_json(all_events, out_json)
    if out_csv:
        export_csv(all_events, out_csv)

    print("\n[Done]")


if __name__ == "__main__":
    main()
