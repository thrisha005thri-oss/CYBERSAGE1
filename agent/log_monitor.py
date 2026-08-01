import win32evtlog
import pandas as pd
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

# ═══════════════════════════════════════════════════════
# CyberSage 2.0 — Live Log Monitor v4
# FIXED: Removed 4656 and 5156 from suspicious IDs
# These cause false positive credential dumping alerts
# Now reads BOTH Security AND System logs
# ═══════════════════════════════════════════════════════

SECURITY_CATALOG = {
    4624: "Successful Login",
    4625: "Failed Login Attempt",
    4634: "User Logged Off",
    4647: "User Initiated Logoff",
    4648: "Login With Explicit Credentials",
    4672: "Special Privileges Assigned",
    4697: "Service Installed In System",
    4698: "Scheduled Task Created",
    4699: "Scheduled Task Deleted",
    4700: "Scheduled Task Enabled",
    4701: "Scheduled Task Disabled",
    4702: "Scheduled Task Updated",
    4719: "System Audit Policy Changed",
    4720: "New User Account Created",
    4722: "User Account Enabled",
    4723: "Password Change Attempt",
    4724: "Password Reset Attempt",
    4725: "User Account Disabled",
    4726: "User Account Deleted",
    4728: "User Added To Security Group",
    4732: "User Added To Local Administrators",
    4738: "User Account Changed",
    4740: "User Account Locked Out",
    4756: "User Added To Universal Group",
    4688: "New Process Created",
    4689: "Process Exited",
    4656: "Object Handle Requested",
    4657: "Registry Value Modified",
    4663: "Object Access Attempt",
    4776: "Credential Validation Attempt",
    5140: "Network Share Accessed",
    5156: "Network Connection Allowed",
    5157: "Network Connection Blocked",
    1102: "Security Audit Log Cleared",
    4616: "System Time Changed",
    4798: "User Local Group Membership Enumerated",
    4799: "Security Group Membership Enumerated",
    5379: "Credential Manager Read",
    5380: "Credential Manager Find",
    5381: "Credential Manager Enumerate",
    5382: "Credential Manager Read Vault",
}

SYSTEM_CATALOG = {
    7045: "New Service Installed",
    7034: "Service Crashed Unexpectedly",
    7036: "Service State Changed",
    7040: "Service Start Type Changed",
}

# ── FIXED: Removed 4656 and 5156 to stop false positives ──
SUSPICIOUS_SECURITY = {
    4625, 4648, 4657, 4663, 4672,
    4688, 4697, 4698, 4700, 4702,
    4719, 4720, 4728, 4732, 4740,
    4776, 1102,
}

SUSPICIOUS_SYSTEM = {7045, 4697}


def extract_security_details(event):
    d = {"source_ip": None, "target_account": None,
         "logon_type": None, "process_name": None}
    try:
        s   = event.StringInserts
        eid = event.EventID & 0xFFFF
        if not s:
            return d
        if eid == 4625:
            if len(s) > 5  and s[5]  and s[5]  != "-":
                d["target_account"] = s[5]
            if len(s) > 19 and s[19] and s[19] not in ["-","::1","127.0.0.1",""]:
                d["source_ip"] = s[19]
        elif eid == 4624:
            if len(s) > 5  and s[5]  and s[5]  != "-":
                d["target_account"] = s[5]
            if len(s) > 18 and s[18] and s[18] not in ["-","::1","127.0.0.1",""]:
                d["source_ip"] = s[18]
            if len(s) > 8  and s[8]:
                d["logon_type"] = s[8]
        elif eid == 4648:
            if len(s) > 5  and s[5]:
                d["target_account"] = s[5]
            if len(s) > 8  and s[8] not in ["-","::1",""]:
                d["source_ip"] = s[8]
        elif eid == 4688:
            if len(s) > 1  and s[1]:
                d["target_account"] = s[1]
            if len(s) > 5  and s[5]:
                d["process_name"] = s[5]
        elif eid in {4720, 4726, 4728, 4732, 4740}:
            if len(s) > 0  and s[0]:
                d["target_account"] = s[0]
        elif eid in {4698, 4702, 4700}:
            if len(s) > 0  and s[0]:
                d["target_account"] = s[0]
    except Exception:
        pass
    return d


def extract_system_details(event):
    d = {"source_ip": None, "target_account": None,
         "logon_type": None, "process_name": None}
    try:
        s   = event.StringInserts
        eid = event.EventID & 0xFFFF
        if not s:
            return d
        if eid == 7045:
            if len(s) > 0 and s[0]:
                d["target_account"] = s[0]
            if len(s) > 1 and s[1]:
                d["process_name"] = s[1]
    except Exception:
        pass
    return d


def read_log(log_type, catalog, suspicious_ids, max_events, extractor):
    rows = []
    try:
        hand  = win32evtlog.OpenEventLog(None, log_type)
        flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                 win32evtlog.EVENTLOG_SEQUENTIAL_READ)
        count = 0
        while count < max_events:
            batch = win32evtlog.ReadEventLog(hand, flags, 0)
            if not batch:
                break
            for ev in batch:
                if count >= max_events:
                    break
                eid = ev.EventID & 0xFFFF
                det = extractor(ev)
                rows.append({
                    "event_id"      : eid,
                    "time"          : ev.TimeGenerated.Format(),
                    "source"        : ev.SourceName,
                    "event_label"   : catalog.get(eid, f"Event {eid}"),
                    "suspicious"    : eid in suspicious_ids,
                    "source_ip"     : det["source_ip"],
                    "target_account": det["target_account"],
                    "logon_type"    : det["logon_type"],
                    "process_name"  : det["process_name"],
                })
                count += 1
        win32evtlog.CloseEventLog(hand)
    except Exception as e:
        print(f"{Fore.YELLOW}  ⚠️  {log_type} log: {e}{Style.RESET_ALL}")
    return rows


def read_windows_logs(log_type="Security", max_events=1000):
    print(f"\n{Fore.CYAN}{'─'*56}")
    print(f"  🛡️  CyberSage 2.0 — Live Log Monitor")
    print(f"{'─'*56}{Style.RESET_ALL}")

    all_rows = []

    # Security log (800 events)
    sec_events = int(max_events * 0.8)
    print(f"  📂 Security log : reading last {sec_events}")
    sec_rows = read_log("Security", SECURITY_CATALOG,
                        SUSPICIOUS_SECURITY, sec_events,
                        extract_security_details)
    all_rows.extend(sec_rows)

    # System log (200 events) — for Event 7045
    sys_events = int(max_events * 0.2)
    print(f"  📂 System log   : reading last {sys_events}")
    sys_rows = read_log("System", SYSTEM_CATALOG,
                        SUSPICIOUS_SYSTEM, sys_events,
                        extract_system_details)
    all_rows.extend(sys_rows)

    if not all_rows:
        print(f"{Fore.RED}  ❌ No logs — run as Administrator!{Style.RESET_ALL}")
        return None

    df = pd.DataFrame(all_rows)
    if not df.empty:
        sc  = int(df["suspicious"].sum())
        tot = len(df)
        print(f"\n  Total read  : {tot:,}")
        print(f"  {Fore.RED}Suspicious  : {sc}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Normal      : {tot-sc}{Style.RESET_ALL}")
        susp_df = df[df["suspicious"] == True]
        if not susp_df.empty:
            counts = susp_df["event_id"].value_counts().to_dict()
            print(f"  Breakdown   : {counts}")
    return df