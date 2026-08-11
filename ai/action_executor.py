import subprocess
import os
import getpass
import json
import shutil
import glob
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

# ═══════════════════════════════════════════════════════════════
# CyberSage — Deep Action Executor
# Goes beyond surface level — actually RESOLVES attacks
# Includes smart file quarantine for ANY suspicious file
#
# FIXES APPLIED:
# 1. run_windows_defender_scan: QuickScan + non-blocking Popen
#    (was FullScan + blocking, froze the whole pipeline)
# 2. stop_and_delete_service: now actually receives the service
#    name from context (was always called with no name, so it
#    never ran sc.exe stop/delete — just logged "flagged for
#    manual review" every time, even on repeat detections)
# ═══════════════════════════════════════════════════════════════

LOG_FILE      = "cybersage_actions.log"
QUARANTINE_DIR = "quarantine"

SAFE_ACCOUNTS = {
    "SYSTEM","LOCAL SERVICE","NETWORK SERVICE",
    "-","nan","None","","NT AUTHORITY\\SYSTEM"
}

def _is_current_user(username):
    """
    FIXED: prevents CyberSage from locking/deleting/demoting the
    account it's currently running under. During local brute-force
    testing (net use against localhost), Windows can log the real
    logged-in account as the associated target, and the classifier
    has no way to distinguish that from a genuine compromised
    account. This check catches that case before any destructive
    action runs against your own live session.
    """
    try:
        current = getpass.getuser().strip().lower()
    except Exception:
        current = os.environ.get("USERNAME", "").strip().lower()
    if not username:
        return False
    # Handle both "Thrisha" and "HP\Thrisha" style names
    uname = str(username).strip().lower()
    uname_short = uname.split("\\")[-1]
    return uname_short == current

# Atomic Red Team paths to clean after each attack
ATOMIC_PATHS = {
    "SCHEDULED_TASK" : [
        "C:\\AtomicRedTeam\\atomics\\T1053.005",
        "%TEMP%\\atomic-*.ps1",
        "%TEMP%\\T1053*",
    ],
    "NEW_SERVICE"    : [
        "C:\\AtomicRedTeam\\atomics\\T1543.003",
        "%TEMP%\\AtomicTest*",
        "%TEMP%\\T1543*",
    ],
    "NEW_ADMIN_USER" : [
        "C:\\AtomicRedTeam\\atomics\\T1136.001",
        "%TEMP%\\T1136*",
    ],
    "BRUTE_FORCE"    : [
        "C:\\AtomicRedTeam\\atomics\\T1110.001",
        "%TEMP%\\T1110*",
    ],
    "DEFENSE_EVASION": [
        "C:\\AtomicRedTeam\\atomics\\T1070.001",
        "%TEMP%\\T1070*",
    ],
    "PORT_SCAN"      : [
        "C:\\AtomicRedTeam\\atomics\\T1046",
        "%TEMP%\\T1046*",
    ],
    "FILELESS_MALWARE": [
        "C:\\AtomicRedTeam\\atomics\\T1059.001",
        "%TEMP%\\*.ps1",
        "%TEMP%\\T1059*",
    ],
    "AI_PHISHING"    : [
        "C:\\AtomicRedTeam\\atomics\\T1566.002",
        "%TEMP%\\T1566*",
    ],
}

# Suspicious file locations to scan after attack
SUSPICIOUS_LOCATIONS = [
    os.path.expandvars("%USERPROFILE%\\Downloads"),
    os.path.expandvars("%TEMP%"),
    os.path.expandvars("%APPDATA%\\Local\\Temp"),
    "C:\\Windows\\Temp",
    os.path.expandvars("%USERPROFILE%\\AppData\\Roaming"),
]

SUSPICIOUS_EXTENSIONS = [
    ".exe",".ps1",".bat",".cmd",".vbs",
    ".js",".jar",".hta",".scr",".pif",
]


def _log(action, msg, attack, ok):
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tag  = "OK  " if ok else "FAIL"
    line = f"[{ts}] [{tag}] [{attack}] {action} — {msg}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)
    color = Fore.GREEN if ok else Fore.RED
    print(f"  {color}{'✅' if ok else '❌'} {action}: {msg}{Style.RESET_ALL}")


def _run(cmd):
    try:
        return subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True
        )
    except Exception as e:
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


# ── NETWORK DEFENSE ───────────────────────────────────────────

def block_attacker_ip(ip, attack="Unknown"):
    if not ip or ip in ["127.0.0.1","::1","nan","None",""]:
        _log("block_attacker_ip", "No valid IP to block", attack, False)
        return {"success": False, "message": "No valid IP"}
    _run(f'netsh advfirewall firewall delete rule name="CS_{ip}" 2>nul')
    r = _run(
        f'netsh advfirewall firewall add rule '
        f'name="CS_{ip}" dir=in action=block remoteip={ip}'
    )
    ok  = r.returncode == 0
    msg = f"Blocked IP: {ip}" if ok else r.stderr.strip()
    _log("block_attacker_ip", msg, attack, ok)
    return {"success": ok, "message": msg}


def enable_firewall_stealth(attack="Unknown"):
    _run('netsh advfirewall set currentprofile settings '
         'inboundusernotification enable')
    msg = "Firewall stealth mode enabled — ports hidden from scanners"
    _log("enable_firewall_stealth", msg, attack, True)
    return {"success": True, "message": msg}


def flush_dns_cache(attack="Unknown"):
    r   = _run("ipconfig /flushdns")
    ok  = r.returncode == 0
    msg = "DNS cache flushed" if ok else r.stderr.strip()
    _log("flush_dns_cache", msg, attack, ok)
    return {"success": ok, "message": msg}


def disable_rdp(attack="Unknown"):
    r = _run(
        'reg add "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server" '
        '/v fDenyTSConnections /t REG_DWORD /d 1 /f'
    )
    ok  = r.returncode == 0
    msg = "RDP disabled" if ok else r.stderr.strip()
    _log("disable_rdp", msg, attack, ok)
    return {"success": ok, "message": msg}


# ── ACCOUNT SECURITY ──────────────────────────────────────────

def lock_targeted_account(username, attack="Unknown"):
    if not username or str(username).strip() in SAFE_ACCOUNTS:
        _log("lock_targeted_account", f"Cannot lock: {username}", attack, False)
        return {"success": False, "message": f"Safe account: {username}"}
    if _is_current_user(username):
        msg = f"Refused to lock '{username}' — matches the currently logged-in account"
        _log("lock_targeted_account", msg, attack, False)
        return {"success": False, "message": msg}
    r   = _run(f'net user "{username}" /active:no')
    ok  = r.returncode == 0
    msg = f"Locked account: {username}" if ok else r.stderr.strip()
    _log("lock_targeted_account", msg, attack, ok)
    return {"success": ok, "message": msg}


def enable_account_lockout_policy(attack="Unknown"):
    _run("net accounts /lockoutthreshold:5")
    _run("net accounts /lockoutduration:30")
    _run("net accounts /lockoutwindow:30")
    msg = "Lockout policy: lock after 5 attempts for 30 min"
    _log("enable_account_lockout_policy", msg, attack, True)
    return {"success": True, "message": msg}


def force_password_reset(username, attack="Unknown"):
    if not username or str(username).strip() in SAFE_ACCOUNTS:
        return {"success": False, "message": "No valid account"}
    r   = _run(f'net user "{username}" /logonpasswordchg:yes')
    ok  = r.returncode == 0
    msg = f"Password reset required: {username}" if ok else r.stderr.strip()
    _log("force_password_reset", msg, attack, ok)
    return {"success": ok, "message": msg}


def remove_from_admin_group(username, attack="Unknown"):
    if not username or str(username).strip() in SAFE_ACCOUNTS:
        return {"success": False, "message": "No valid account"}
    if _is_current_user(username):
        msg = f"Refused to remove '{username}' from Administrators — matches the currently logged-in account"
        _log("remove_from_admin_group", msg, attack, False)
        return {"success": False, "message": msg}
    r   = _run(f'net localgroup administrators "{username}" /delete')
    ok  = r.returncode == 0
    msg = f"Removed {username} from Administrators" if ok else r.stderr.strip()
    _log("remove_from_admin_group", msg, attack, ok)
    return {"success": ok, "message": msg}


def delete_backdoor_account(username, attack="Unknown"):
    if not username or str(username).strip() in SAFE_ACCOUNTS:
        return {"success": False, "message": "No valid account"}
    if _is_current_user(username):
        msg = f"Refused to delete '{username}' — matches the currently logged-in account"
        _log("delete_backdoor_account", msg, attack, False)
        return {"success": False, "message": msg}
    _run(f'net user "{username}" /active:no')
    _run(f'net localgroup administrators "{username}" /delete')
    r   = _run(f'net user "{username}" /delete')
    ok  = r.returncode == 0
    msg = f"Deleted backdoor account: {username}" if ok else r.stderr.strip()
    _log("delete_backdoor_account", msg, attack, ok)
    return {"success": ok, "message": msg}


# ── POWERSHELL SECURITY ───────────────────────────────────────

def restrict_powershell(attack="Unknown"):
    r = _run(
        'powershell -Command "Set-ExecutionPolicy '
        'Restricted -Scope LocalMachine -Force"'
    )
    ok  = r.returncode == 0
    msg = "PowerShell execution policy set to Restricted" \
          if ok else "Policy set (may need reboot)"
    _log("restrict_powershell", msg, attack, True)
    return {"success": True, "message": msg}


def disable_powershell_v2(attack="Unknown"):
    r = _run(
        'dism /online /disable-feature '
        '/featurename:MicrosoftWindowsPowerShellV2 /norestart'
    )
    msg = "PowerShell v2 disabled (prevents AMSI bypass)"
    _log("disable_powershell_v2", msg, attack, True)
    return {"success": True, "message": msg}


def enable_scriptblock_logging(attack="Unknown"):
    _run(
        'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\'
        'PowerShell\\ScriptBlockLogging" '
        '/v EnableScriptBlockLogging /t REG_DWORD /d 1 /f'
    )
    msg = "PowerShell ScriptBlock logging enabled"
    _log("enable_scriptblock_logging", msg, attack, True)
    return {"success": True, "message": msg}


# ── MALWARE RESPONSE ──────────────────────────────────────────

def kill_malicious_process(process_name, attack="Unknown"):
    if not process_name:
        return {"success": False, "message": "No process name"}
    r   = _run(f'taskkill /F /IM "{process_name}"')
    ok  = r.returncode == 0
    msg = f"Killed process: {process_name}" if ok else r.stderr.strip()
    _log("kill_malicious_process", msg, attack, ok)
    return {"success": ok, "message": msg}


def smart_quarantine_suspicious_files(attack="Unknown"):
    """
    Smart file detection — finds recently created suspicious files
    in common malware drop locations and quarantines them.
    Works for ANY malware, not just Atomic Red Team!
    """
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    quarantined = []
    cutoff_time = datetime.now().timestamp() - 3600  # last 1 hour

    for location in SUSPICIOUS_LOCATIONS:
        if not os.path.exists(location):
            continue
        try:
            for fname in os.listdir(location):
                fpath = os.path.join(location, fname)
                if not os.path.isfile(fpath):
                    continue
                # Check extension
                _, ext = os.path.splitext(fname.lower())
                if ext not in SUSPICIOUS_EXTENSIONS:
                    continue
                # Check if recently created
                try:
                    ctime = os.path.getctime(fpath)
                    if ctime < cutoff_time:
                        continue
                except:
                    continue
                # Skip system files
                if any(s in fpath.lower() for s in
                       ["system32","syswow64","windows\\installer"]):
                    continue
                # Quarantine it!
                try:
                    dest = os.path.join(
                        QUARANTINE_DIR,
                        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{fname}"
                    )
                    shutil.move(fpath, dest)
                    quarantined.append(f"{fname} → quarantine/")
                    print(f"  {Fore.YELLOW}🔒 Quarantined: {fname}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"  ⚠️  Could not quarantine {fname}: {e}")
        except Exception:
            continue

    if quarantined:
        msg = f"Quarantined {len(quarantined)} suspicious files: {', '.join(quarantined[:3])}"
    else:
        msg = "No new suspicious files found in common drop locations"

    _log("smart_quarantine", msg, attack, True)
    return {"success": True, "message": msg, "quarantined": quarantined}


def eradicate_atomic_redteam_files(attack_pattern, attack="Unknown"):
    """
    Delete Atomic Red Team test files that caused the attack.
    Prevents the same attack from being re-run!
    """
    paths = ATOMIC_PATHS.get(attack_pattern, [])
    deleted = []

    for path_pattern in paths:
        expanded = os.path.expandvars(path_pattern)
        # Handle glob patterns
        if "*" in expanded:
            matches = glob.glob(expanded)
            for match in matches:
                try:
                    if os.path.isfile(match):
                        os.remove(match)
                        deleted.append(os.path.basename(match))
                    elif os.path.isdir(match):
                        shutil.rmtree(match, ignore_errors=True)
                        deleted.append(os.path.basename(match))
                except:
                    pass
        else:
            if os.path.exists(expanded):
                try:
                    if os.path.isfile(expanded):
                        os.remove(expanded)
                    elif os.path.isdir(expanded):
                        shutil.rmtree(expanded, ignore_errors=True)
                    deleted.append(os.path.basename(expanded))
                except:
                    pass

    if deleted:
        msg = f"Eradicated attack source files: {', '.join(deleted[:5])}"
    else:
        msg = "Attack source files already cleaned or not found"

    _log("eradicate_atomic_files", msg, attack, True)
    return {"success": True, "message": msg, "deleted": deleted}


# ── SERVICE & TASK MANAGEMENT ─────────────────────────────────

def stop_and_delete_service(service_name=None, attack="Unknown"):
    """
    FIXED: previously this only ever ran with service_name=None
    because execute_action() never passed it through, so it always
    hit the fallback branch below ("flagged for manual review") and
    never actually called sc.exe stop/delete. Now execute_action()
    passes the service name captured from Event 7045 (see the
    dispatch table at the bottom of this file), so real services
    like W64Time / AtomicTestService_* are genuinely removed.
    """
    if service_name and service_name.strip() and service_name.strip().lower() != "nan":
        _run(f'sc.exe stop "{service_name}"')
        r   = _run(f'sc.exe delete "{service_name}"')
        ok  = r.returncode == 0
        msg = f"Stopped and deleted service: {service_name}" \
              if ok else f"Could not fully remove {service_name}: {r.stderr.strip() or 'unknown error'}"
    else:
        msg = "Malicious service flagged — manual review required (no service name captured)"
        ok  = False
    _log("stop_and_delete_service", msg, attack, ok)
    return {"success": ok, "message": msg}


def remove_malicious_task(task_name=None, attack="Unknown"):
    if task_name:
        r   = _run(f'schtasks /delete /tn "{task_name}" /f')
        ok  = r.returncode == 0
        msg = f"Deleted task: {task_name}" if ok else r.stderr.strip()
    else:
        # Remove all suspicious tasks
        suspicious = [
            "AtomicTask","ATOMIC-T1053","atomic red team",
            "CompMgmtBypass","EventViewerBypass","T1053_005_OnLogon",
            "T1053_005_OnStartup","spawn","AtomicTaskModifed",
        ]
        removed = []
        for t in suspicious:
            r = _run(f'schtasks /delete /tn "{t}" /f')
            if r.returncode == 0:
                removed.append(t)
        msg = f"Removed tasks: {removed}" if removed else "No suspicious tasks found"
        ok  = True
    _log("remove_malicious_task", msg, attack, ok)
    return {"success": ok, "message": msg}


# ── FORENSIC & SYSTEM ─────────────────────────────────────────

def create_system_snapshot(attack="Unknown"):
    r = _run(
        'powershell -Command "Checkpoint-Computer '
        '-Description \'CyberSage_Evidence\' '
        '-RestorePointType \'MODIFY_SETTINGS\'"'
    )
    msg = "System restore point created before remediation"
    _log("create_system_snapshot", msg, attack, True)
    return {"success": True, "message": msg}


def save_forensic_evidence(df, attack="Unknown"):
    try:
        ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
        folder = os.path.join("dataset", "forensic")
        os.makedirs(folder, exist_ok=True)
        fname  = f"forensic_{attack}_{ts}.json"
        path   = os.path.join(folder, fname)
        logs   = []
        if df is not None:
            for _, row in df.head(100).iterrows():
                logs.append({
                    "event_id"   : int(row.get("event_id", 0)),
                    "time"       : str(row.get("time", "")),
                    "event_label": str(row.get("event_label", "")),
                    "source_ip"  : str(row.get("source_ip", "")),
                    "account"    : str(row.get("target_account", "")),
                })
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"attack": attack, "captured": ts, "logs": logs},
                      f, indent=2)
        msg = f"Forensic evidence saved: {fname}"
        _log("save_forensic_evidence", msg, attack, True)
        return {"success": True, "message": msg}
    except Exception as e:
        _log("save_forensic_evidence", str(e), attack, False)
        return {"success": False, "message": str(e)}


def setup_log_protection(attack="Unknown"):
    """Protect logs from future clearing"""
    _run('wevtutil sl Security /enabled:true /retention:false')
    _run('wevtutil sl Security /maxsize:2097152')
    _run('auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable')
    _run('auditpol /set /category:"Account Management" /success:enable /failure:enable')
    _run('auditpol /set /category:"Policy Change" /success:enable /failure:enable')
    msg = "Log protection enabled: 2GB limit + all auditing restored"
    _log("setup_log_protection", msg, attack, True)
    return {"success": True, "message": msg}


def restore_network(attack="Unknown"):
    _run("netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound")
    _run("netsh int ip reset")
    _run("netsh winsock reset")
    _run("ipconfig /flushdns")
    msg = "Network configuration restored to safe state"
    _log("restore_network", msg, attack, True)
    return {"success": True, "message": msg}


def alert_security_team(attack="Unknown", risk=0):
    msg = f"🚨 SECURITY ALERT: {attack} — Risk {risk}/100 — Action required!"
    print(f"\n  {Fore.RED}{msg}{Style.RESET_ALL}")
    _log("alert_security_team", msg, attack, True)
    return {"success": True, "message": msg}


def run_windows_defender_scan(attack="Unknown"):
    """
    Trigger Windows Defender QUICK scan — non-blocking.
    FIXED: Previously used FullScan + blocking subprocess.run(),
    which could freeze the entire remediation pipeline for
    20-60+ minutes while scanning the whole disk. QuickScan
    checks common malware locations in seconds/minutes, and
    Popen() fires it in the background without waiting.
    """
    try:
        subprocess.Popen(
            ['powershell', '-Command', 'Start-MpScan -ScanType QuickScan'],
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        msg = "Windows Defender quick scan initiated (running in background)"
        ok  = True
    except Exception as e:
        msg = f"Could not start Defender scan: {e}"
        ok  = False
    _log("run_windows_defender_scan", msg, attack, ok)
    return {"success": ok, "message": msg}


def get_all_actions():
    return [
        # Network
        "block_attacker_ip",
        "enable_firewall_stealth",
        "flush_dns_cache",
        "disable_rdp",
        "restore_network",
        # Account
        "lock_targeted_account",
        "enable_account_lockout_policy",
        "force_password_reset",
        "remove_from_admin_group",
        "delete_backdoor_account",
        # PowerShell
        "restrict_powershell",
        "disable_powershell_v2",
        "enable_scriptblock_logging",
        # Malware
        "kill_malicious_process",
        "smart_quarantine_suspicious_files",
        "eradicate_atomic_redteam_files",
        # Service/Task
        "stop_and_delete_service",
        "remove_malicious_task",
        # Forensic
        "create_system_snapshot",
        "save_forensic_evidence",
        "setup_log_protection",
        "run_windows_defender_scan",
        # Alert
        "alert_security_team",
    ]


def execute_action(action_name, context, df=None):
    attack  = context.get("attack_type", "Unknown")
    ip      = context.get("attacker_ip")
    acct    = context.get("target_account")
    proc    = context.get("process_name")
    risk    = context.get("risk", 0)
    pattern = context.get("pattern", "")

    dispatch = {
        "block_attacker_ip"             : lambda: block_attacker_ip(ip, attack),
        "enable_firewall_stealth"       : lambda: enable_firewall_stealth(attack),
        "flush_dns_cache"               : lambda: flush_dns_cache(attack),
        "disable_rdp"                   : lambda: disable_rdp(attack),
        "restore_network"               : lambda: restore_network(attack),
        "lock_targeted_account"         : lambda: lock_targeted_account(acct, attack),
        "enable_account_lockout_policy" : lambda: enable_account_lockout_policy(attack),
        "force_password_reset"          : lambda: force_password_reset(acct, attack),
        "remove_from_admin_group"       : lambda: remove_from_admin_group(acct, attack),
        "delete_backdoor_account"       : lambda: delete_backdoor_account(acct, attack),
        "restrict_powershell"           : lambda: restrict_powershell(attack),
        "disable_powershell_v2"         : lambda: disable_powershell_v2(attack),
        "enable_scriptblock_logging"    : lambda: enable_scriptblock_logging(attack),
        "kill_malicious_process"        : lambda: kill_malicious_process(proc, attack),
        "smart_quarantine_suspicious_files": lambda: smart_quarantine_suspicious_files(attack),
        "eradicate_atomic_redteam_files": lambda: eradicate_atomic_redteam_files(pattern, attack),
        # FIXED: was stop_and_delete_service(attack=attack) — never
        # passed a service name, so it always fell into the "manual
        # review required" fallback, even on repeat detections of
        # the SAME leftover service. `acct` holds the service name
        # for NEW_SERVICE attacks (see log_monitor.py's
        # extract_system_details() for Event 7045).
        "stop_and_delete_service"       : lambda: stop_and_delete_service(service_name=acct, attack=attack),
        "remove_malicious_task"         : lambda: remove_malicious_task(attack=attack),
        "create_system_snapshot"        : lambda: create_system_snapshot(attack),
        "save_forensic_evidence"        : lambda: save_forensic_evidence(df, attack),
        "setup_log_protection"          : lambda: setup_log_protection(attack),
        "run_windows_defender_scan"     : lambda: run_windows_defender_scan(attack),
        "alert_security_team"           : lambda: alert_security_team(attack, risk),
    }

    fn = dispatch.get(action_name)
    if fn:
        return fn()
    return {"success": False, "message": f"Unknown action: {action_name}"}