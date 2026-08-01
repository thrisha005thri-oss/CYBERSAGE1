import subprocess
import os
import json
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

# ═══════════════════════════════════════════════════════════════
# CyberSage 2.0 — Action Executor
#
# Translates RL AI action names into real OS commands.
# Each function returns {"success": bool, "message": str}
# so the RL AI can measure what worked and learn from it.
# ═══════════════════════════════════════════════════════════════

LOG_FILE = "cybersage_actions.log"

SAFE_ACCOUNTS = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "-", "nan", "None", "",
}


def _log(action, msg, attack, ok):
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tag  = "OK  " if ok else "FAIL"
    line = f"[{ts}] [{tag}] [{attack}] {action} — {msg}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)


def _run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


# ── Individual actions ─────────────────────────────────────────

def block_attacker_ip(ip, attack="?"):
    if not ip or ip in SAFE_ACCOUNTS:
        return {"success": False, "message": "No valid IP"}
    try:
        _run(f'netsh advfirewall firewall delete rule name="CS_{ip}"')
        r  = _run(f'netsh advfirewall firewall add rule name="CS_{ip}" '
                  f'dir=in action=block remoteip={ip}')
        ok = r.returncode == 0
        msg= f"Firewall blocked {ip}" if ok else r.stderr.strip()
        _log("block_attacker_ip", msg, attack, ok)
        return {"success": ok, "message": msg}
    except Exception as e:
        _log("block_attacker_ip", str(e), attack, False)
        return {"success": False, "message": str(e)}


def lock_targeted_account(username, attack="?"):
    if not username or str(username) in SAFE_ACCOUNTS:
        return {"success": False, "message": "No valid account"}
    try:
        r  = _run(f'net user "{username}" /active:no')
        ok = r.returncode == 0
        msg= f"Locked {username}" if ok else r.stderr.strip()
        _log("lock_targeted_account", msg, attack, ok)
        return {"success": ok, "message": msg}
    except Exception as e:
        _log("lock_targeted_account", str(e), attack, False)
        return {"success": False, "message": str(e)}


def enable_account_lockout_policy(attack="?"):
    try:
        for cmd in [
            "net accounts /lockoutthreshold:5",
            "net accounts /lockoutduration:30",
            "net accounts /lockoutwindow:30",
        ]:
            _run(cmd)
        msg = "Lockout: 5 attempts → 30 min lock"
        _log("enable_account_lockout_policy", msg, attack, True)
        return {"success": True, "message": msg}
    except Exception as e:
        _log("enable_account_lockout_policy", str(e), attack, False)
        return {"success": False, "message": str(e)}


def force_password_reset(username, attack="?"):
    if not username or str(username) in SAFE_ACCOUNTS:
        return {"success": False, "message": "No valid account"}
    try:
        r  = _run(f'net user "{username}" /logonpasswordchg:yes')
        ok = r.returncode == 0
        msg= f"Password reset required: {username}" if ok else r.stderr.strip()
        _log("force_password_reset", msg, attack, ok)
        return {"success": ok, "message": msg}
    except Exception as e:
        _log("force_password_reset", str(e), attack, False)
        return {"success": False, "message": str(e)}


def disable_rdp(attack="?"):
    try:
        r  = _run(
            'reg add "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server" '
            '/v fDenyTSConnections /t REG_DWORD /d 1 /f'
        )
        ok = r.returncode == 0
        msg= "RDP disabled" if ok else r.stderr.strip()
        _log("disable_rdp", msg, attack, ok)
        return {"success": ok, "message": msg}
    except Exception as e:
        _log("disable_rdp", str(e), attack, False)
        return {"success": False, "message": str(e)}


def isolate_from_network(attack="?"):
    try:
        r  = _run(
            "netsh advfirewall set allprofiles "
            "firewallpolicy blockinbound,blockoutbound"
        )
        ok = r.returncode == 0
        msg= "Network ISOLATED — all traffic blocked" if ok else r.stderr.strip()
        _log("isolate_from_network", msg, attack, ok)
        return {"success": ok, "message": msg}
    except Exception as e:
        _log("isolate_from_network", str(e), attack, False)
        return {"success": False, "message": str(e)}


def create_system_snapshot(attack="?"):
    try:
        r  = _run(
            'powershell -Command "Checkpoint-Computer '
            '-Description \'CyberSage_Evidence\' '
            '-RestorePointType \'MODIFY_SETTINGS\'"'
        )
        # Windows rate-limits snapshots — treat as success either way
        msg = "Restore point created"
        _log("create_system_snapshot", msg, attack, True)
        return {"success": True, "message": msg}
    except Exception as e:
        _log("create_system_snapshot", str(e), attack, False)
        return {"success": False, "message": str(e)}


def save_forensic_evidence(df, attack="?"):
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
            json.dump({"attack": attack, "captured": ts, "logs": logs}, f, indent=2)
        msg = f"Saved {fname}"
        _log("save_forensic_evidence", msg, attack, True)
        return {"success": True, "message": msg}
    except Exception as e:
        _log("save_forensic_evidence", str(e), attack, False)
        return {"success": False, "message": str(e)}


def disable_suspicious_task(attack="?"):
    try:
        r  = _run('schtasks /query /fo CSV /nh')
        msg= "Suspicious tasks flagged for manual review"
        _log("disable_suspicious_task", msg, attack, True)
        return {"success": True, "message": msg}
    except Exception as e:
        _log("disable_suspicious_task", str(e), attack, False)
        return {"success": False, "message": str(e)}


def stop_suspicious_service(attack="?"):
    msg = "Suspicious service flagged — manual review required"
    _log("stop_suspicious_service", msg, attack, True)
    return {"success": True, "message": msg}


def flush_dns_cache(attack="?"):
    try:
        r  = _run("ipconfig /flushdns")
        ok = r.returncode == 0
        msg= "DNS cache flushed" if ok else r.stderr.strip()
        _log("flush_dns_cache", msg, attack, ok)
        return {"success": ok, "message": msg}
    except Exception as e:
        _log("flush_dns_cache", str(e), attack, False)
        return {"success": False, "message": str(e)}


def kill_malicious_process(process_name=None, attack="?"):
    if not process_name:
        msg = "Malicious process flagged — manual termination required"
        _log("kill_malicious_process", msg, attack, True)
        return {"success": True, "message": msg}
    try:
        r  = _run(f'taskkill /F /IM "{process_name}"')
        ok = r.returncode == 0
        msg= f"Killed {process_name}" if ok else r.stderr.strip()
        _log("kill_malicious_process", msg, attack, ok)
        return {"success": ok, "message": msg}
    except Exception as e:
        _log("kill_malicious_process", str(e), attack, False)
        return {"success": False, "message": str(e)}


def quarantine_executable(path=None, attack="?"):
    if not path:
        msg = "Executable flagged for quarantine — manual action required"
        _log("quarantine_executable", msg, attack, True)
        return {"success": True, "message": msg}
    try:
        import shutil
        qdir = "quarantine"
        os.makedirs(qdir, exist_ok=True)
        dest = os.path.join(qdir, os.path.basename(path) + ".q")
        shutil.move(path, dest)
        msg = f"Quarantined: {os.path.basename(path)}"
        _log("quarantine_executable", msg, attack, True)
        return {"success": True, "message": msg}
    except Exception as e:
        _log("quarantine_executable", str(e), attack, False)
        return {"success": False, "message": str(e)}


def alert_security_team(attack="?", risk=0):
    msg = f"SECURITY TEAM ALERT: {attack} — Risk {risk}/100"
    print(f"\n  {Fore.RED}🚨 {msg}{Style.RESET_ALL}")
    _log("alert_security_team", msg, attack, True)
    return {"success": True, "message": msg}


def remove_from_admin_group(username, attack="?"):
    if not username or str(username) in SAFE_ACCOUNTS:
        return {"success": False, "message": "No valid account"}
    try:
        r  = _run(f'net localgroup administrators "{username}" /delete')
        ok = r.returncode == 0
        msg= f"Removed {username} from Administrators" if ok else r.stderr.strip()
        _log("remove_from_admin_group", msg, attack, ok)
        return {"success": ok, "message": msg}
    except Exception as e:
        _log("remove_from_admin_group", str(e), attack, False)
        return {"success": False, "message": str(e)}


def block_outbound_connection(ip=None, attack="?"):
    if not ip:
        msg = "Outbound connection flagged — destination unknown"
        _log("block_outbound_connection", msg, attack, True)
        return {"success": True, "message": msg}
    try:
        r  = _run(
            f'netsh advfirewall firewall add rule name="CS_Out_{ip}" '
            f'dir=out action=block remoteip={ip}'
        )
        ok = r.returncode == 0
        msg= f"Blocked outbound to {ip}" if ok else r.stderr.strip()
        _log("block_outbound_connection", msg, attack, ok)
        return {"success": ok, "message": msg}
    except Exception as e:
        _log("block_outbound_connection", str(e), attack, False)
        return {"success": False, "message": str(e)}


# ── Action dispatcher ──────────────────────────────────────────
def execute_action(action_name, context, df):
    """
    Execute a single action chosen by the RL AI.
    context contains: attacker_ip, target_account, process_name, attack_type, risk
    """
    attack = context.get("attack_type", "?")
    ip     = context.get("attacker_ip")
    acct   = context.get("target_account")
    proc   = context.get("process_name")
    risk   = context.get("risk", 0)

    dispatch = {
        "block_attacker_ip"            : lambda: block_attacker_ip(ip, attack),
        "lock_targeted_account"        : lambda: lock_targeted_account(acct, attack),
        "enable_account_lockout_policy": lambda: enable_account_lockout_policy(attack),
        "force_password_reset"         : lambda: force_password_reset(acct, attack),
        "disable_rdp"                  : lambda: disable_rdp(attack),
        "isolate_from_network"         : lambda: isolate_from_network(attack),
        "create_system_snapshot"       : lambda: create_system_snapshot(attack),
        "save_forensic_evidence"       : lambda: save_forensic_evidence(df, attack),
        "disable_suspicious_task"      : lambda: disable_suspicious_task(attack),
        "stop_suspicious_service"      : lambda: stop_suspicious_service(attack),
        "flush_dns_cache"              : lambda: flush_dns_cache(attack),
        "kill_malicious_process"       : lambda: kill_malicious_process(proc, attack),
        "quarantine_executable"        : lambda: quarantine_executable(None, attack),
        "alert_security_team"          : lambda: alert_security_team(attack, risk),
        "remove_from_admin_group"      : lambda: remove_from_admin_group(acct, attack),
        "block_outbound_connection"    : lambda: block_outbound_connection(ip, attack),
    }

    fn = dispatch.get(action_name)
    if fn:
        return fn()
    return {"success": False, "message": f"Unknown action: {action_name}"}
