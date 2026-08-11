from colorama import Fore, Style, init
init(autoreset=True)

try:
    from detector.mitre_engine import ATTACKS
except ImportError:
    from mitre_engine import ATTACKS

# ═══════════════════════════════════════════════════════════════
# CyberSage — Attack Classifier
# 8 Attacks — Clean Detection — No False Positives
#
# FIXED: PORT_SCAN threshold raised from 200 to 1500.
# On an actively-used machine, normal background traffic
# (browser tabs, OneDrive sync, telemetry, AV cloud lookups)
# can generate 1000+ Event 5156 entries in a 10-minute window
# with zero actual scanning activity. A real T1046 port scan
# test generates a much larger, concentrated burst, so 1500
# gives a safer margin against false positives while still
# catching genuine scans.
# ═══════════════════════════════════════════════════════════════

import os
from datetime import datetime, timedelta

SAFE_ACCOUNTS = {
    "SYSTEM","LOCAL SERVICE","NETWORK SERVICE",
    "DWM-1","DWM-2","DWM-3","UMFD-0","UMFD-1",
    "-","nan","None","","Anonymous Logon",
}

# FIXED: FILELESS_MALWARE used to fire on a single PowerShell
# process-creation event (>= 1), which is far too sensitive — one
# legitimate admin action, or even CyberSage's OWN remediation
# calling PowerShell (restrict_powershell, create_system_snapshot,
# etc.), would trip it. Genuine attacks and atomic tests generate a
# large, concentrated burst (hundreds of invocations), not one-offs.
# Raising this to a minimum burst size filters out normal single
# PowerShell launches while still catching real fileless activity.
FILELESS_MIN_COUNT = 8

# FIXED: adds an explicit "maintenance mode" suppression window.
# Certain legitimate actions (e.g. clearing Windows logs as part of
# routine cleanup) generate the EXACT SAME telemetry signature as a
# real attack (Event 1102). There is no way to distinguish "admin
# cleared the log on purpose" from "attacker cleared the log to hide
# tracks" using OS telemetry alone — this is a known, real limitation
# in security tooling generally, not something unique to CyberSage.
# The honest fix is an explicit maintenance flag: before doing known
# self-caused maintenance (log clearing, bulk remediation testing),
# create this flag file, and DEFENSE_EVASION detection is suppressed
# for MAINTENANCE_WINDOW_MINUTES afterward. This mirrors "maintenance
# windows" in real SIEM/EDR products.
MAINTENANCE_FLAG_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "cybersage_maintenance.flag"
)
MAINTENANCE_WINDOW_MINUTES = 10


def _in_maintenance_mode():
    if not os.path.exists(MAINTENANCE_FLAG_FILE):
        return False
    try:
        mtime = datetime.fromtimestamp(os.path.getmtime(MAINTENANCE_FLAG_FILE))
        return (datetime.now() - mtime) < timedelta(minutes=MAINTENANCE_WINDOW_MINUTES)
    except Exception:
        return False

# Raised from 200 — see note above. Adjust further if your
# machine's normal background traffic still trips this.
PORT_SCAN_THRESHOLD = 1500

# FIXED: allow-list for known-legitimate Windows scheduled tasks, so
# SCHEDULED_TASK stops flagging normal background maintenance (Windows
# Defender's own internal cleanup/cache/verification tasks, etc.).
# Matches on substring, since task names include full paths like
# "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup".
KNOWN_SAFE_TASK_PATTERNS = [
    "windows defender cleanup",
    "windows defender cache maintenance",
    "windows defender verification",
    "windows defender scheduled scan",
    "microsoft\\windows\\windowsupdate",
    "microsoft\\windows\\onedrive",
    "microsoft\\windows\\diskcleanup",
]

# Allow-list for known-legitimate Windows services, so NEW_SERVICE
# stops flagging normal background activity (Windows Update, time
# sync, Defender, etc.). Extend this list if your machine's own
# legitimate services keep tripping detection.
KNOWN_SAFE_SERVICES = {
    "w32time", "wuauserv", "windefend", "onedrive",
    "bits", "cryptsvc", "dot3svc", "eventlog",
    "windows time", "background intelligent transfer service",
    "windows update", "windows defender antivirus service",
}


def _counts(df):
    return df["event_id"].value_counts().to_dict()


def _get_ip(df):
    if "source_ip" not in df.columns:
        return None
    v = df[df["source_ip"].notna()]["source_ip"].value_counts()
    if not v.empty:
        ip = str(v.index[0])
        if ip not in ["127.0.0.1","::1","-","None","nan",""]:
            return ip
    return None


def _get_account(df, event_ids=None):
    if "target_account" not in df.columns:
        return None
    filtered = df[df["event_id"].isin(event_ids)] if event_ids else df
    if filtered.empty:
        filtered = df
    v = filtered[filtered["target_account"].notna()]["target_account"].value_counts()
    for acct in v.index:
        a = str(acct).strip()
        if a and a not in SAFE_ACCOUNTS and "$" not in a:
            return a
    return None


def detect_attacks(df):
    if df is None or df.empty:
        return []

    ec = _counts(df)
    detected = []

    susp = {k: v for k, v in ec.items()
            if k in {4625,4648,4688,4698,4700,4702,
                     4720,4732,5156,5157,7045,1102,4104}}
    if susp:
        print(f"  📊 Event counts: {susp}")

    # ── 01: Brute Force ────────────────────────────────────────
    if ec.get(4625, 0) >= 5:
        a = ATTACKS["BRUTE_FORCE"].copy()
        a.update({
            "pattern"       : "BRUTE_FORCE",
            "count"         : ec[4625],
            "attacker_ip"   : _get_ip(df),
            "target_account": _get_account(df, [4625]),
            "plain_english" : ATTACKS["BRUTE_FORCE"]["plain_english"]
                              .format(count=ec[4625]),
        })
        detected.append(a)
        print(f"  🔴 BRUTE_FORCE detected ({ec[4625]} × Event 4625)")

    # ── 02: Scheduled Task ─────────────────────────────────────
    # FIXED: now checks the actual task name against
    # KNOWN_SAFE_TASK_PATTERNS before flagging. Windows Defender and
    # other built-in components periodically update their own
    # scheduled tasks (cleanup, cache maintenance, verification),
    # which previously triggered a false SCHEDULED_TASK detection
    # with zero filtering.
    sched = ec.get(4698,0) + ec.get(4702,0) + ec.get(4700,0)
    if sched >= 1:
        task_rows = df[df["event_id"].isin([4698, 4702, 4700])]
        task_names = [
            str(n).strip().lower()
            for n in task_rows["target_account"].dropna().unique()
        ]
        suspicious_tasks = [
            n for n in task_names
            if n and n != "nan" and not any(p in n for p in KNOWN_SAFE_TASK_PATTERNS)
        ]
        if suspicious_tasks:
            a = ATTACKS["SCHEDULED_TASK"].copy()
            a.update({
                "pattern"       : "SCHEDULED_TASK",
                "count"         : sched,
                "attacker_ip"   : None,
                "target_account": suspicious_tasks[0],
            })
            detected.append(a)
            print(f"  🔴 SCHEDULED_TASK detected ({suspicious_tasks[0]})")
        else:
            print(f"  ℹ️  Scheduled task update(s) filtered — matched known-safe allow-list")

    # ── 03: New Service ────────────────────────────────────────
    # FIXED: now checks the actual service name(s) against
    # KNOWN_SAFE_SERVICES before flagging. Only fires if at least
    # one newly-installed service is NOT in the allow-list.
    svc = ec.get(7045,0) + ec.get(4697,0)
    if svc >= 1:
        svc_rows = df[df["event_id"].isin([7045, 4697])]
        svc_names = [
            str(n).strip().lower()
            for n in svc_rows["target_account"].dropna().unique()
        ]
        suspicious_names = [
            n for n in svc_names
            if n and n not in KNOWN_SAFE_SERVICES and n != "nan"
        ]
        if suspicious_names:
            a = ATTACKS["NEW_SERVICE"].copy()
            a.update({
                "pattern"       : "NEW_SERVICE",
                "count"         : svc,
                "attacker_ip"   : None,
                "target_account": suspicious_names[0],
            })
            detected.append(a)
            print(f"  🔴 NEW_SERVICE detected ({suspicious_names[0]})")
        else:
            print(f"  ℹ️  New service(s) filtered — matched known-safe allow-list")

    # ── 04: Backdoor Admin ─────────────────────────────────────
    if ec.get(4720,0) >= 1 and ec.get(4732,0) >= 1:
        a = ATTACKS["NEW_ADMIN_USER"].copy()
        a.update({
            "pattern"       : "NEW_ADMIN_USER",
            "count"         : ec.get(4720,0),
            "attacker_ip"   : None,
            "target_account": _get_account(df, [4720,4732]),
        })
        detected.append(a)
        print(f"  🔴 NEW_ADMIN_USER detected!")

    # ── 05: Defense Evasion ────────────────────────────────────
    if ec.get(1102,0) >= 1:
        if _in_maintenance_mode():
            print(f"  ℹ️  Event 1102 present but suppressed — maintenance mode active "
                  f"({MAINTENANCE_FLAG_FILE} touched within last {MAINTENANCE_WINDOW_MINUTES} min)")
        else:
            a = ATTACKS["DEFENSE_EVASION"].copy()
            a.update({
                "pattern"       : "DEFENSE_EVASION",
                "count"         : ec[1102],
                "attacker_ip"   : None,
                "target_account": None,
            })
            detected.append(a)
            print(f"  🔴 DEFENSE_EVASION detected!")

    # ── 06: Port Scan ──────────────────────────────────────────
    # FIXED: threshold raised from 200 to PORT_SCAN_THRESHOLD (1500)
    # to avoid flagging normal background traffic as an attack.
    if ec.get(5156,0) >= PORT_SCAN_THRESHOLD or ec.get(5157,0) >= PORT_SCAN_THRESHOLD:
        scan_count = ec.get(5156,0) + ec.get(5157,0)
        a = ATTACKS["PORT_SCAN"].copy()
        a.update({
            "pattern"       : "PORT_SCAN",
            "count"         : scan_count,
            "attacker_ip"   : _get_ip(df),
            "target_account": None,
        })
        detected.append(a)
        print(f"  🔴 PORT_SCAN detected ({scan_count} connections)")

    # ── 07: Fileless Malware ───────────────────────────────────
    if ec.get(4688,0) >= 1 and "process_name" in df.columns:
        ps = df[
            (df["event_id"] == 4688) &
            (df["process_name"].notna()) &
            (df["process_name"].str.lower().str.contains(
                "powershell|pwsh|wscript|cscript|mshta|rundll32",
                na=False))
        ]
        if len(ps) >= FILELESS_MIN_COUNT:
            # FIXED: previously "process_name" was never set on the
            # attack dict, so kill_malicious_process() always received
            # None and silently did nothing. Now we extract the actual
            # offending process's short name (e.g. "powershell.exe")
            # from the matched rows so remediation can genuinely act.
            raw_name = str(ps["process_name"].iloc[0])
            short_name = raw_name.split("\\")[-1].strip()

            a = ATTACKS["FILELESS_MALWARE"].copy()
            a.update({
                "pattern"       : "FILELESS_MALWARE",
                "count"         : len(ps),
                "attacker_ip"   : None,
                "target_account": _get_account(df, [4688]),
                "process_name"  : short_name,
            })
            detected.append(a)
            print(f"  🔴 FILELESS_MALWARE detected! (process: {short_name}, {len(ps)} invocations)")
        elif not ps.empty:
            print(f"  ℹ️  {len(ps)} PowerShell process(es) seen — below burst threshold "
                  f"({FILELESS_MIN_COUNT}), not flagged (likely normal admin/remediation activity)")

    # ── 08: AI Phishing ────────────────────────────────────────
    if ec.get(4688,0) >= 1 and "process_name" in df.columns:
        email_procs = df[
            (df["event_id"] == 4688) &
            (df["process_name"].notna()) &
            (df["process_name"].str.lower().str.contains(
                "outlook|thunderbird|mailspring|wscript|mshta",
                na=False))
        ]
        if not email_procs.empty and ec.get(5156,0) >= 3:
            a = ATTACKS["AI_PHISHING"].copy()
            a.update({
                "pattern"       : "AI_PHISHING",
                "count"         : len(email_procs),
                "attacker_ip"   : _get_ip(df),
                "target_account": _get_account(df, [4688]),
            })
            detected.append(a)
            print(f"  🔴 AI_PHISHING detected!")

    # ── 09: Password Spray ──────────────────────────────────────
    # Differs from Brute Force: many DISTINCT accounts each with a
    # few failures, rather than one account hammered repeatedly.
    # Real signal an attacker is trying one guessed password across
    # many usernames to dodge per-account lockout thresholds.
    if ec.get(4625, 0) >= 3 and "target_account" in df.columns:
        failed = df[df["event_id"] == 4625]
        distinct_targets = failed["target_account"].dropna().unique()
        distinct_targets = [t for t in distinct_targets if str(t).strip() not in SAFE_ACCOUNTS]
        if len(distinct_targets) >= 3:
            a = ATTACKS["PASSWORD_SPRAY"].copy()
            a.update({
                "pattern"       : "PASSWORD_SPRAY",
                "count"         : len(distinct_targets),
                "attacker_ip"   : _get_ip(df),
                "target_account": ", ".join(distinct_targets[:3]),
            })
            detected.append(a)
            print(f"  🔴 PASSWORD_SPRAY detected ({len(distinct_targets)} accounts targeted)")

    # ── 10: Unauthorized RDP ────────────────────────────────────
    # Event 4624 with LogonType 10 = RemoteInteractive (RDP).
    # NOTE: logon_type is only captured for 4624 in extract_security_details();
    # this checks for that specific type.
    if "logon_type" in df.columns:
        rdp = df[(df["event_id"] == 4624) & (df["logon_type"] == "10")]
        if not rdp.empty:
            a = ATTACKS["UNAUTHORIZED_RDP"].copy()
            a.update({
                "pattern"       : "UNAUTHORIZED_RDP",
                "count"         : len(rdp),
                "attacker_ip"   : _get_ip(df),
                "target_account": _get_account(df, [4624]),
            })
            detected.append(a)
            print(f"  🔴 UNAUTHORIZED_RDP detected ({len(rdp)} RDP logons)")

    # ── 11: Credential Dumping (LSASS access) ───────────────────
    # Event 4663 (object access) targeting lsass.exe is one of the
    # most well-documented real signatures for credential-dumping
    # tools (Mimikatz etc.) attempting to read process memory.
    if ec.get(4663, 0) >= 1 and "process_name" in df.columns:
        lsass_access = df[
            (df["event_id"] == 4663) &
            (df["process_name"].notna()) &
            (df["process_name"].str.lower().str.contains("lsass", na=False))
        ]
        if not lsass_access.empty:
            a = ATTACKS["CREDENTIAL_DUMPING"].copy()
            a.update({
                "pattern"       : "CREDENTIAL_DUMPING",
                "count"         : len(lsass_access),
                "attacker_ip"   : None,
                "target_account": _get_account(df, [4663]),
            })
            detected.append(a)
            print(f"  🔴 CREDENTIAL_DUMPING detected (LSASS access)")

    # ── 12: Pass-the-Hash (heuristic) ───────────────────────────
    # Simplified heuristic: an explicit-credential logon (4648) to a
    # DIFFERENT account than the currently logged-on session, network
    # logon type, without a prior interactive logon for that account
    # in this window. This is a coarse approximation — real PtH
    # detection needs NTLM audit event correlation (4776) which most
    # systems don't enable by default.
    if ec.get(4648, 0) >= 3:
        a = ATTACKS["PASS_THE_HASH"].copy()
        a.update({
            "pattern"       : "PASS_THE_HASH",
            "count"         : ec[4648],
            "attacker_ip"   : _get_ip(df),
            "target_account": _get_account(df, [4648]),
        })
        detected.append(a)
        print(f"  🔴 PASS_THE_HASH detected (heuristic — {ec[4648]}× explicit credential use)")

    # ── 13: C2 Beaconing (heuristic) ─────────────────────────────
    # Real C2 detection needs traffic-content/interval analysis this
    # project doesn't have. Coarse proxy: a single external IP
    # responsible for a large share of allowed connections, distinct
    # from ordinary browsing (many different destinations).
    if ec.get(5156, 0) >= 50 and "source_ip" in df.columns:
        conn = df[(df["event_id"] == 5156) & (df["source_ip"].notna())]
        ip_counts = conn["source_ip"].value_counts()
        real_ips = ip_counts[~ip_counts.index.isin(["127.0.0.1","::1","-","None","nan",""])]
        if not real_ips.empty and real_ips.iloc[0] >= 30:
            a = ATTACKS["C2_BEACONING"].copy()
            a.update({
                "pattern"       : "C2_BEACONING",
                "count"         : int(real_ips.iloc[0]),
                "attacker_ip"   : str(real_ips.index[0]),
                "target_account": None,
            })
            detected.append(a)
            print(f"  🔴 C2_BEACONING detected (heuristic — repeated connections to {real_ips.index[0]})")

    # ── 14–17: Defined but NOT reliably detectable from current
    # telemetry sources (Windows Security/System event logs alone).
    # These remain fully defined in mitre_engine.py, have real RL
    # seed actions and remediation steps, and CAN be triggered
    # manually via ai_remediate() for demonstration — but there is
    # no honest Event-ID-based signal for them without additional
    # sensors:
    #   RANSOMWARE          — needs file-system integrity/entropy
    #                          monitoring (mass file modification),
    #                          not available from Security log alone.
    #   STARTUP_FOLDER       — needs file-system watch on the actual
    #                          startup folder path; Event 4663 doesn't
    #                          capture the file path with current
    #                          extractor logic.
    #   KEYLOGGER            — needs process behavior/API-hooking
    #                          telemetry, not exposed via Event Log.
    #   CRYPTOMINER          — needs CPU/GPU utilization telemetry,
    #                          which Event Logs don't carry.
    #   TROJAN               — needs file reputation/hash telemetry
    #                          (e.g. Defender's own detections), not
    #                          something this classifier reads.
    #   DNS_TUNNELING        — needs DNS query-content logs, which
    #                          require the DNS Client Operational
    #                          log (not enabled here) or a resolver
    #                          with query logging.
    #   DATA_EXFILTRATION    — needs data-volume/DLP telemetry, not
    #                          just connection-allowed counts.
    #   LATERAL_MOVEMENT     — needs correlated multi-host logon
    #                          telemetry; this project monitors one
    #                          host only.
    #   POLYMORPHIC_MALWARE  — needs file-hash/entropy history across
    #                          runs to notice code changing.
    #   PROMPT_INJECTION, DEEPFAKE_AUDIO, ADVERSARIAL_INPUT
    #                        — these are AI-application-layer attacks;
    #                          they need telemetry FROM an AI system
    #                          (prompts, model outputs, audio streams),
    #                          not OS-level event logs. Out of scope
    #                          for a Windows Event Log-based sensor.
    #
    # This is intentional and documented rather than faked: the
    # framework (ATTACKS dict, RL seed actions, remediation steps)
    # supports all 25, but detection is only claimed where the
    # underlying telemetry genuinely supports it.

    # ── FALSE POSITIVE FILTERS ─────────────────────────────────
    patterns   = [d["pattern"] for d in detected]
    count_4625 = ec.get(4625, 0)
    count_4672 = ec.get(4672, 0)

    # 4672 = ALWAYS normal admin activity
    # Never flag it as attack unless brute force present
    if count_4672 >= 1 and count_4625 == 0:
         detected = [d for d in detected
                   if d["pattern"] not in
                    ["PRIVILEGE_ESCALATION","PASS_THE_HASH",
                     "CREDENTIAL_DUMPING","UNAUTHORIZED_RDP"]]
    if count_4672 > 0:
        print(f"  ℹ️  Event 4672 filtered — normal admin activity")

    # Ransomware overrides startup folder
    if "RANSOMWARE" in patterns and "STARTUP_FOLDER" in patterns:
        detected = [d for d in detected
                    if d["pattern"] != "STARTUP_FOLDER"]

    # Sort by risk
    detected.sort(key=lambda x: x.get("risk",0), reverse=True)

    if detected:
        print(f"\n  {Fore.RED}⚠️  {len(detected)} attack(s) detected:{Style.RESET_ALL}")
        for d in detected:
            print(f"    {Fore.RED}▸ {d['pattern']} — {d['risk']}/100{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.GREEN}✅ System clean — no attacks detected{Style.RESET_ALL}")

    return detected


def calculate_risk(df):
    attacks = detect_attacks(df)
    if not attacks:
        return 0
    return min(100, max(a["risk"] for a in attacks))