from colorama import Fore, Style, init
init(autoreset=True)

# ═══════════════════════════════════════════════════════════════
# CyberSage 2.0 — Attack Classifier v5
# FIXED:
#   1. Event 4656 threshold raised to 50 (stops false positives)
#   2. Event 4672 alone = NORMAL (filtered)
#   3. isolate_from_network removed from seed actions
#   4. Network blocking disabled for testing
# ═══════════════════════════════════════════════════════════════

try:
    from detector.mitre_engine import ATTACKS
except ImportError:
    from mitre_engine import ATTACKS

SAFE_ACCOUNTS = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "DWM-1", "DWM-2", "DWM-3",
    "UMFD-0", "UMFD-1", "UMFD-2",
    "-", "nan", "None", "", "Anonymous Logon",
}


def _counts(df):
    return df["event_id"].value_counts().to_dict()


def _get_ip(df):
    if "source_ip" in df.columns:
        v = df[df["source_ip"].notna()]["source_ip"].value_counts()
        if not v.empty:
            ip = str(v.index[0])
            if ip not in ["127.0.0.1","::1","-","None","nan",""]:
                return ip
    return None


def _get_account(df, event_ids=None):
    if "target_account" not in df.columns:
        return None
    filtered = df
    if event_ids:
        filtered = df[df["event_id"].isin(event_ids)]
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

    ec       = _counts(df)
    detected = []

    susp = {k: v for k, v in ec.items()
            if k in {4625,4648,4657,4663,4672,4688,
                     4697,4698,4700,4702,4719,4720,
                     4728,4732,4740,4776,1102,7045}}
    if susp:
        print(f"  📊 Suspicious event counts: {susp}")

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

    # ── 02: Password Spray ─────────────────────────────────────
    if ec.get(4625, 0) >= 3 and "target_account" in df.columns:
        failed = df[df["event_id"] == 4625]
        unique = failed["target_account"].dropna().nunique()
        if unique >= 3:
            a = ATTACKS["PASSWORD_SPRAY"].copy()
            a.update({
                "pattern"       : "PASSWORD_SPRAY",
                "count"         : unique,
                "attacker_ip"   : _get_ip(df),
                "target_account": None,
                "plain_english" : ATTACKS["PASSWORD_SPRAY"]["plain_english"]
                                  .format(count=unique),
            })
            detected.append(a)

    # ── 04: Credential Dumping ─────────────────────────────────
    # FIXED: threshold raised to 50 to prevent false positives
    if ec.get(4656, 0) >= 50 and ec.get(4625, 0) == 0:
        a = ATTACKS["CREDENTIAL_DUMPING"].copy()
        a.update({
            "pattern"       : "CREDENTIAL_DUMPING",
            "count"         : ec[4656],
            "attacker_ip"   : _get_ip(df),
            "target_account": _get_account(df, [4656]),
        })
        detected.append(a)
        print(f"  🔴 CREDENTIAL_DUMPING detected ({ec[4656]} × Event 4656)")

    # ── 06: Scheduled Task ─────────────────────────────────────
    sched_count = (ec.get(4698, 0) + ec.get(4702, 0) + ec.get(4700, 0))
    if sched_count >= 1:
        a = ATTACKS["SCHEDULED_TASK"].copy()
        a.update({
            "pattern"       : "SCHEDULED_TASK",
            "count"         : sched_count,
            "attacker_ip"   : None,
            "target_account": _get_account(df, [4698, 4702, 4700]),
        })
        detected.append(a)
        print(f"  🔴 SCHEDULED_TASK detected "
              f"(4698:{ec.get(4698,0)}, 4702:{ec.get(4702,0)})")

    # ── 07: New Service ────────────────────────────────────────
    svc_count = ec.get(7045, 0) + ec.get(4697, 0)
    if svc_count >= 1:
        a = ATTACKS["NEW_SERVICE"].copy()
        a.update({
            "pattern"       : "NEW_SERVICE",
            "count"         : svc_count,
            "attacker_ip"   : None,
            "target_account": _get_account(df, [7045, 4697]),
        })
        detected.append(a)
        print(f"  🔴 NEW_SERVICE detected ({svc_count})")

    # ── 08: Registry Run Key ───────────────────────────────────
    if ec.get(4657, 0) >= 1:
        a = ATTACKS["REGISTRY_RUN_KEY"].copy()
        a.update({
            "pattern"       : "REGISTRY_RUN_KEY",
            "count"         : ec[4657],
            "attacker_ip"   : None,
            "target_account": _get_account(df, [4657]),
        })
        detected.append(a)
        print(f"  🔴 REGISTRY_RUN_KEY detected")

    # ── 09: New Admin User ─────────────────────────────────────
    # REQUIRES BOTH 4720 AND 4732
    if ec.get(4720, 0) >= 1 and ec.get(4732, 0) >= 1:
        a = ATTACKS["NEW_ADMIN_USER"].copy()
        a.update({
            "pattern"       : "NEW_ADMIN_USER",
            "count"         : ec.get(4720, 0),
            "attacker_ip"   : None,
            "target_account": _get_account(df, [4720, 4732]),
        })
        detected.append(a)
        print(f"  🔴 NEW_ADMIN_USER detected!")

    # ── 10: Startup Folder ─────────────────────────────────────
    if 1 <= ec.get(4663, 0) < 50:
        a = ATTACKS["STARTUP_FOLDER"].copy()
        a.update({
            "pattern"       : "STARTUP_FOLDER",
            "count"         : ec[4663],
            "attacker_ip"   : None,
            "target_account": _get_account(df, [4663]),
        })
        detected.append(a)

    # ── 11: Ransomware ─────────────────────────────────────────
    if ec.get(4663, 0) >= 100:
        a = ATTACKS["RANSOMWARE"].copy()
        a.update({
            "pattern"       : "RANSOMWARE",
            "count"         : ec[4663],
            "attacker_ip"   : None,
            "target_account": _get_account(df),
        })
        detected.append(a)

    # ── 26: Defense Evasion ────────────────────────────────────
    if ec.get(1102, 0) >= 1:
        a = ATTACKS["DEFENSE_EVASION"].copy()
        a.update({
            "pattern"       : "DEFENSE_EVASION",
            "count"         : ec[1102],
            "attacker_ip"   : None,
            "target_account": _get_account(df, [1102]),
        })
        detected.append(a)
        print(f"  🔴 DEFENSE_EVASION detected! (Event 1102)")

    # ══════════════════════════════════════════════════════════
    # FALSE POSITIVE FILTERS
    # ══════════════════════════════════════════════════════════

    patterns       = [d["pattern"] for d in detected]
    count_4625     = ec.get(4625, 0)
    count_4672     = ec.get(4672, 0)
    count_4720     = ec.get(4720, 0)
    count_4732     = ec.get(4732, 0)

    # FILTER 1: Event 4672 alone = normal admin activity
    if count_4672 >= 1 and count_4625 == 0 and count_4720 == 0:
        before = len(detected)
        detected = [d for d in detected
                    if d["pattern"] not in
                    ["PRIVILEGE_ESCALATION", "PASS_THE_HASH"]]
        if len(detected) < before:
            print(f"  {Fore.YELLOW}ℹ️  4672 filtered (normal admin){Style.RESET_ALL}")

    # FILTER 2: Ransomware overrides startup folder
    if "RANSOMWARE" in patterns and "STARTUP_FOLDER" in patterns:
        detected = [d for d in detected
                   if d["pattern"] != "STARTUP_FOLDER"]

    # FILTER 3: NEW_ADMIN_USER needs BOTH 4720 AND 4732
    if "NEW_ADMIN_USER" in patterns:
        if count_4720 == 0 or count_4732 == 0:
            detected = [d for d in detected
                       if d["pattern"] != "NEW_ADMIN_USER"]

    # Sort by risk
    detected.sort(key=lambda x: x.get("risk", 0), reverse=True)

    if detected:
        print(f"\n  {Fore.RED}⚠️  {len(detected)} attack(s):{Style.RESET_ALL}")
        for d in detected:
            print(f"    {Fore.RED}▸ {d['pattern']} — {d['risk']}/100{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.GREEN}✅ System clean{Style.RESET_ALL}")

    return detected


def calculate_risk(df):
    attacks = detect_attacks(df)
    if not attacks:
        return 0
    return min(100, max(a["risk"] for a in attacks))