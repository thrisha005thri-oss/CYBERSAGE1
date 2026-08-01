import sys
import os
import json
import threading
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agent.log_monitor          import read_windows_logs
from detector.attack_classifier import detect_attacks, calculate_risk
from explainer.llm_engine       import explain_attack
from ai.ai_remediation          import ai_remediate

# ═══════════════════════════════════════════════════════════════
# CyberSage 2.0 — Main Pipeline v4
# Reads 1000 logs (increased from 500 to catch more events)
# ═══════════════════════════════════════════════════════════════

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE  = os.path.join(PROJECT_DIR, "cybersage_state.json")


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, default=str)


def run_pipeline(max_events=1000):
    scan_start = datetime.now()
    scan_count = _load_scan_count()

    print(f"\n{Fore.CYAN}{'═'*58}")
    print(f"  🛡️  CyberSage 2.0  —  AI Cyber Defense")
    print(f"{'═'*58}{Style.RESET_ALL}")
    print(f"  Scan #{scan_count + 1}  |  "
          f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ── STEP 1: Read logs ──────────────────────────────────────
    print(f"\n{Fore.YELLOW}▶ STEP 1: Reading live Windows Event Logs..."
          f"{Style.RESET_ALL}")
    df = read_windows_logs(log_type="Security", max_events=max_events)

    if df is None:
        print(f"{Fore.RED}  ❌ Cannot read logs — run as Administrator!"
              f"{Style.RESET_ALL}")
        return None

    total_scanned = len(df)
    threats_found = int(df["suspicious"].sum()) if not df.empty else 0

    # ── STEP 2: Detect attacks ─────────────────────────────────
    print(f"\n{Fore.YELLOW}▶ STEP 2: Mapping logs to MITRE ATT&CK..."
          f"{Style.RESET_ALL}")
    attacks = detect_attacks(df)
    risk    = calculate_risk(df)

    if not attacks:
        print(f"\n  {Fore.GREEN}✅  System CLEAN — "
              f"no attack patterns detected{Style.RESET_ALL}")
        elapsed = (datetime.now() - scan_start).total_seconds()
        print(f"  Scan time: {elapsed:.2f}s\n")
        state = _build_state(df, [], risk, total_scanned,
                             threats_found, scan_count + 1, "MONITORING")
        save_state(state)
        _save_scan_count(scan_count + 1)
        return state

    # Attacks found
    print(f"\n  {Fore.RED}⚠️  {len(attacks)} ATTACK(S) DETECTED!{Style.RESET_ALL}")
    for a in attacks:
        print(f"  {Fore.RED}  ▸ [{a['mitre_id']}] {a['name']}  "
              f"—  Risk: {a['risk']}/100{Style.RESET_ALL}")

    # ── STEP 3: Explain + Remediate in parallel ────────────────
    print(f"\n{Fore.YELLOW}▶ STEP 3: AI explaining + remediating "
          f"in parallel...{Style.RESET_ALL}")

    explanations = {}
    ai_reports   = {}

    def explain_all():
        for attack in attacks:
            pat               = attack["pattern"]
            explanations[pat] = explain_attack(attack, "normal")

    def remediate_all():
        for attack in attacks:
            pat            = attack["pattern"]
            ai_reports[pat]= ai_remediate(attack, df)

    t1 = threading.Thread(target=explain_all,   daemon=True)
    t2 = threading.Thread(target=remediate_all, daemon=True)
    t1.start(); t2.start()
    t1.join();  t2.join()

    state = _build_state(df, attacks, risk, total_scanned, threats_found,
                         scan_count + 1, "UNDER ATTACK",
                         explanations, ai_reports)
    save_state(state)
    _save_scan_count(scan_count + 1)

    elapsed = (datetime.now() - scan_start).total_seconds()
    print(f"\n{Fore.CYAN}{'─'*58}")
    print(f"  ✅ Scan complete in {elapsed:.2f}s")
    print(f"  📊 {len(attacks)} attacks detected and remediated")
    print(f"{'─'*58}{Style.RESET_ALL}\n")

    return state


def _build_state(df, attacks, risk, total_scanned, threats_found,
                 scan_count, status, explanations=None, ai_reports=None):
    all_logs = []
    if df is not None and not df.empty:
        for _, row in df.iterrows():
            all_logs.append({
                "event_id"      : int(row.get("event_id", 0)),
                "time"          : str(row.get("time", "")),
                "source"        : str(row.get("source", "")),
                "event_label"   : str(row.get("event_label", "")),
                "suspicious"    : bool(row.get("suspicious", False)),
                "source_ip"     : str(row.get("source_ip",""))
                                  if row.get("source_ip") else None,
                "target_account": str(row.get("target_account",""))
                                  if row.get("target_account") else None,
                "logon_type"    : str(row.get("logon_type",""))
                                  if row.get("logon_type") else None,
                "process_name"  : str(row.get("process_name",""))
                                  if row.get("process_name") else None,
            })

    attack_list = []
    for a in attacks:
        pat    = a["pattern"]
        ai_rep = (ai_reports or {}).get(pat, {})
        attack_list.append({
            "pattern"        : pat,
            "name"           : a.get("name", pat),
            "category"       : a.get("category", ""),
            "mitre_id"       : a.get("mitre_id", ""),
            "mitre_tactic"   : a.get("mitre_tactic", ""),
            "mitre_url"      : a.get("mitre_url", ""),
            "severity"       : a.get("severity", ""),
            "risk"           : a.get("risk", 0),
            "count"          : a.get("count", 0),
            "attacker_ip"    : a.get("attacker_ip"),
            "target_account" : a.get("target_account"),
            "plain_english"  : str(a.get("plain_english",""))
                               .replace("{count}", str(a.get("count",""))),
            "principle"      : a.get("principle", ""),
            "remediation"    : a.get("remediation", []),
            "sources"        : a.get("sources", []),
            "explanation"    : (explanations or {}).get(pat, ""),
            "ai_mode"        : ai_rep.get("ai_mode", ""),
            "ai_confidence"  : ai_rep.get("confidence", 0),
            "ai_actions"     : ai_rep.get("actions_chosen", []),
            "ai_actions_done": ai_rep.get("actions_done", []),
            "ai_outcome"     : ai_rep.get("outcome", ""),
            "ai_experience"  : ai_rep.get("rl_experience", 0),
            "ai_explore"     : ai_rep.get("explore_rate", 0),
            "ai_q_snapshot"  : ai_rep.get("q_snapshot", {}),
        })

    return {
        "status"       : status,
        "risk_score"   : risk,
        "total_scanned": total_scanned,
        "threats_found": threats_found,
        "attacks"      : attack_list,
        "all_logs"     : all_logs,
        "last_scan"    : datetime.now().strftime("%H:%M:%S"),
        "scan_count"   : scan_count,
    }


_SCAN_CTR = "scan_count.json"

def _load_scan_count():
    try:
        with open(_SCAN_CTR) as f:
            return json.load(f).get("count", 0)
    except Exception:
        return 0

def _save_scan_count(n):
    with open(_SCAN_CTR, "w") as f:
        json.dump({"count": n}, f)


if __name__ == "__main__":
    run_pipeline(max_events=1000)