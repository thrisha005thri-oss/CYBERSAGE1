from colorama import Fore, Style, init
from ai.rl_remediation  import get_ai
from ai.action_executor import execute_action
init(autoreset=True)

# ═══════════════════════════════════════════════════════════════
# CyberSage 2.0 — AI Remediation Pipeline
#
# This is the entry point called by main.py.
# Steps:
#   1. RL AI decides which actions to take
#   2. Execute each action via action_executor
#   3. Calculate outcome (how many succeeded)
#   4. RL AI learns from the outcome
#   5. Return full report for dashboard
# ═══════════════════════════════════════════════════════════════


def ai_remediate(attack_info, df, user_feedback=None):
    """
    Full AI-based remediation for one detected attack.

    attack_info : dict from attack_classifier (pattern, risk, attacker_ip, etc.)
    df          : raw log DataFrame (for forensic evidence)
    user_feedback: float -1.0 to +1.0 from dashboard Correct/Wrong buttons

    Returns dict with all results for dashboard display.
    """
    pattern = attack_info.get("pattern", "UNKNOWN")
    risk    = attack_info.get("risk", 0)
    name    = attack_info.get("name", pattern)

    print(f"\n{Fore.CYAN}{'═'*58}")
    print(f"  🤖 AI Remediation Engine — {name}")
    print(f"  Risk: {risk}/100  |  MITRE: {attack_info.get('mitre_id','')}")
    print(f"{'═'*58}{Style.RESET_ALL}")

    ai = get_ai()

    # ── Step 1: RL AI decides actions ─────────────────────────
    decision = ai.decide(pattern)
    actions  = decision["actions"]

    # Build execution context
    context = {
        "attack_type"   : pattern,
        "attacker_ip"   : attack_info.get("attacker_ip"),
        "target_account": attack_info.get("target_account"),
        "process_name"  : attack_info.get("process_name"),
        "risk"          : risk,
    }

    # ── Step 2: Execute each action ───────────────────────────
    print(f"\n{Fore.YELLOW}  ⚡ Executing {len(actions)} AI-chosen actions:{Style.RESET_ALL}")

    results      = []
    actions_done = []

    for action in actions:
        print(f"\n  → {action}")
        result = execute_action(action, context, df)
        results.append(result)
        color  = Fore.GREEN if result["success"] else Fore.RED
        symbol = "✅" if result["success"] else "❌"
        print(f"    {color}{symbol} {result['message']}{Style.RESET_ALL}")
        if result["success"]:
            actions_done.append(result["message"])

    # ── Step 3: Calculate outcome ──────────────────────────────
    n_ok    = sum(1 for r in results if r["success"])
    n_total = len(results)

    if n_ok == n_total:
        outcome = "success"
        outcome_color = Fore.GREEN
    elif n_ok > 0:
        outcome = "partial"
        outcome_color = Fore.YELLOW
    else:
        outcome = "failed"
        outcome_color = Fore.RED

    print(f"\n  {Fore.CYAN}{'─'*56}{Style.RESET_ALL}")
    print(f"  Outcome : {outcome_color}{outcome.upper()}{Style.RESET_ALL} "
          f"({n_ok}/{n_total} actions succeeded)")

    # ── Step 4: RL AI learns ───────────────────────────────────
    ai.learn(pattern, actions, outcome, user_feedback)

    # ── Step 5: Build report ───────────────────────────────────
    report = {
        "pattern"        : pattern,
        "name"           : name,
        "outcome"        : outcome,
        "ai_mode"        : decision["mode"],
        "confidence"     : decision["confidence"],
        "actions_chosen" : actions,
        "actions_done"   : actions_done,
        "results"        : results,
        "n_ok"           : n_ok,
        "n_total"        : n_total,
        "rl_experience"  : ai.experience,
        "explore_rate"   : round(ai.explore_rate, 3),
        "q_snapshot"     : decision["q_snapshot"],
    }

    print(f"\n  {Fore.CYAN}AI Summary:")
    print(f"    Mode       : {decision['mode']}")
    print(f"    Confidence : {decision['confidence']:.0f}%")
    print(f"    Experience : {ai.experience} total episodes")
    print(f"    Explore    : {ai.explore_rate:.2f} "
          f"({'still learning' if ai.explore_rate > 0.15 else 'mostly exploiting'})")
    print(f"{'═'*58}{Style.RESET_ALL}\n")

    return report
