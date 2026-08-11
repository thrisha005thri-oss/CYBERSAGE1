import time
import concurrent.futures
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

from ai.rl_remediation  import get_ai
from ai.action_executor import execute_action, get_all_actions

# ═══════════════════════════════════════════════════════════════
# CyberSage — AI Remediation Pipeline
# Connects RL AI decisions to deep OS actions
#
# FIXES APPLIED:
# 1. Per-action timeout (15s) — prevents any single action (e.g.
#    a heavy scan) from hanging the whole pipeline.
# 2. Remediation cooldown — prevents the self-reinforcing loop
#    where remediation actions (which shell out to PowerShell)
#    generate new Event 4688 entries, which get re-detected as a
#    fresh FILELESS_MALWARE attack, triggering more remediation,
#    forever. Detection + alerting still happen every scan; actual
#    remediation EXECUTION for a given attack pattern only runs
#    once per cooldown window.
# ═══════════════════════════════════════════════════════════════

ACTION_TIMEOUT_SECONDS = 15   # max time any single action gets to complete
REMEDIATION_COOLDOWN_SECONDS = 180  # don't re-remediate the same pattern within 3 min

# In-memory record of when each attack pattern was last remediated.
# Resets when the process restarts — intentional, so a fresh
# CyberSage run always remediates on first detection.
_last_remediated = {}


def _in_cooldown(pattern):
    last = _last_remediated.get(pattern)
    if last is None:
        return False
    return (datetime.now() - last).total_seconds() < REMEDIATION_COOLDOWN_SECONDS


def _execute_with_timeout(action, context, df, timeout=ACTION_TIMEOUT_SECONDS):
    """
    Runs execute_action() in a worker thread with a hard timeout.
    If the action doesn't finish in time, it's marked as failed/timed-out
    instead of freezing the whole remediation pipeline.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(execute_action, action, context, df)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            return {
                "success": False,
                "message": f"Action timed out after {timeout}s — skipped to avoid hanging pipeline"
            }
        except Exception as e:
            return {"success": False, "message": str(e)}


def ai_remediate(attack, df=None):
    rl      = get_ai()
    pattern = attack.get("pattern", "UNKNOWN")
    risk    = attack.get("risk", 0)

    print(f"\n{Fore.CYAN}{'─'*56}")
    print(f"  🤖 CyberSage AI Remediation")
    print(f"{'─'*56}{Style.RESET_ALL}")
    print(f"  Attack  : {Fore.RED}{pattern}{Style.RESET_ALL}")
    print(f"  Risk    : {risk}/100")

    # ── Cooldown check ──────────────────────────────────────────
    # Detection/alerting already happened before this function was
    # called (see attack_classifier + agent alert logic). This gate
    # only controls whether we ACT again, to stop remediation from
    # generating new events that re-trigger detection in a loop.
    if _in_cooldown(pattern):
        remaining = REMEDIATION_COOLDOWN_SECONDS - (
            datetime.now() - _last_remediated[pattern]
        ).total_seconds()
        print(f"  {Fore.YELLOW}⏳ Remediation cooldown active for {pattern} "
              f"({remaining:.0f}s remaining) — already remediated recently, "
              f"skipping repeat action execution.{Style.RESET_ALL}")
        return {
            "ai_mode"       : "COOLDOWN",
            "confidence"    : 0,
            "actions_chosen": [],
            "actions_done"  : [],
            "outcome"       : "skipped_cooldown",
            "rl_experience" : rl.experience,
            "explore_rate"  : rl.explore_rate,
            "q_snapshot"    : {},
        }

    # RL AI decides actions
    decision = rl.decide(pattern)
    actions  = decision["actions"]
    mode     = decision["mode"]
    conf     = decision["confidence"]

    print(f"  Mode    : {Fore.CYAN}{mode}{Style.RESET_ALL}")
    print(f"  Confidence: {conf}%")
    print(f"  Actions : {len(actions)} planned\n")

    # Build context for action executor
    context = {
        "attack_type"   : pattern,
        "attacker_ip"   : attack.get("attacker_ip"),
        "target_account": attack.get("target_account"),
        "process_name"  : attack.get("process_name"),
        "risk"          : risk,
        "pattern"       : pattern,
    }

    # Execute each action — with timeout protection
    results      = []
    actions_done = []

    for action in actions:
        print(f"\n  ▶ Executing: {action}")
        try:
            result  = _execute_with_timeout(action, context, df)
            success = result.get("success", False)
            msg     = result.get("message", "")
            results.append({"action": action, "success": success, "message": msg})
            if success:
                actions_done.append(msg)
            else:
                print(f"  {Fore.YELLOW}⚠️  {msg}{Style.RESET_ALL}")
        except Exception as e:
            print(f"  {Fore.RED}❌ Error: {e}{Style.RESET_ALL}")
            results.append({"action": action, "success": False, "message": str(e)})

    # Calculate outcome
    n_ok    = sum(1 for r in results if r["success"])
    n_total = len(results)

    if n_ok == n_total:
        outcome = "success"
    elif n_ok > 0:
        outcome = "partial"
    else:
        outcome = "failed"

    print(f"\n  {Fore.CYAN}{'─'*56}{Style.RESET_ALL}")
    print(f"  ✅ Actions succeeded: {n_ok}/{n_total}")
    print(f"  Outcome: {Fore.GREEN if outcome=='success' else Fore.YELLOW}{outcome}{Style.RESET_ALL}")

    # Mark this pattern as remediated now, starting the cooldown
    _last_remediated[pattern] = datetime.now()

    # RL learns from outcome
    rl.learn(pattern, actions, outcome)

    return {
        "ai_mode"       : mode,
        "confidence"    : conf,
        "actions_chosen": actions,
        "actions_done"  : actions_done,
        "outcome"       : outcome,
        "rl_experience" : rl.experience,
        "explore_rate"  : rl.explore_rate,
        "q_snapshot"    : decision["q_snapshot"],
    }