import json
import os
import random
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

# ═══════════════════════════════════════════════════════════════
# CyberSage 2.0 — RL-Based Remediation AI
#
# Built completely from scratch using Q-Learning.
# The AI learns WHICH remediation actions work best
# for each attack type — from real experience.
#
# How it works:
#   State   = attack type (e.g. "BRUTE_FORCE")
#   Actions = remediation options (e.g. "block_ip", "lock_account")
#   Reward  = +1.0 if attack stopped, -0.5 if it continued
#   Q-Table = memory of what worked — saved to rl_memory.json
#
# After every Kali attack:
#   AI picks actions → executes them → observes outcome
#   → updates Q-values → next time it picks better actions
# ═══════════════════════════════════════════════════════════════

MEMORY_FILE = "rl_memory.json"

# ── All possible remediation actions ──────────────────────────
ALL_ACTIONS = [
    # Network Defense (8)
    "block_attacker_ip",
    "block_outbound_connection",
    "isolate_from_network",
    "enable_firewall_stealth",
    "set_dns_primary",
    "flush_dns_cache",
    "disable_rdp",
    "block_outbound_by_path",
    # Account Security (7)
    "lock_targeted_account",
    "enable_account_lockout_policy",
    "force_password_reset",
    "reset_all_passwords",
    "remove_from_admin_group",
    "add_to_protected_users",
    "delete_backdoor_account",
    # Authentication (2)
    "disable_ntlm_auth",
    "enable_credential_guard",
    # PowerShell Security (3)
    "restrict_powershell_execution",
    "enable_scriptblock_logging",
    "disable_powershell_v2",
    # Malware Response (4)
    "kill_malicious_process",
    "quarantine_executable",
    "check_shadow_copies",
    "restore_from_shadow_copy",
    # Forensic & System (7)
    "create_system_snapshot",
    "save_forensic_evidence",
    "setup_event_forwarding",
    "disable_suspicious_task",
    "remove_malicious_task",
    "stop_suspicious_service",
    "stop_and_delete_service",
    "remove_registry_runkey",
    "restore_network",
    # Email Security (2)
    "quarantine_email",
    "block_email_domain",
    # Alerting (1)
    "alert_security_team",
]

# ── All attack types the AI learns about ─────────────────────
ALL_ATTACKS = [
    "BRUTE_FORCE", "PASSWORD_SPRAY", "PASS_THE_HASH",
    "CREDENTIAL_DUMPING", "UNAUTHORIZED_RDP",
    "SCHEDULED_TASK", "NEW_SERVICE", "REGISTRY_RUN_KEY",
    "NEW_ADMIN_USER", "STARTUP_FOLDER",
    "RANSOMWARE", "FILELESS_MALWARE", "TROJAN",
    "KEYLOGGER", "CRYPTOMINER",
    "PORT_SCAN", "C2_BEACONING", "DNS_TUNNELING",
    "DATA_EXFILTRATION", "LATERAL_MOVEMENT",
    "AI_PHISHING", "PROMPT_INJECTION", "DEEPFAKE_AUDIO",
    "POLYMORPHIC_MALWARE", "ADVERSARIAL_INPUT",
    "DEFENSE_EVASION", "UNKNOWN",
]

# ── Seed actions: what the AI starts knowing per attack ───────
# (from MITRE/NIST research in mitre_engine.py)
# AI can explore beyond these, but always includes them
SEED_ACTIONS = {
    "BRUTE_FORCE"        : ["block_attacker_ip", "lock_targeted_account", "enable_account_lockout_policy"],
    "PASSWORD_SPRAY"     : ["block_attacker_ip", "enable_account_lockout_policy", "lock_targeted_account"],
    "PASS_THE_HASH"      : ["block_attacker_ip", "force_password_reset", "create_system_snapshot"],
    "CREDENTIAL_DUMPING" : ["save_forensic_evidence", "force_password_reset", "create_system_snapshot"],
    "UNAUTHORIZED_RDP"   : ["block_attacker_ip", "disable_rdp", "create_system_snapshot"],
    "SCHEDULED_TASK"     : ["disable_suspicious_task", "create_system_snapshot", "save_forensic_evidence"],
    "NEW_SERVICE"        : ["stop_suspicious_service", "create_system_snapshot", "save_forensic_evidence"],
    "REGISTRY_RUN_KEY"   : ["create_system_snapshot", "save_forensic_evidence", "alert_security_team"],
    "NEW_ADMIN_USER"     : ["lock_targeted_account", "remove_from_admin_group", "save_forensic_evidence"],
    "STARTUP_FOLDER"     : ["create_system_snapshot", "save_forensic_evidence", "alert_security_team"],
    "RANSOMWARE"         : ["isolate_from_network", "kill_malicious_process", "save_forensic_evidence"],
    "FILELESS_MALWARE"   : ["kill_malicious_process", "block_outbound_connection", "save_forensic_evidence"],
    "TROJAN"             : ["kill_malicious_process", "block_outbound_connection", "quarantine_executable"],
    "KEYLOGGER"          : ["kill_malicious_process", "force_password_reset", "save_forensic_evidence"],
    "CRYPTOMINER"        : ["kill_malicious_process", "block_outbound_connection", "save_forensic_evidence"],
    "PORT_SCAN"          : ["block_attacker_ip", "save_forensic_evidence", "alert_security_team"],
    "C2_BEACONING"       : ["block_outbound_connection", "isolate_from_network", "save_forensic_evidence"],
    "DNS_TUNNELING"      : ["flush_dns_cache", "block_attacker_ip", "save_forensic_evidence"],
    "DATA_EXFILTRATION"  : ["isolate_from_network", "block_outbound_connection", "save_forensic_evidence"],
    "LATERAL_MOVEMENT"   : ["block_attacker_ip", "lock_targeted_account", "save_forensic_evidence"],
    "AI_PHISHING"        : ["alert_security_team", "save_forensic_evidence"],
    "PROMPT_INJECTION"   : ["block_attacker_ip", "save_forensic_evidence"],
    "DEEPFAKE_AUDIO"     : ["alert_security_team", "save_forensic_evidence"],
    "POLYMORPHIC_MALWARE": ["kill_malicious_process", "quarantine_executable", "save_forensic_evidence"],
    "ADVERSARIAL_INPUT"  : ["save_forensic_evidence", "alert_security_team"],
    "DEFENSE_EVASION"    : ["create_system_snapshot", "save_forensic_evidence", "alert_security_team"],
    "UNKNOWN"            : ["save_forensic_evidence", "alert_security_team", "create_system_snapshot"],
}


class RLRemediationAI:
    """
    Q-Learning Reinforcement Learning AI for remediation.

    Q-Table: q_table[attack_type][action] = float (0.0 – 1.0)
    Higher value = AI has learned this action works well for this attack.

    Update formula (standard Q-Learning):
      new_Q = old_Q + learning_rate × (reward - old_Q)

    Exploration:
      35% of the time the AI tries new action combinations (explore)
      65% of the time it uses its best known actions (exploit)
      Exploration decreases over time as AI gains confidence
    """

    def __init__(self):
        self.learning_rate   = 0.15   # how fast Q-values update
        self.explore_rate    = 0.35   # probability of trying new actions
        self.explore_min     = 0.05   # minimum exploration (never stops learning)
        self.explore_decay   = 0.98   # exploration reduces after each episode

        self.q_table         = {}
        self.experience      = 0
        self.episode_log     = []

        self._init_q_table()
        self._load()

        print(f"{Fore.CYAN}  🤖 RL Remediation AI initialized")
        print(f"     Experience   : {self.experience} episodes")
        print(f"     Explore rate : {self.explore_rate:.2f}")
        print(f"     Q-table size : {len(self.q_table)} attack types{Style.RESET_ALL}")

    # ── Initialise Q-table ─────────────────────────────────────
    def _init_q_table(self):
        """
        Seed Q-table with small positive values for known-good actions
        (from MITRE/NIST research) and near-zero for others.
        AI can still discover better combinations through exploration.
        """
        for attack in ALL_ATTACKS:
            self.q_table[attack] = {}
            seeds = SEED_ACTIONS.get(attack, [])
            for action in ALL_ACTIONS:
                if action in seeds:
                    # Seed good actions with a head start
                    self.q_table[attack][action] = round(random.uniform(0.35, 0.55), 3)
                else:
                    # Other actions start near zero
                    self.q_table[attack][action] = round(random.uniform(0.01, 0.08), 3)

    # ── Main decision function ─────────────────────────────────
    def decide(self, attack_type):
        """
        AI decides which remediation actions to execute.
        Returns dict: {actions, mode, confidence, q_snapshot}
        """
        if attack_type not in self.q_table:
            attack_type = "UNKNOWN"

        q = self.q_table[attack_type]

        # Epsilon-greedy: explore vs exploit
        if random.random() < self.explore_rate:
            actions = self._explore(attack_type)
            mode    = "EXPLORE"
        else:
            actions = self._exploit(attack_type)
            mode    = "EXPLOIT"

        confidence = self._confidence(q, actions)

        # Store for learning
        self._last = {
            "attack_type": attack_type,
            "actions"    : actions,
            "mode"       : mode,
        }

        print(f"\n{Fore.CYAN}  🤖 RL AI Decision for [{attack_type}]{Style.RESET_ALL}")
        print(f"     Mode       : {Fore.YELLOW if mode=='EXPLORE' else Fore.GREEN}{mode}{Style.RESET_ALL}")
        print(f"     Actions    : {', '.join(actions)}")
        print(f"     Confidence : {confidence:.0f}%")
        print(f"     Experience : {self.experience} episodes")

        # Print top Q-values for transparency
        sorted_q = sorted(q.items(), key=lambda x: x[1], reverse=True)[:5]
        print(f"     Top Q-values:")
        for act, val in sorted_q:
            bar    = "█" * int(val * 20)
            marker = " ◄" if act in actions else ""
            print(f"       {act:<30} {val:.3f} {bar}{marker}")

        return {
            "actions"   : actions,
            "mode"      : mode,
            "confidence": confidence,
            "q_snapshot": dict(sorted_q),
        }

    # ── Exploit: use best known actions ───────────────────────
    def _exploit(self, attack_type):
        q      = self.q_table[attack_type]
        seeds  = SEED_ACTIONS.get(attack_type, [])
        sorted_q = sorted(q.items(), key=lambda x: x[1], reverse=True)

        chosen = list(seeds[:2])  # always include top 2 seed actions
        for action, value in sorted_q:
            if action not in chosen and value > 0.15:
                chosen.append(action)
            if len(chosen) >= 5:
                break
        return chosen if chosen else [a for a, _ in sorted_q[:3]]

    # ── Explore: try less-used actions ────────────────────────
    def _explore(self, attack_type):
        q     = self.q_table[attack_type]
        seeds = SEED_ACTIONS.get(attack_type, [])

        # Always keep seed actions (safety net)
        chosen = list(seeds[:2])

        # Add 1-2 random less-tried actions
        others  = [a for a in ALL_ACTIONS if a not in chosen]
        n_extra = random.randint(1, 2)
        chosen += random.sample(others, min(n_extra, len(others)))

        return chosen

    # ── Learn from outcome ─────────────────────────────────────
    def learn(self, attack_type, actions, outcome, user_feedback=None):
        """
        Update Q-values based on what happened.

        outcome       : "success" | "partial" | "failed"
        user_feedback : float -1.0 to +1.0 (from dashboard buttons)
        """
        if attack_type not in self.q_table:
            attack_type = "UNKNOWN"

        reward = self._reward(outcome, user_feedback)

        print(f"\n{Fore.CYAN}  🎓 RL Learning — Episode {self.experience + 1}{Style.RESET_ALL}")
        print(f"     Attack  : {attack_type}")
        print(f"     Outcome : {outcome}")
        print(f"     Reward  : {Fore.GREEN if reward > 0 else Fore.RED}{reward:+.2f}{Style.RESET_ALL}")
        print(f"     Q-Updates:")

        for action in actions:
            old_q = self.q_table[attack_type][action]
            # Q-Learning update formula
            new_q = old_q + self.learning_rate * (reward - old_q)
            new_q = round(max(0.0, min(1.0, new_q)), 4)
            self.q_table[attack_type][action] = new_q

            delta = new_q - old_q
            color = Fore.GREEN if delta > 0 else Fore.RED
            print(f"       {action:<30} "
                  f"{old_q:.3f} → {color}{new_q:.3f} ({delta:+.3f}){Style.RESET_ALL}")

        # Decay exploration
        self.explore_rate = max(self.explore_min,
                                self.explore_rate * self.explore_decay)

        self.experience += 1
        self.episode_log.append({
            "episode"    : self.experience,
            "attack"     : attack_type,
            "actions"    : actions,
            "outcome"    : outcome,
            "reward"     : reward,
            "explore"    : self.explore_rate,
            "timestamp"  : datetime.now().isoformat(),
        })
        if len(self.episode_log) > 500:
            self.episode_log = self.episode_log[-500:]

        self._save()
        print(f"     New explore rate: {self.explore_rate:.3f}")

    # ── Reward function ────────────────────────────────────────
    def _reward(self, outcome, user_feedback=None):
        base = {"success": 1.0, "partial": 0.4, "failed": -0.5}.get(outcome, 0.0)
        if user_feedback is not None:
            base += float(user_feedback) * 0.3
        return round(base, 3)

    # ── Confidence score ───────────────────────────────────────
    def _confidence(self, q, actions):
        if not actions:
            return 0.0
        avg = sum(q.get(a, 0) for a in actions) / len(actions)
        return round(min(99.0, 40.0 + avg * 65.0), 1)

    # ── Best actions summary ───────────────────────────────────
    def best_actions(self, attack_type):
        if attack_type not in self.q_table:
            return []
        q = self.q_table[attack_type]
        return [a for a, _ in sorted(q.items(), key=lambda x: x[1], reverse=True)[:4]]

    def learning_report(self):
        return {
            "experience"  : self.experience,
            "explore_rate": round(self.explore_rate, 3),
            "per_attack"  : {
                atk: {
                    "best_actions": self.best_actions(atk),
                    "top_q"       : dict(sorted(
                        self.q_table[atk].items(),
                        key=lambda x: x[1], reverse=True
                    )[:5])
                }
                for atk in ALL_ATTACKS if atk in self.q_table
            }
        }

    # ── Persistence ───────────────────────────────────────────
    def _save(self):
        data = {
            "q_table"     : self.q_table,
            "experience"  : self.experience,
            "explore_rate": self.explore_rate,
            "episode_log" : self.episode_log[-100:],
            "saved_at"    : datetime.now().isoformat(),
        }
        with open(MEMORY_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _load(self):
        if not os.path.exists(MEMORY_FILE):
            return
        try:
            with open(MEMORY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.q_table      = data.get("q_table", self.q_table)
            self.experience   = data.get("experience", 0)
            self.explore_rate = data.get("explore_rate", 0.35)
            self.episode_log  = data.get("episode_log", [])
            print(f"{Fore.GREEN}  ✅ RL memory loaded — {self.experience} episodes{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}  ⚠️  Could not load RL memory: {e}{Style.RESET_ALL}")


# Singleton — one AI instance shared across the pipeline
_ai = None

def get_ai():
    global _ai
    if _ai is None:
        _ai = RLRemediationAI()
    return _ai