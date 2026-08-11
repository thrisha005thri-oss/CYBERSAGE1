import json
import os
import random
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

# ═══════════════════════════════════════════════════════════════
# CyberSage — Q-Learning RL Engine
# Built completely from scratch — no library used
# Learns which deep remediation actions work best
# NO network isolation — never blocks its own connection!
#
# UPDATED: seed actions added for all 17 additional attack patterns
# (defined in mitre_engine.py) so the RL engine has a valid Q-table
# entry for every one of the 25 total attacks the project defines.
# The original 8 patterns' seed lists are byte-for-byte unchanged
# from before, so existing testing/behavior is unaffected.
# ═══════════════════════════════════════════════════════════════

MEMORY_FILE = "rl_memory.json"

ALL_ACTIONS = [
    # Network Defense
    "block_attacker_ip",
    "enable_firewall_stealth",
    "flush_dns_cache",
    "disable_rdp",
    "restore_network",
    # Account Security
    "lock_targeted_account",
    "enable_account_lockout_policy",
    "force_password_reset",
    "remove_from_admin_group",
    "delete_backdoor_account",
    # PowerShell Security
    "restrict_powershell",
    "disable_powershell_v2",
    "enable_scriptblock_logging",
    # Malware Response
    "kill_malicious_process",
    "smart_quarantine_suspicious_files",
    "eradicate_atomic_redteam_files",
    # Service/Task
    "stop_and_delete_service",
    "remove_malicious_task",
    # Forensic & System
    "create_system_snapshot",
    "save_forensic_evidence",
    "setup_log_protection",
    "run_windows_defender_scan",
    # Alert
    "alert_security_team",
]

# Deep seed actions per attack — goes beyond surface level!
SEED_ACTIONS = {
    "BRUTE_FORCE"     : [
        "block_attacker_ip",
        "lock_targeted_account",
        "enable_account_lockout_policy",
        "force_password_reset",
        "save_forensic_evidence",
        "alert_security_team",
        "eradicate_atomic_redteam_files",
    ],
    "SCHEDULED_TASK"  : [
        "remove_malicious_task",
        "create_system_snapshot",
        "smart_quarantine_suspicious_files",
        "eradicate_atomic_redteam_files",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "NEW_SERVICE"     : [
        "stop_and_delete_service",
        "create_system_snapshot",
        "smart_quarantine_suspicious_files",
        "eradicate_atomic_redteam_files",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "NEW_ADMIN_USER"  : [
        "delete_backdoor_account",
        "remove_from_admin_group",
        "lock_targeted_account",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "DEFENSE_EVASION" : [
        "setup_log_protection",
        "create_system_snapshot",
        "eradicate_atomic_redteam_files",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "PORT_SCAN"       : [
        "block_attacker_ip",
        "enable_firewall_stealth",
        "eradicate_atomic_redteam_files",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "FILELESS_MALWARE": [
        "kill_malicious_process",
        "restrict_powershell",
        "disable_powershell_v2",
        "enable_scriptblock_logging",
        "smart_quarantine_suspicious_files",
        "eradicate_atomic_redteam_files",
        "save_forensic_evidence",
    ],
    "AI_PHISHING"     : [
        "block_attacker_ip",
        "smart_quarantine_suspicious_files",
        "eradicate_atomic_redteam_files",
        "save_forensic_evidence",
        "alert_security_team",
    ],

    # ── Additional 17 — new entries only, nothing above this
    # line was changed. Seed actions mapped to the closest matching
    # existing remediation functions. Where no dedicated action
    # exists (e.g. NTLM disabling, DNS server forcing), the closest
    # available action is used; this is noted where relevant.
    "PASSWORD_SPRAY": [
        "block_attacker_ip",
        "enable_account_lockout_policy",
        "force_password_reset",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "PASS_THE_HASH": [
        "force_password_reset",
        "lock_targeted_account",
        "save_forensic_evidence",
        "alert_security_team",
        "create_system_snapshot",
    ],
    "UNAUTHORIZED_RDP": [
        "disable_rdp",
        "block_attacker_ip",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "STARTUP_FOLDER": [
        "smart_quarantine_suspicious_files",
        "eradicate_atomic_redteam_files",
        "create_system_snapshot",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "RANSOMWARE": [
        "kill_malicious_process",
        "create_system_snapshot",
        "restore_network",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "KEYLOGGER": [
        "kill_malicious_process",
        "smart_quarantine_suspicious_files",
        "force_password_reset",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "CRYPTOMINER": [
        "kill_malicious_process",
        "block_attacker_ip",
        "smart_quarantine_suspicious_files",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "C2_BEACONING": [
        "block_attacker_ip",
        "kill_malicious_process",
        "smart_quarantine_suspicious_files",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "DNS_TUNNELING": [
        "flush_dns_cache",
        "block_attacker_ip",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "DATA_EXFILTRATION": [
        "block_attacker_ip",
        "restore_network",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "LATERAL_MOVEMENT": [
        "block_attacker_ip",
        "lock_targeted_account",
        "force_password_reset",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "TROJAN": [
        "kill_malicious_process",
        "smart_quarantine_suspicious_files",
        "run_windows_defender_scan",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "PROMPT_INJECTION": [
        "alert_security_team",
        "save_forensic_evidence",
        "create_system_snapshot",
    ],
    "DEEPFAKE_AUDIO": [
        "alert_security_team",
        "save_forensic_evidence",
    ],
    "POLYMORPHIC_MALWARE": [
        "kill_malicious_process",
        "enable_scriptblock_logging",
        "run_windows_defender_scan",
        "save_forensic_evidence",
        "alert_security_team",
    ],
    "ADVERSARIAL_INPUT": [
        "alert_security_team",
        "save_forensic_evidence",
    ],
    "CREDENTIAL_DUMPING": [
        "lock_targeted_account",
        "force_password_reset",
        "save_forensic_evidence",
        "alert_security_team",
        "create_system_snapshot",
    ],

    "UNKNOWN"         : [
        "create_system_snapshot",
        "save_forensic_evidence",
        "smart_quarantine_suspicious_files",
        "alert_security_team",
    ],
}


class RLRemediationAI:
    def __init__(self):
        self.learning_rate  = 0.15
        self.explore_rate   = 0.35
        self.explore_min    = 0.05
        self.explore_decay  = 0.995
        self.q_table        = {}
        self.experience     = 0
        self._init_q_table()
        self._load()
        print(f"{Fore.GREEN}✅ RL AI ready | "
              f"Experience: {self.experience} | "
              f"Explore: {self.explore_rate:.2f}{Style.RESET_ALL}")

    def _init_q_table(self):
        for attack in SEED_ACTIONS:
            self.q_table[attack] = {}
            for action in ALL_ACTIONS:
                if action in SEED_ACTIONS.get(attack, []):
                    self.q_table[attack][action] = round(
                        random.uniform(0.4, 0.5), 3)
                else:
                    self.q_table[attack][action] = round(
                        random.uniform(0.05, 0.1), 3)

    def decide(self, attack_type):
        if attack_type not in self.q_table:
            attack_type = "UNKNOWN"

        q        = self.q_table[attack_type]
        is_expl  = random.random() < self.explore_rate

        if is_expl:
            # Explore — try less-known actions
            seed    = SEED_ACTIONS.get(attack_type, [])[:3]
            others  = [a for a in ALL_ACTIONS if a not in seed]
            extra   = random.sample(others, min(2, len(others)))
            actions = seed + extra
            mode    = "EXPLORE"
        else:
            # Exploit — use best known actions
            sorted_q = sorted(q.items(), key=lambda x: x[1], reverse=True)
            actions  = [a for a, v in sorted_q if v > 0.3][:6]
            if not actions:
                actions = SEED_ACTIONS.get(attack_type, ALL_ACTIONS[:3])
            mode = "EXPLOIT"

        confidence = self._confidence(q, actions)

        return {
            "actions"    : actions,
            "mode"       : mode,
            "confidence" : confidence,
            "q_snapshot" : dict(sorted(q.items(),
                           key=lambda x: x[1], reverse=True)[:5])
        }

    def learn(self, attack_type, actions, outcome, user_feedback=None):
        if attack_type not in self.q_table:
            attack_type = "UNKNOWN"

        rewards = {"success": 1.0, "partial": 0.4, "failed": -0.5}
        reward  = rewards.get(outcome, 0.0)
        if user_feedback:
            reward += float(user_feedback) * 0.3

        print(f"\n  {Fore.CYAN}🧠 RL Learning — Episode {self.experience+1}{Style.RESET_ALL}")
        print(f"  Outcome: {outcome} | Reward: {reward:+.2f}")

        for action in actions:
            if action in self.q_table[attack_type]:
                old_q = self.q_table[attack_type][action]
                new_q = old_q + self.learning_rate * (reward - old_q)
                new_q = round(max(0.0, min(1.0, new_q)), 4)
                self.q_table[attack_type][action] = new_q
                delta = new_q - old_q
                color = Fore.GREEN if delta > 0 else Fore.RED
                print(f"    {action}: {old_q:.3f} → {color}{new_q:.3f} ({delta:+.3f}){Style.RESET_ALL}")

        self.explore_rate = max(
            self.explore_min,
            self.explore_rate * self.explore_decay
        )
        self.experience += 1
        self._save()
        return {"reward": reward, "episodes": self.experience}

    def _confidence(self, q, actions):
        if not actions:
            return 0.0
        avg = sum(q.get(a, 0) for a in actions) / len(actions)
        return round(min(99.0, 40.0 + avg * 60.0), 1)

    def _save(self):
        with open(MEMORY_FILE, "w") as f:
            json.dump({
                "q_table"    : self.q_table,
                "experience" : self.experience,
                "explore_rate": self.explore_rate,
                "saved_at"   : datetime.now().isoformat()
            }, f, indent=2)

    def _load(self):
        if os.path.exists(MEMORY_FILE):
            try:
                with open(MEMORY_FILE) as f:
                    mem = json.load(f)
                self.q_table     = mem.get("q_table", self.q_table)
                self.experience  = mem.get("experience", 0)
                self.explore_rate= mem.get("explore_rate", self.explore_rate)
                print(f"{Fore.GREEN}✅ Loaded {self.experience} RL episodes{Style.RESET_ALL}")
            except:
                print(f"{Fore.YELLOW}⚠️  Starting fresh RL memory{Style.RESET_ALL}")


_ai = None

def get_ai():
    global _ai
    if _ai is None:
        _ai = RLRemediationAI()
    return _ai