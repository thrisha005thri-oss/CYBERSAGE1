import os
import requests
from colorama import Fore, Style, init
init(autoreset=True)

# ═══════════════════════════════════════════════════════════════
# CyberSage 2.0 — LLM Engine
# Groq LLaMA for plain English explanation ONLY
# Fixed: reads .env correctly, shows on dashboard
# ═══════════════════════════════════════════════════════════════

GROQ_URL   = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"


def _get_key():
    """Load Groq API key from .env file"""
    try:
        env_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            ".env"
        )
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("GROQ_API_KEY="):
                        key = line.split("=", 1)[1].strip()
                        if key and key != "your_key_here":
                            return key
    except Exception as e:
        print(f"  env read error: {e}")
    return os.environ.get("GROQ_API_KEY", "")


def explain_attack(attack, audience="normal"):
    """
    Generate plain English explanation using Groq LLaMA.
    Falls back to built-in explanation if API unavailable.
    """
    pattern     = attack.get("pattern", "UNKNOWN")
    name        = attack.get("name", pattern)
    mitre_id    = attack.get("mitre_id", "")
    risk        = attack.get("risk", 0)
    count       = attack.get("count", 0)
    attacker_ip = attack.get("attacker_ip", "unknown")
    account     = attack.get("target_account", "unknown")
    plain       = attack.get("plain_english", "")

    # Try Groq API first
    key = _get_key()
    if key:
        try:
            prompt = (
                f"You are CyberSage, an AI security assistant.\n"
                f"Explain this cyberattack to a NON-TECHNICAL person "
                f"in 3 sentences. Use simple words. No jargon. Be calm.\n\n"
                f"Attack: {name}\n"
                f"MITRE: {mitre_id}\n"
                f"Risk: {risk}/100\n"
                f"Events detected: {count}\n"
                f"Attacker IP: {attacker_ip}\n"
                f"Target account: {account}\n\n"
                f"Explain: what attacker tried, why dangerous, "
                f"that CyberSage blocked it. Under 70 words."
            )

            headers = {
                "Authorization": f"Bearer {key}",
                "Content-Type" : "application/json",
            }
            payload = {
                "model"      : GROQ_MODEL,
                "messages"   : [{"role": "user", "content": prompt}],
                "max_tokens" : 200,
                "temperature": 0.4,
            }

            resp = requests.post(
                GROQ_URL,
                headers=headers,
                json=payload,
                timeout=10
            )

            if resp.status_code == 200:
                data        = resp.json()
                explanation = data["choices"][0]["message"]["content"].strip()
                print(f"  {Fore.GREEN}✅ Groq explanation ready{Style.RESET_ALL}")
                return explanation
            else:
                print(f"  {Fore.YELLOW}⚠️  Groq API error "
                      f"{resp.status_code}{Style.RESET_ALL}")

        except Exception as e:
            print(f"  {Fore.YELLOW}⚠️  Groq error: {e}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.YELLOW}⚠️  No Groq key — "
              f"using built-in explanation{Style.RESET_ALL}")

    # Fallback to built-in explanation
    if plain:
        return plain.replace("{count}", str(count))

    return _fallback(name, risk, count)


def _fallback(name, risk, count):
    """Built-in plain English explanations"""
    fallbacks = {
        "Brute Force Login Attack": (
            f"Someone rapidly tried {count} wrong passwords on your account. "
            "Like a thief trying every key on a keychain. "
            "CyberSage blocked the attacker and locked the account automatically."
        ),
        "Backdoor Admin Account Created": (
            "An attacker created a secret admin account to maintain access "
            "even if detected. This is one of the most dangerous persistence "
            "techniques. CyberSage disabled the account and saved forensic evidence."
        ),
        "Scheduled Task Persistence": (
            "A scheduled task was created to run malicious code automatically "
            "at set times even after every reboot. Attackers use this to stay "
            "on your system. CyberSage flagged it and created a system snapshot."
        ),
        "Malicious Service Installation": (
            "A new Windows service was installed that could run malicious "
            "code with high system privileges. "
            "CyberSage stopped the service and preserved forensic evidence."
        ),
        "Registry Run Key Persistence": (
            "A program was added to Windows startup registry so it runs "
            "automatically every time Windows boots. "
            "CyberSage captured forensic evidence of this persistence attempt."
        ),
        "Defense Evasion": (
            "The Windows Security Event Log was deliberately cleared to "
            "destroy evidence of the attack. This is a CRITICAL sign of "
            "active intrusion. CyberSage isolated the system and preserved evidence."
        ),
        "Credential Dumping": (
            "An attacker tried to access Windows memory where all passwords "
            "are stored. If successful they could steal every account credential. "
            "CyberSage blocked the access and saved forensic evidence."
        ),
        "Port Scan Detected": (
            "Someone scanned your system to find open ports and vulnerabilities. "
            "This is usually the first step of a larger attack. "
            "CyberSage blocked the scanner IP in the firewall."
        ),
    }

    return fallbacks.get(
        name,
        f"A suspicious security event was detected: {name}. "
        f"Risk level: {risk}/100. "
        "CyberSage automatically took protective action "
        "and preserved forensic evidence for investigation."
    )