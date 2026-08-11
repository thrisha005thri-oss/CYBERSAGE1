import os
import requests
from colorama import Fore, Style, init
init(autoreset=True)

# ═══════════════════════════════════════════════════════════════
# CyberSage — LLM Engine
# Primary: Groq LLaMA 3.3 (free + fast)
# Fallback: Google Gemini (free + reliable)
# Always works — never blocks network!
# ═══════════════════════════════════════════════════════════════

GROQ_URL    = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL  = "llama-3.3-70b-versatile"
GEMINI_URL  = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"


def _get_env(key):
    try:
        env_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            ".env"
        )
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(f"{key}="):
                        val = line.split("=", 1)[1].strip()
                        if val and val != "your_key_here":
                            return val
    except:
        pass
    return os.environ.get(key, "")


def _build_prompt(attack, count):
    name    = attack.get("name", "Unknown Attack")
    mitre   = attack.get("mitre_id", "")
    risk    = attack.get("risk", 0)
    tactic  = attack.get("mitre_tactic", "")
    ip      = attack.get("attacker_ip", "unknown")
    acct    = attack.get("target_account", "unknown")

    return (
        f"You are CyberSage, an AI cybersecurity assistant. "
        f"Explain this Windows cyberattack to a NON-TECHNICAL person "
        f"in 3-4 simple sentences. No jargon. Be clear and calm.\n\n"
        f"Attack: {name}\n"
        f"MITRE Technique: {mitre} — {tactic}\n"
        f"Risk Level: {risk}/100\n"
        f"Events detected: {count}\n"
        f"Attacker IP: {ip}\n"
        f"Target: {acct}\n\n"
        f"Explain: (1) what the attacker tried to do, "
        f"(2) why it is dangerous, "
        f"(3) that CyberSage automatically blocked and fixed it. "
        f"Keep under 80 words."
    )


def _try_groq(prompt):
    key = _get_env("GROQ_API_KEY")
    if not key:
        return None
    try:
        resp = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type" : "application/json"
            },
            json={
                "model"      : GROQ_MODEL,
                "messages"   : [{"role": "user", "content": prompt}],
                "max_tokens" : 200,
                "temperature": 0.4,
            },
            timeout=8
        )
        if resp.status_code == 200:
            text = resp.json()["choices"][0]["message"]["content"].strip()
            print(f"  {Fore.GREEN}✅ Groq explanation ready{Style.RESET_ALL}")
            return text
        else:
            print(f"  {Fore.YELLOW}⚠️  Groq error {resp.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"  {Fore.YELLOW}⚠️  Groq unavailable: {e}{Style.RESET_ALL}")
    return None


def _try_gemini(prompt):
    key = _get_env("GEMINI_API_KEY")
    if not key:
        return None
    try:
        resp = requests.post(
            f"{GEMINI_URL}?key={key}",
            headers={"Content-Type": "application/json"},
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=8
        )
        if resp.status_code == 200:
            text = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
            print(f"  {Fore.GREEN}✅ Gemini explanation ready{Style.RESET_ALL}")
            return text
        print(f"  {Fore.YELLOW}⚠️  Gemini error {resp.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"  {Fore.YELLOW}⚠️  Gemini unavailable: {e}{Style.RESET_ALL}")
    return None


def _fallback(attack):
    """Built-in explanations when both APIs unavailable"""
    fallbacks = {
        "NEW_ADMIN_USER"  : "An attacker created a secret administrator account to maintain hidden access to your system. This lets them log in anytime even after you think they're gone. CyberSage detected and permanently deleted this backdoor account.",
        "SCHEDULED_TASK"  : "A malicious scheduled task was created to run harmful code automatically at set times — even after reboot. Attackers use this to keep their code running without staying connected. CyberSage deleted the task and removed all associated files.",
        "NEW_SERVICE"     : "A new Windows service was installed to run malicious code with the highest system privileges at every startup. CyberSage stopped, disabled, and permanently deleted this service before it could cause further damage.",
        "DEFENSE_EVASION" : "The Windows Security log was deliberately cleared to destroy evidence of the attack. This is a critical sign of an active intruder covering their tracks. CyberSage immediately restored audit logging and increased log protection.",
        "BRUTE_FORCE"     : "Someone rapidly tried many passwords on your account — like a thief testing every key on a keychain. CyberSage blocked the attacker's IP, locked the targeted account, and enabled lockout policies to prevent future attempts.",
        "PORT_SCAN"       : "An attacker scanned your system looking for open ports and vulnerabilities — the first step before a real attack. CyberSage blocked the scanner immediately and enabled stealth mode to hide your system's ports.",
        "FILELESS_MALWARE": "Malicious code ran entirely in memory, leaving no file for antivirus to find. This bypasses traditional security tools. CyberSage caught it through behavioral monitoring, killed the process, and restricted PowerShell to prevent recurrence.",
        "AI_PHISHING"     : "An AI-generated phishing attack was detected attempting to steal credentials through a convincing fake message. CyberSage quarantined the suspicious content and blocked the sender domain to prevent further attempts.",
    }
    pattern = attack.get("pattern", "")
    return fallbacks.get(
        pattern,
        f"A cyberattack was detected: {attack.get('name', 'Unknown')}. "
        f"Risk level: {attack.get('risk', 0)}/100. "
        f"CyberSage automatically blocked the attack, "
        f"executed deep remediation, and preserved forensic evidence."
    )


def explain_attack(attack, audience="normal"):
    count  = attack.get("count", 0)
    prompt = _build_prompt(attack, count)

    # Try Groq first
    result = _try_groq(prompt)
    if result:
        return result

    # Try Gemini as fallback
    result = _try_gemini(prompt)
    if result:
        return result

    # Use built-in fallback
    print(f"  {Fore.CYAN}ℹ️  Using built-in explanation{Style.RESET_ALL}")
    plain = attack.get("plain_english", "")
    if plain:
        return plain.replace("{count}", str(count))
    return _fallback(attack)