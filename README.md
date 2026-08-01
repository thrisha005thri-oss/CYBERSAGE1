# 🛡️ CyberSage 2.0 — AI-Based Autonomous Attack Detector and Resolver

> Built from scratch | VTU Major Project BIC685 | Bangalore Institute of Technology

---

## What CyberSage 2.0 Does

```
1. Reads ALL live Windows Security Event Logs in real time
2. Maps suspicious log patterns to MITRE ATT&CK techniques
3. Explains each attack in plain English (Groq LLaMA)
4. Auto-remediates in parallel (blocks IP, locks account, snapshots)
5. Shows everything in a live Wireshark-style dashboard
6. Runs silently in system tray like Windows Defender
```

---

## 25 Attacks Detected

| # | Attack | MITRE ID | Category |
|---|--------|----------|----------|
| 01 | Brute Force Login | T1110.001 | Access |
| 02 | Password Spray | T1110.003 | Access |
| 03 | Pass-the-Hash | T1550.002 | Access |
| 04 | Credential Dumping | T1003.001 | Access |
| 05 | Unauthorized RDP | T1021.001 | Access |
| 06 | Scheduled Task Persistence | T1053.005 | Persistence |
| 07 | Malicious Service Install | T1543.003 | Persistence |
| 08 | Registry Run Key | T1547.001 | Persistence |
| 09 | Backdoor Admin Account | T1136.001 | Persistence |
| 10 | Startup Folder | T1547.001 | Persistence |
| 11 | Ransomware | T1486 | Malware |
| 12 | Fileless Malware | T1059.001 | Malware |
| 13 | Trojan | T1204 | Malware |
| 14 | Keylogger | T1056.001 | Malware |
| 15 | Cryptominer | T1496 | Malware |
| 16 | Port Scan | T1046 | Network |
| 17 | C2 Beaconing | T1071.001 | Network |
| 18 | DNS Tunneling | T1071.004 | Network |
| 19 | Data Exfiltration | T1048 | Network |
| 20 | Lateral Movement | T1021 | Network |
| 21 | AI Phishing | T1566.002 | AI Attacks |
| 22 | Prompt Injection | T1059 | AI Attacks |
| 23 | Deepfake Audio | T1566 | AI Attacks |
| 24 | Polymorphic Malware | T1027 | AI Attacks |
| 25 | Adversarial ML Input | T1059 | AI Attacks |
| +1 | Defense Evasion (Log Clear) | T1070.001 | Evasion |

---

## Project Structure

```
CyberSage2/
├── agent/
│   └── log_monitor.py          ← Reads Windows Event Logs
├── detector/
│   ├── mitre_engine.py         ← 25 attacks with MITRE mapping + sources
│   └── attack_classifier.py    ← Maps live logs to attack patterns
├── explainer/
│   └── llm_engine.py           ← Groq LLaMA (explanation only)
├── remediation/
│   └── auto_fix.py             ← OS-level auto-remediation
├── dashboard/
│   ├── app.py                  ← Flask + SocketIO backend
│   └── templates/index.html    ← Live log dashboard (attacks in RED)
├── kali_scripts/
│   ├── 01_brute_force.sh       ← Kali attack script
│   └── brute_force_sim.py      ← Python brute force simulator
├── cybersage_agent.py          ← System tray agent
├── main.py                     ← Main pipeline
├── requirements.txt
└── .env                        ← Groq API key
```

---

## Setup

### Step 1: Install dependencies
```powershell
py -m pip install flask flask-socketio flask-cors pywin32 pandas colorama requests python-dotenv pystray pillow
```

### Step 2: Add Groq API key
Edit `.env`:
```
GROQ_API_KEY=your_key_here
```
Get free key at: https://console.groq.com

### Step 3: Run as Administrator

**Terminal 1 — Agent (system tray):**
```powershell
py cybersage_agent.py
```

**Terminal 2 — Dashboard:**
```powershell
py dashboard/app.py
```

**Browser:**
```
http://localhost:5000
```

---

## Test with Kali Linux

From Kali VM:
```bash
python3 ~/brute_force_sim.py
```

Within 30 seconds on Windows:
- Popup alert appears
- Dashboard shows attack logs in RED
- Remediation executes automatically
- Forensic evidence saved to `dataset/forensic/`

---

## Remediation Sources

Every remediation step in `detector/mitre_engine.py` is sourced from:
- MITRE ATT&CK Framework — https://attack.mitre.org
- NIST SP 800-61 Rev 2 — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
- CISA Incident Response Guides — https://www.cisa.gov
- Microsoft Security Documentation — https://learn.microsoft.com/en-us/security
- NSA Cybersecurity Technical Reports — https://media.defense.gov

---

## How to Answer HOD Questions

**Q: How do you test it?**
> We simulate real attacks using Kali Linux in an isolated VirtualBox lab environment. Kali generates actual Windows Event Logs which CyberSage reads in real time.

**Q: How do you know the remediation is correct?**
> Every remediation step is sourced from MITRE ATT&CK official mitigations, NIST SP 800-61 incident response guide, and CISA advisories — the same standards used by enterprise security teams. Sources are cited per attack in `detector/mitre_engine.py`.

**Q: Is it really AI?**
> Yes. Groq LLaMA 3.3 (70B parameter model) explains attacks in plain English. Detection uses an expert system AI (rule-based pattern matching). Together they form a hybrid AI system.

**Q: What makes it original?**
> We built our own detection rules, our own MITRE mappings, our own remediation playbooks, and our own attack dataset from real Kali tests. No existing tool was copied.
