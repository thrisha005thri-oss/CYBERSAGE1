# ═══════════════════════════════════════════════════════
# CyberSage 2.0 — MITRE ATT&CK Engine
#
# 25 attacks + 1 bonus (defense evasion).
# Each entry has:
#   detection_rule  — what log pattern triggers this
#   mitre_id        — official MITRE technique ID
#   plain_english   — simple explanation for non-experts
#   remediation     — step-by-step fix
#   sources         — exact URLs used to author each fix
# ═══════════════════════════════════════════════════════

ATTACKS = {

    # ════════════════════════════════════════
    # CATEGORY 1 — ACCESS ATTACKS (01–05)
    # ════════════════════════════════════════

    "BRUTE_FORCE": {
        "id": "01", "name": "Brute Force Login Attack",
        "category": "Access",
        "mitre_id": "T1110.001", "mitre_tactic": "Credential Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/001/",
        "severity": "HIGH", "risk": 85,
        "event_ids": [4625], "threshold": 5,
        "detection_rule": "5+ Event 4625 (failed login) within 60 s from same source",
        "plain_english": (
            "Someone is rapidly trying many different passwords on your account — "
            "like trying every key on a keychain to open one lock. "
            "CyberSage detected {count} failed login attempts in a short window, "
            "which is the signature of automated password guessing."
        ),
        "remediation": [
            "Block the attacking IP immediately in Windows Firewall: "
            "netsh advfirewall firewall add rule name='Block_Attacker' dir=in action=block remoteip=<IP>",
            "Lock the targeted account: net user <username> /active:no",
            "Enable account lockout policy — lock after 5 failures for 30 min: "
            "net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30",
            "Force a password reset for the targeted account: net user <username> *",
            "Enable Multi-Factor Authentication (MFA) so passwords alone are never enough",
            "Review all recent SUCCESSFUL logins (Event 4624) from the same IP — "
            "check if any attempt succeeded before CyberSage blocked it",
            "Create a system restore point: Checkpoint-Computer -Description 'PreAttack'",
        ],
        "sources": [
            "MITRE ATT&CK T1110.001 — https://attack.mitre.org/techniques/T1110/001/",
            "NIST SP 800-63B Digital Identity Guidelines §5.2.2 — https://pages.nist.gov/800-63-3/sp800-63b.html",
            "CISA Alert AA21-321A Ransomware — https://www.cisa.gov/uscert/ncas/alerts/aa21-321a",
            "Microsoft Security Baselines — Account Lockout Policy — "
            "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-policy",
        ],
        "principle": "Attackers need unlimited attempts. Remove that and brute force fails.",
    },

    "PASSWORD_SPRAY": {
        "id": "02", "name": "Password Spray Attack",
        "category": "Access",
        "mitre_id": "T1110.003", "mitre_tactic": "Credential Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/003/",
        "severity": "HIGH", "risk": 80,
        "event_ids": [4625], "threshold": 3,
        "detection_rule": "Event 4625 failures spread across 3+ distinct accounts in 5 min",
        "plain_english": (
            "Instead of hammering one account with many passwords (which causes lockout), "
            "the attacker tried one common password across many accounts. "
            "CyberSage detected the spreading pattern — {count} accounts targeted — "
            "which is the hallmark of a password spray attack."
        ),
        "remediation": [
            "Lock all accounts that received failed login attempts",
            "Block the source IP: netsh advfirewall firewall add rule name='SprayBlock' dir=in action=block remoteip=<IP>",
            "Enforce a banned-password list — reject common passwords like Password123",
            "Enable MFA across all accounts so stolen passwords become useless",
            "Audit all targeted accounts for successful logins that preceded the block",
            "Deploy conditional access policies to block logins from unexpected locations",
        ],
        "sources": [
            "MITRE ATT&CK T1110.003 — https://attack.mitre.org/techniques/T1110/003/",
            "Microsoft: Detect and Remediate Password Spray — "
            "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/",
            "CISA: Password Spray — "
            "https://www.cisa.gov/sites/default/files/publications/19-06-132-Password-Spray-Cheat-Sheet.pdf",
        ],
        "principle": "Detect the spread across accounts, not depth on one. Lock all affected accounts.",
    },

    "PASS_THE_HASH": {
        "id": "03", "name": "Pass-the-Hash Attack",
        "category": "Access",
        "mitre_id": "T1550.002", "mitre_tactic": "Lateral Movement",
        "mitre_url": "https://attack.mitre.org/techniques/T1550/002/",
        "severity": "CRITICAL", "risk": 95,
        "event_ids": [4624], "threshold": 1,
        "detection_rule": "Event 4624 Logon Type 3 (network) from unexpected source with NTLM auth",
        "plain_english": (
            "The attacker stole the hashed (scrambled) version of a password "
            "and is using it to authenticate without knowing the real password — "
            "like making a wax impression of a key and using it to open the lock. "
            "Forcing a password reset invalidates the stolen hash immediately."
        ),
        "remediation": [
            "Force password reset for all potentially compromised accounts: net user <username> *",
            "Block the source IP performing hash-based authentication",
            "Disable NTLM authentication where Kerberos is available: "
            "Set GPO Network Security — Restrict NTLM to 'Deny All'",
            "Enable Windows Defender Credential Guard to protect hashes in memory",
            "Audit all network logons (Logon Type 3) for anomalous source machines",
            "Deploy Microsoft LAPS (Local Administrator Password Solution) for unique local admin passwords",
            "Save forensic snapshot before making any changes",
        ],
        "sources": [
            "MITRE ATT&CK T1550.002 — https://attack.mitre.org/techniques/T1550/002/",
            "Microsoft: Mitigating Pass-the-Hash — "
            "https://www.microsoft.com/en-us/download/details.aspx?id=36036",
            "NSA: Credential Theft Defense — "
            "https://media.defense.gov/2022/Oct/04/2003083025/-1/-1/0/NSA_CSI_BEST_PRACTICES_PASS_THE_HASH.PDF",
        ],
        "principle": "A stolen hash becomes worthless the moment the real password changes.",
    },

    "CREDENTIAL_DUMPING": {
        "id": "04", "name": "Credential Dumping",
        "category": "Access",
        "mitre_id": "T1003.001", "mitre_tactic": "Credential Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1003/001/",
        "severity": "CRITICAL", "risk": 95,
        "event_ids": [4656, 4663], "threshold": 1,
        "detection_rule": "Event 4656 (handle request) on LSASS by unexpected process",
        "plain_english": (
            "The attacker accessed the system process (LSASS) where Windows stores "
            "all active passwords in memory. Tools like Mimikatz do this to steal "
            "every credential at once. The damage to memory is already done — "
            "the response is mass invalidation of everything that was there."
        ),
        "remediation": [
            "Reset passwords for ALL accounts on this machine immediately",
            "Enable Windows Defender Credential Guard — prevents LSASS memory access: "
            "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure",
            "Kill the process that accessed LSASS if still running",
            "Isolate the machine from the network to prevent lateral movement with stolen credentials",
            "Enable Protected Users Security Group for all privileged accounts",
            "Audit all network activity from this machine in the last 24 hours for lateral movement",
            "Preserve memory dump for forensics before rebooting",
        ],
        "sources": [
            "MITRE ATT&CK T1003.001 — https://attack.mitre.org/techniques/T1003/001/",
            "Microsoft Credential Guard — "
            "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure",
            "NIST SP 800-61 Rev 2 §3.3 Eradication — "
            "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf",
        ],
        "principle": "Memory is already read. Only response is mass credential invalidation.",
    },

    "UNAUTHORIZED_RDP": {
        "id": "05", "name": "Unauthorized RDP Access",
        "category": "Access",
        "mitre_id": "T1021.001", "mitre_tactic": "Lateral Movement",
        "mitre_url": "https://attack.mitre.org/techniques/T1021/001/",
        "severity": "HIGH", "risk": 85,
        "event_ids": [4624], "threshold": 1,
        "detection_rule": "Event 4624 Logon Type 10 (RemoteInteractive) from unrecognized IP",
        "plain_english": (
            "Someone is remotely controlling your computer via RDP (Remote Desktop) "
            "from an IP address not on the approved list. "
            "This gives the attacker full visual and keyboard access — "
            "they can see your screen and control your computer in real time."
        ),
        "remediation": [
            "Block the source IP in Windows Firewall immediately",
            "Disable RDP: reg add 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 1 /f",
            "Terminate the active RDP session: query session, then logoff <session_id>",
            "Whitelist only approved IPs for RDP access using firewall rules",
            "Require Network Level Authentication (NLA): gpedit.msc > Require NLA",
            "Move RDP to a non-default port and require VPN connection before RDP is reachable",
            "Enable RDP session logging for full audit trail",
        ],
        "sources": [
            "MITRE ATT&CK T1021.001 — https://attack.mitre.org/techniques/T1021/001/",
            "CISA: Securing Remote Desktop Protocol — "
            "https://www.cisa.gov/sites/default/files/publications/CISA_MS-ISAC_RDP_Security_Guide.pdf",
            "Microsoft: RDP Security — "
            "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/",
        ],
        "principle": "Unexpected remote access is either misconfiguration or attack. Block first.",
    },

    # ════════════════════════════════════════
    # CATEGORY 2 — PERSISTENCE (06–10)
    # ════════════════════════════════════════

    "SCHEDULED_TASK": {
        "id": "06", "name": "Scheduled Task Persistence",
        "category": "Persistence",
        "mitre_id": "T1053.005", "mitre_tactic": "Persistence",
        "mitre_url": "https://attack.mitre.org/techniques/T1053/005/",
        "severity": "MEDIUM", "risk": 75,
        "event_ids": [4698], "threshold": 1,
        "detection_rule": "Event 4698 (scheduled task created) by unexpected process/account",
        "plain_english": (
            "A scheduled task was created that will run code automatically "
            "at set times — even after every reboot. "
            "Attackers use this so their malicious code keeps running "
            "without needing to stay connected. "
            "Think of it as setting an alarm that runs their code forever."
        ),
        "remediation": [
            "Disable the task immediately: schtasks /change /tn '<task_name>' /disable",
            "Create system snapshot BEFORE removing anything (preserve evidence): "
            "Checkpoint-Computer -Description 'Evidence_TaskAttack'",
            "Scan the task's executable: run through antivirus before deleting",
            "Delete the task if confirmed malicious: schtasks /delete /tn '<task_name>' /f",
            "Audit all scheduled tasks: schtasks /query /fo LIST /v | more",
            "Review who created it: check Event 4698 details for Subject Account Name",
        ],
        "sources": [
            "MITRE ATT&CK T1053.005 — https://attack.mitre.org/techniques/T1053/005/",
            "NIST SP 800-61 Rev 2 Eradication Phase — "
            "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf",
            "Microsoft: Scheduled Task Security — "
            "https://learn.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler",
        ],
        "principle": "Removing the registration removes the persistence entirely.",
    },

    "NEW_SERVICE": {
        "id": "07", "name": "Malicious Service Installation",
        "category": "Persistence",
        "mitre_id": "T1543.003", "mitre_tactic": "Persistence",
        "mitre_url": "https://attack.mitre.org/techniques/T1543/003/",
        "severity": "HIGH", "risk": 80,
        "event_ids": [7045], "threshold": 1,
        "detection_rule": "Event 7045 (new service installed) outside of known software install windows",
        "plain_english": (
            "A new Windows service was installed. Services run with high privilege "
            "and start automatically at every boot — making them the most powerful "
            "persistence mechanism. Attackers disguise malware as services to ensure "
            "it survives reboots and runs with system-level authority."
        ),
        "remediation": [
            "Stop the service immediately: sc stop '<service_name>'",
            "Disable it: sc config '<service_name>' start= disabled",
            "Verify the service binary digital signature",
            "Scan the binary with antivirus and VirusTotal (https://www.virustotal.com)",
            "Delete if malicious: sc delete '<service_name>'",
            "Audit all services: sc query type= all | findstr SERVICE_NAME",
            "Check service account — services should not run as SYSTEM unnecessarily",
        ],
        "sources": [
            "MITRE ATT&CK T1543.003 — https://attack.mitre.org/techniques/T1543/003/",
            "CIS Control 4: Controlled Use of Admin Privileges — https://www.cisecurity.org/controls/",
            "Microsoft: Service Security — "
            "https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights",
        ],
        "principle": "Stop + disable removes both the running threat and the persistence.",
    },

    "REGISTRY_RUN_KEY": {
        "id": "08", "name": "Registry Run Key Persistence",
        "category": "Persistence",
        "mitre_id": "T1547.001", "mitre_tactic": "Persistence",
        "mitre_url": "https://attack.mitre.org/techniques/T1547/001/",
        "severity": "HIGH", "risk": 80,
        "event_ids": [4657], "threshold": 1,
        "detection_rule": "Event 4657 (registry value modified) in HKLM/HKCU Run keys",
        "plain_english": (
            "The Windows registry startup keys were modified. "
            "The registry has a list of programs that run automatically when Windows starts — "
            "attackers add their malware to this list so it runs every time anyone logs in. "
            "This is one of the simplest and most common persistence techniques."
        ),
        "remediation": [
            "Open Registry Editor: regedit",
            "Check HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run — remove unauthorized entries",
            "Check HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run — same check",
            "Check RunOnce keys too: same path with RunOnce at the end",
            "Use Sysinternals Autoruns to see ALL autostart locations: "
            "https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
            "Scan all executables referenced in the run keys with antivirus",
            "Re-check after reboot — some malware restores the key",
        ],
        "sources": [
            "MITRE ATT&CK T1547.001 — https://attack.mitre.org/techniques/T1547/001/",
            "Microsoft Sysinternals Autoruns — https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns",
            "SANS: Registry Persistence Mechanisms — "
            "https://www.sans.org/blog/sans-dfir-summary-windows-registry-persistence-mechanisms/",
        ],
        "principle": "Removing the run key entry removes the autostart and the persistence.",
    },

    "NEW_ADMIN_USER": {
        "id": "09", "name": "Backdoor Admin Account Created",
        "category": "Persistence",
        "mitre_id": "T1136.001", "mitre_tactic": "Persistence",
        "mitre_url": "https://attack.mitre.org/techniques/T1136/001/",
        "severity": "CRITICAL", "risk": 95,
        "event_ids": [4720, 4732], "threshold": 1,
        "detection_rule": "Event 4720 (account created) within 60 s of Event 4732 (added to Administrators)",
        "plain_english": (
            "A new user account was created and immediately added to the Administrators group. "
            "This is a backdoor — the attacker now has their own admin account "
            "and can log back in anytime in the future, even if you change other passwords. "
            "This is the most durable form of persistent access."
        ),
        "remediation": [
            "Disable the backdoor account immediately: net user <backdoor_username> /active:no",
            "Remove from Administrators: net localgroup administrators <username> /delete",
            "Audit the full admin group: net localgroup administrators",
            "Review who created this account — check Event 4720 Subject field",
            "Delete if confirmed unauthorized: net user <username> /delete",
            "Set alert for any future Event 4720 (account creation)",
        ],
        "sources": [
            "MITRE ATT&CK T1136.001 — https://attack.mitre.org/techniques/T1136/001/",
            "NIST SP 800-53 AC-2: Account Management — "
            "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
            "CIS Control 5: Account Management — https://www.cisecurity.org/controls/",
        ],
        "principle": "An unauthorized admin account is non-negotiable to remove.",
    },

    "STARTUP_FOLDER": {
        "id": "10", "name": "Startup Folder Persistence",
        "category": "Persistence",
        "mitre_id": "T1547.001", "mitre_tactic": "Persistence",
        "mitre_url": "https://attack.mitre.org/techniques/T1547/001/",
        "severity": "MEDIUM", "risk": 70,
        "event_ids": [4663], "threshold": 1,
        "detection_rule": "Event 4663 (file write) to Windows Startup folder paths",
        "plain_english": (
            "A file was written to the Windows Startup folder. "
            "Anything placed there runs automatically when any user logs in — "
            "no registry edits, no services needed. "
            "Just drop a file and it runs on every login."
        ),
        "remediation": [
            "Find the unauthorized startup file in: "
            "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            "Also check system-wide: C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            "Scan the file with antivirus before removing",
            "Take system snapshot first: Checkpoint-Computer -Description 'Startup_Evidence'",
            "Remove the unauthorized file",
            "Monitor startup folders for future unauthorized writes using a file integrity monitor",
        ],
        "sources": [
            "MITRE ATT&CK T1547.001 — https://attack.mitre.org/techniques/T1547/001/",
            "Microsoft: Startup Folder — "
            "https://support.microsoft.com/en-us/windows/add-an-app-to-run-automatically-at-startup-in-windows-10",
            "SANS: Windows Persistence — https://www.sans.org/blog/",
        ],
        "principle": "Removing the file from the startup folder is the complete fix.",
    },

    # ════════════════════════════════════════
    # CATEGORY 3 — MALWARE (11–15)
    # ════════════════════════════════════════

    "RANSOMWARE": {
        "id": "11", "name": "Ransomware",
        "category": "Malware",
        "mitre_id": "T1486", "mitre_tactic": "Impact",
        "mitre_url": "https://attack.mitre.org/techniques/T1486/",
        "severity": "CRITICAL", "risk": 100,
        "event_ids": [4663], "threshold": 100,
        "detection_rule": "100+ Event 4663 (file access) in 30 s — mass encryption pattern",
        "plain_english": (
            "Ransomware is actively encrypting your files right now. "
            "CyberSage detected {count} rapid file modifications — "
            "the signature of ransomware encrypting everything it can reach. "
            "Every second matters. Stop the process before more files are locked."
        ),
        "remediation": [
            "IMMEDIATELY disconnect from the network — pull ethernet and disable WiFi",
            "Do NOT reboot — rebooting may trigger deletion of shadow copies",
            "Identify the ransomware process via Task Manager (look for CPU spike)",
            "Kill the process: taskkill /F /PID <pid>",
            "Check if Volume Shadow Copies still exist: vssadmin list shadows",
            "If shadows exist, restore from them: right-click file > Previous Versions",
            "If shadows deleted, restore from offline backup — this is your only recovery path",
            "Report to CISA if critical infrastructure: https://www.cisa.gov/stopransomware",
        ],
        "sources": [
            "MITRE ATT&CK T1486 — https://attack.mitre.org/techniques/T1486/",
            "CISA: Ransomware Guide — https://www.cisa.gov/stopransomware",
            "FBI: Ransomware Prevention — https://www.ic3.gov/Media/PDF/AnnualReport/2021_IC3Report.pdf",
            "Microsoft: Ransomware Response — "
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-ransomware",
        ],
        "principle": "Stop encryption now. Only recovery path is clean backup.",
    },

    "FILELESS_MALWARE": {
        "id": "12", "name": "Fileless Malware",
        "category": "Malware",
        "mitre_id": "T1059.001", "mitre_tactic": "Execution",
        "mitre_url": "https://attack.mitre.org/techniques/T1059/001/",
        "severity": "HIGH", "risk": 90,
        "event_ids": [4688], "threshold": 1,
        "detection_rule": "Event 4688 showing PowerShell/cmd with encoded or suspicious command line",
        "plain_english": (
            "Malicious code is running entirely in memory — no file was written to disk. "
            "This bypasses antivirus software which can only scan files. "
            "The attack used PowerShell or command prompt to run code "
            "that lives only in RAM. The only handle we have is the running process."
        ),
        "remediation": [
            "Kill the malicious PowerShell/cmd process: taskkill /F /PID <pid>",
            "Block the process network connections in Windows Firewall",
            "Enable PowerShell Script Block Logging: "
            "Set-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1",
            "Restrict PowerShell execution policy: Set-ExecutionPolicy AllSigned",
            "Disable PowerShell v2 (no AMSI protection): "
            "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root",
            "Enable AMSI logging to catch future in-memory code execution",
        ],
        "sources": [
            "MITRE ATT&CK T1059.001 — https://attack.mitre.org/techniques/T1059/001/",
            "Microsoft: PowerShell Security — "
            "https://learn.microsoft.com/en-us/powershell/scripting/security/preventing-script-injection",
            "SANS: Fileless Malware — https://www.sans.org/reading-room/whitepapers/malicious/fileless-malware-beyond-run-keys-37893",
        ],
        "principle": "No file to delete. Kill the process — that is the only handle.",
    },

    "TROJAN": {
        "id": "13", "name": "Trojan / Malicious Process",
        "category": "Malware",
        "mitre_id": "T1204", "mitre_tactic": "Execution",
        "mitre_url": "https://attack.mitre.org/techniques/T1204/",
        "severity": "HIGH", "risk": 85,
        "event_ids": [4688, 5156], "threshold": 1,
        "detection_rule": "Event 4688 (process created) with unexpected Event 5156 outbound connections",
        "plain_english": (
            "A process is behaving in a way that doesn't match what it claims to be — "
            "making network connections it has no reason to make. "
            "Classic trojan behavior: legitimate-looking software hiding malicious activity. "
            "CyberSage detected unexpected outbound connections from a suspicious process."
        ),
        "remediation": [
            "Kill the process immediately: taskkill /F /PID <pid>",
            "Block its outbound connection: netsh advfirewall firewall add rule "
            "name='BlockTrojan' dir=out action=block program='<path>'",
            "Quarantine the executable — copy to safe location, do not run",
            "Upload to VirusTotal for multi-engine scan: https://www.virustotal.com",
            "Investigate where the file came from — downloads, email, USB",
            "Review all network connections the process made for data theft",
        ],
        "sources": [
            "MITRE ATT&CK T1204 — https://attack.mitre.org/techniques/T1204/",
            "VirusTotal — https://www.virustotal.com",
            "NIST SP 800-83: Malware Incident Prevention — "
            "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-83.pdf",
        ],
        "principle": "Kill based on behavior (unexpected network connections) not just name.",
    },

    "KEYLOGGER": {
        "id": "14", "name": "Keylogger",
        "category": "Malware",
        "mitre_id": "T1056.001", "mitre_tactic": "Collection",
        "mitre_url": "https://attack.mitre.org/techniques/T1056/001/",
        "severity": "HIGH", "risk": 88,
        "event_ids": [4688], "threshold": 1,
        "detection_rule": "Event 4688 (process created) with SetWindowsHookEx keyboard hook pattern",
        "plain_english": (
            "A process installed a keyboard hook — it is recording every key you press, "
            "including passwords, credit card numbers, and private messages. "
            "Everything typed since this process started is in the attacker's hands. "
            "All credentials typed on this machine must be treated as compromised."
        ),
        "remediation": [
            "Kill the keylogger process immediately: taskkill /F /PID <pid>",
            "Treat ALL passwords typed on this machine as stolen",
            "Reset every password from a DIFFERENT, CLEAN device",
            "Alert your bank if financial details were typed recently",
            "Scan the full system for related components — keyloggers often have droppers",
            "Review outbound network connections — logged keys are sent somewhere",
            "Reformat and reinstall the OS if full compromise is suspected",
        ],
        "sources": [
            "MITRE ATT&CK T1056.001 — https://attack.mitre.org/techniques/T1056/001/",
            "NIST SP 800-83: Malware Incident Prevention — "
            "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-83.pdf",
            "CISA: Malware — https://www.cisa.gov/malware",
        ],
        "principle": "Everything typed must be treated as stolen and reset.",
    },

    "CRYPTOMINER": {
        "id": "15", "name": "Cryptominer / Resource Hijacking",
        "category": "Malware",
        "mitre_id": "T1496", "mitre_tactic": "Impact",
        "mitre_url": "https://attack.mitre.org/techniques/T1496/",
        "severity": "MEDIUM", "risk": 65,
        "event_ids": [4688, 5156], "threshold": 1,
        "detection_rule": "Event 4688 (new process) + sustained high CPU + Event 5156 to mining pool IPs",
        "plain_english": (
            "Malware is using your computer's processing power to mine cryptocurrency "
            "for the attacker. Your computer slows down, electricity bills rise, "
            "and the attacker profits silently. "
            "The damage is resource theft — but the process may also be a cover for other activity."
        ),
        "remediation": [
            "Kill the mining process — look for unusually high CPU in Task Manager",
            "Block outbound connections to mining pool destinations in Firewall",
            "Scan the miner executable with antivirus",
            "Find how it was installed — check recent downloads, scripts, browser extensions",
            "Remove all scheduled tasks or registry entries that restart the miner",
            "Recheck after reboot — miners often have persistence mechanisms",
        ],
        "sources": [
            "MITRE ATT&CK T1496 — https://attack.mitre.org/techniques/T1496/",
            "CISA: Cryptomining Malware — https://www.cisa.gov/news-events/alerts",
            "Microsoft Defender: Coin Miners — "
            "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/",
        ],
        "principle": "Kill the process and block the mining destination.",
    },

    # ════════════════════════════════════════
    # CATEGORY 4 — NETWORK ATTACKS (16–20)
    # ════════════════════════════════════════

    "PORT_SCAN": {
        "id": "16", "name": "Port Scan / Reconnaissance",
        "category": "Network",
        "mitre_id": "T1046", "mitre_tactic": "Discovery",
        "mitre_url": "https://attack.mitre.org/techniques/T1046/",
        "severity": "MEDIUM", "risk": 60,
        "event_ids": [5156], "threshold": 20,
        "detection_rule": "20+ Event 5156 from single source to different destination ports in 30 s",
        "plain_english": (
            "Someone is probing your system to find open ports — "
            "like trying every door and window of a building to find unlocked ones. "
            "This is reconnaissance, not an attack yet — "
            "but it means an attack is being planned. Block now before they act."
        ),
        "remediation": [
            "Block the scanning source IP: netsh advfirewall firewall add rule "
            "name='BlockScanner' dir=in action=block remoteip=<IP>",
            "Enable Windows Firewall stealth mode — do not respond to probes",
            "Review and close unnecessary open ports: netstat -an | findstr LISTENING",
            "Audit which services actually need to be internet-accessible",
            "Set an alert — port scanning almost always precedes a targeted attack",
            "Check threat intelligence feeds for whether this IP is a known scanner",
        ],
        "sources": [
            "MITRE ATT&CK T1046 — https://attack.mitre.org/techniques/T1046/",
            "NIST SP 800-115: Technical Guide to Security Testing — "
            "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf",
            "CIS Control 9: Limitation of Network Ports — https://www.cisecurity.org/controls/",
        ],
        "principle": "Block the scanner before they act on what they learn.",
    },

    "C2_BEACONING": {
        "id": "17", "name": "Command and Control Beaconing",
        "category": "Network",
        "mitre_id": "T1071.001", "mitre_tactic": "Command and Control",
        "mitre_url": "https://attack.mitre.org/techniques/T1071/001/",
        "severity": "CRITICAL", "risk": 95,
        "event_ids": [5156], "threshold": 5,
        "detection_rule": "5+ Event 5156 from same process to same destination at regular intervals",
        "plain_english": (
            "A process on your system is regularly checking in with an attacker server — "
            "like an employee secretly sending reports to a spy every few minutes. "
            "Active C2 means the attacker has a foothold and is maintaining "
            "remote control of your machine right now."
        ),
        "remediation": [
            "Block the C2 destination IP in Windows Firewall immediately",
            "Kill the process making the beaconing connections: taskkill /F /PID <pid>",
            "Isolate the host from the network — the attacker may issue new commands any moment",
            "Perform full forensic analysis — active C2 means other damage may have occurred",
            "Check for lateral movement to other machines on the network from this host",
            "Identify the initial compromise vector — how did the implant get installed?",
            "Preserve memory dump before rebooting",
        ],
        "sources": [
            "MITRE ATT&CK T1071.001 — https://attack.mitre.org/techniques/T1071/001/",
            "CISA AA22-321A — https://www.cisa.gov/uscert/ncas/alerts/aa22-321a",
            "NIST SP 800-61 Rev 2 — "
            "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf",
        ],
        "principle": "Active C2 means the attacker still has control. Break that channel first.",
    },

    "DNS_TUNNELING": {
        "id": "18", "name": "DNS Tunneling",
        "category": "Network",
        "mitre_id": "T1071.004", "mitre_tactic": "Command and Control",
        "mitre_url": "https://attack.mitre.org/techniques/T1071/004/",
        "severity": "HIGH", "risk": 85,
        "event_ids": [5156], "threshold": 1,
        "detection_rule": "High volume of DNS queries with unusual subdomain length and entropy patterns",
        "plain_english": (
            "The attacker is hiding data inside DNS requests — "
            "the protocol your computer uses to look up website addresses. "
            "DNS is usually not inspected by firewalls, making it an ideal covert channel. "
            "Data is smuggled out (or commands smuggled in) disguised as normal DNS lookups."
        ),
        "remediation": [
            "Block the affected process from making external DNS queries",
            "Force all DNS through a monitored internal DNS resolver",
            "Flush DNS cache: ipconfig /flushdns",
            "Enable DNS query logging to identify what was tunneled",
            "Deploy DNS Security (DNSSEC) and DNS filtering/monitoring",
            "Block access to known DNS tunneling services using threat intel",
        ],
        "sources": [
            "MITRE ATT&CK T1071.004 — https://attack.mitre.org/techniques/T1071/004/",
            "CISA: DNS Infrastructure Tampering — "
            "https://www.cisa.gov/news-events/alerts/2019/01/24/dns-infrastructure-tampering",
            "Cisco: DNS Security — https://www.cisco.com/c/en/us/products/security/",
        ],
        "principle": "Block source and flush DNS. Data is being smuggled through a trusted channel.",
    },

    "DATA_EXFILTRATION": {
        "id": "19", "name": "Data Exfiltration",
        "category": "Network",
        "mitre_id": "T1048", "mitre_tactic": "Exfiltration",
        "mitre_url": "https://attack.mitre.org/techniques/T1048/",
        "severity": "CRITICAL", "risk": 98,
        "event_ids": [5156, 4663], "threshold": 1,
        "detection_rule": "Unusually large outbound data volume from unexpected process to external IP",
        "plain_english": (
            "Sensitive data is being sent out of your network right now. "
            "This is often the final goal of an intrusion. "
            "The attacker has been inside your network and is now taking what they came for. "
            "Every second of delay means more data leaves your control."
        ),
        "remediation": [
            "IMMEDIATELY isolate the host — disconnect from all networks",
            "Block the destination IP at the perimeter firewall",
            "Kill the process performing the exfiltration",
            "Identify what data was accessed and transferred — check file access logs (Event 4663)",
            "Notify your Data Protection Officer — legal obligations may apply (GDPR Art 33)",
            "Preserve all evidence before doing anything else — do not wipe the system",
            "Check whether data was encrypted before exfiltration (harder to recover from)",
        ],
        "sources": [
            "MITRE ATT&CK T1048 — https://attack.mitre.org/techniques/T1048/",
            "GDPR Article 33: Breach Notification — https://gdpr.eu/article-33-notification/",
            "NIST SP 800-61 Rev 2 — "
            "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf",
        ],
        "principle": "Immediate isolation is the only way to stop data leaving in real time.",
    },

    "LATERAL_MOVEMENT": {
        "id": "20", "name": "Lateral Movement",
        "category": "Network",
        "mitre_id": "T1021", "mitre_tactic": "Lateral Movement",
        "mitre_url": "https://attack.mitre.org/techniques/T1021/",
        "severity": "CRITICAL", "risk": 95,
        "event_ids": [4624], "threshold": 3,
        "detection_rule": "Event 4624 showing one host authenticating to 3+ different internal machines",
        "plain_english": (
            "After compromising one machine, the attacker is moving to other computers "
            "on the same network — like a burglar who breaks into one room "
            "then tries every other door in the building. "
            "The compromised machine is being used as a launchpad to reach other systems."
        ),
        "remediation": [
            "Isolate the compromised source machine from the network immediately",
            "Reset credentials for all accounts used in the lateral movement connections",
            "Audit every machine that was reached — each may also be compromised",
            "Block the compromised machine's credentials at the domain controller",
            "Review Event 4624 logs across the network for all affected machines",
            "Implement network segmentation to limit future lateral movement paths",
        ],
        "sources": [
            "MITRE ATT&CK T1021 — https://attack.mitre.org/techniques/T1021/",
            "NSA: Network Infrastructure Security Guide — "
            "https://media.defense.gov/2022/Jun/15/2003018261/-1/-1/0/CTR_NSA_NETWORK_INFRASTRUCTURE_SECURITY_GUIDE_20220615.PDF",
            "NIST SP 800-61 Rev 2 — "
            "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf",
        ],
        "principle": "Isolate the source machine to stop the spread before the attacker pivots further.",
    },

    # ════════════════════════════════════════
    # CATEGORY 5 — AI ATTACKS (21–25)
    # ════════════════════════════════════════

    "AI_PHISHING": {
        "id": "21", "name": "AI-Generated Phishing",
        "category": "AI Attacks",
        "mitre_id": "T1566.002", "mitre_tactic": "Initial Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1566/002/",
        "severity": "HIGH", "risk": 80,
        "event_ids": [], "threshold": 1,
        "detection_rule": "Message content: urgency language + credential request + impersonation markers",
        "plain_english": (
            "A highly convincing phishing message was detected, likely written by AI — "
            "making it more grammatically perfect and persuasive than traditional phishing. "
            "The response is the same regardless of whether AI or a human wrote it: "
            "block the sender and warn the targeted person immediately."
        ),
        "remediation": [
            "Block the sender email address and domain in your mail gateway",
            "Quarantine the message before the user can click any links",
            "Alert the targeted user and explain why it is suspicious",
            "Check if the user clicked any links or entered credentials on a suspicious page",
            "Reset credentials if they were entered on any linked page",
            "Implement email authentication: SPF, DKIM, and DMARC records",
            "Run phishing awareness training — focus on AI-generated message patterns",
        ],
        "sources": [
            "MITRE ATT&CK T1566.002 — https://attack.mitre.org/techniques/T1566/002/",
            "CISA: Phishing Guidance — https://www.cisa.gov/phishing",
            "Google: Email Authentication — https://support.google.com/a/answer/10539635",
        ],
        "principle": "Block the sender and alert the user. AI authorship does not change the response.",
    },

    "PROMPT_INJECTION": {
        "id": "22", "name": "Prompt Injection",
        "category": "AI Attacks",
        "mitre_id": "T1059", "mitre_tactic": "Execution",
        "mitre_url": "https://attack.mitre.org/techniques/T1059/",
        "severity": "HIGH", "risk": 85,
        "event_ids": [], "threshold": 1,
        "detection_rule": "Input to AI system matches role-override or jailbreak instruction patterns",
        "plain_english": (
            "Someone tried to manipulate CyberSage's AI into ignoring its instructions — "
            "like telling a security guard 'forget your training, I'm your real boss.' "
            "The malicious input was intercepted before it reached any AI model. "
            "This attack targets the AI itself, not the operating system."
        ),
        "remediation": [
            "Block the malicious input at the application input layer",
            "Add the detected patterns to the input validation blocklist",
            "Log the injection attempt for security team review",
            "Strengthen input sanitization — strip instruction-override patterns",
            "Implement LLM guardrails and output validation",
            "Rate-limit requests from the source IP to prevent repeated attempts",
        ],
        "sources": [
            "OWASP: LLM01 Prompt Injection — "
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "MITRE ATLAS AML.T0051 — https://atlas.mitre.org/techniques/AML.T0051",
            "NIST AI RMF — https://www.nist.gov/system/files/documents/2023/01/26/NIST.AI.100-1.pdf",
        ],
        "principle": "Block before it reaches any model. No AI input should be trusted without validation.",
    },

    "DEEPFAKE_AUDIO": {
        "id": "23", "name": "Deepfake Audio Social Engineering",
        "category": "AI Attacks",
        "mitre_id": "T1566", "mitre_tactic": "Initial Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1566/",
        "severity": "HIGH", "risk": 82,
        "event_ids": [4663], "threshold": 1,
        "detection_rule": "Audio file with social engineering filename received via suspicious channel",
        "plain_english": (
            "A suspicious audio file was detected — possibly AI-cloned voice "
            "impersonating an executive or authority figure. "
            "Deepfake audio tricks people into transferring money or sharing credentials. "
            "CyberSage cannot automatically verify audio authenticity — "
            "a human must confirm via a separate, trusted channel."
        ),
        "remediation": [
            "Quarantine the suspicious audio file — do not play it on the target system",
            "Alert the person who was targeted by the message",
            "Verify the supposed sender's identity via a SEPARATE channel "
            "(call them directly on a known phone number — not the one in the message)",
            "Never act on audio-only instructions involving money or credentials without in-person confirmation",
            "Submit the audio to a deepfake detection service for analysis",
            "Report to your security team for forensic investigation",
        ],
        "sources": [
            "MITRE ATT&CK T1566 — https://attack.mitre.org/techniques/T1566/",
            "FTC: Voice Cloning Fraud — https://consumer.ftc.gov/articles/what-know-about-family-emergency-scams",
            "CISA: Social Engineering — https://www.cisa.gov/social-engineering",
        ],
        "principle": "Audio authenticity needs human verification. Quarantine and verify via separate channel.",
    },

    "POLYMORPHIC_MALWARE": {
        "id": "24", "name": "Polymorphic / Signature-Evading Malware",
        "category": "AI Attacks",
        "mitre_id": "T1027", "mitre_tactic": "Defense Evasion",
        "mitre_url": "https://attack.mitre.org/techniques/T1027/",
        "severity": "HIGH", "risk": 88,
        "event_ids": [4688, 5156], "threshold": 1,
        "detection_rule": "Process with anomalous behavior + no antivirus signature match + unexpected network connections",
        "plain_english": (
            "Malware that rewrites its own code every time it runs to evade antivirus. "
            "Traditional antivirus compares files against a database of known threats — "
            "but if the code changes with every execution, no signature matches. "
            "CyberSage detects this by what the malware DOES, not what it looks like."
        ),
        "remediation": [
            "Kill the process based on its behavior — not its file hash or name",
            "Block all network connections from that process in Firewall",
            "Quarantine the executable for behavioral sandboxed analysis",
            "Submit to sandboxed analysis: Any.run (https://any.run) or Hybrid Analysis (https://www.hybrid-analysis.com)",
            "Switch to behavior-based endpoint detection with cloud protection enabled",
            "Search for all copies — polymorphic malware often replicates itself",
        ],
        "sources": [
            "MITRE ATT&CK T1027 — https://attack.mitre.org/techniques/T1027/",
            "Any.run Sandbox — https://any.run",
            "Hybrid Analysis Sandbox — https://www.hybrid-analysis.com",
            "Microsoft: Behavior Monitoring — "
            "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/",
        ],
        "principle": "Signature matching fails by design here. Detect and block based on behavior only.",
    },

    "ADVERSARIAL_INPUT": {
        "id": "25", "name": "Adversarial ML Attack",
        "category": "AI Attacks",
        "mitre_id": "T1059", "mitre_tactic": "Defense Evasion",
        "mitre_url": "https://attack.mitre.org/techniques/T1059/",
        "severity": "HIGH", "risk": 87,
        "event_ids": [], "threshold": 1,
        "detection_rule": "Input anomalous vs expected distribution but classifier confidence is low",
        "plain_english": (
            "An input was crafted specifically to fool CyberSage's detection model "
            "into classifying an attack as normal activity. "
            "This is an attack against the AI detector itself — "
            "the attacker knows how the system works and is trying to blind it. "
            "When confidence is low but behavior is anomalous, block first and investigate."
        ),
        "remediation": [
            "Block the anomalous input regardless of the model's low-confidence classification",
            "Log the full input for analysis and future model retraining",
            "Flag for human security analyst review — do not rely on the AI alone here",
            "Add the adversarial example to the training dataset to harden detection",
            "Implement input feature range validation to reject out-of-distribution samples",
            "Require multiple detection methods to agree before clearing suspicious inputs",
        ],
        "sources": [
            "MITRE ATLAS: Adversarial ML — https://atlas.mitre.org",
            "NIST: Adversarial Machine Learning — "
            "https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-2e2023.pdf",
            "OWASP: ML Security Top 10 — https://mltop10.info",
        ],
        "principle": "Low confidence + anomalous behavior = block and investigate. Never trust the model alone.",
    },

    # ════════════════════════════════════════
    # BONUS — DEFENSE EVASION (log tampering)
    # ════════════════════════════════════════

    "DEFENSE_EVASION": {
        "id": "26", "name": "Defense Evasion — Log Cleared",
        "category": "Defense Evasion",
        "mitre_id": "T1070.001", "mitre_tactic": "Defense Evasion",
        "mitre_url": "https://attack.mitre.org/techniques/T1070/001/",
        "severity": "CRITICAL", "risk": 98,
        "event_ids": [1102], "threshold": 1,
        "detection_rule": "Event 1102 (security audit log cleared) — log records its own deletion",
        "plain_english": (
            "The Security audit log was cleared. "
            "This is almost always done by an attacker destroying evidence of what they did. "
            "The fact that CyberSage caught it means the log recorded its own deletion "
            "before being cleared — a rare window of visibility. "
            "Treat this as an active intruder on the system right now."
        ),
        "remediation": [
            "CRITICAL: Treat as active intrusion — isolate immediately",
            "Set up Windows Event Forwarding NOW before logs are cleared again: "
            "https://learn.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection",
            "Check SIEM or remote log server for events captured before deletion",
            "Identify WHO cleared the log — check Event 1102 Subject Account Name",
            "Do NOT restore/wipe system before forensic investigation is complete",
            "Assume all activity since last known-clean backup is suspicious",
        ],
        "sources": [
            "MITRE ATT&CK T1070.001 — https://attack.mitre.org/techniques/T1070/001/",
            "NIST SP 800-92: Computer Security Log Management — "
            "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf",
            "Microsoft: Windows Event Forwarding — "
            "https://learn.microsoft.com/en-us/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection",
        ],
        "principle": "Log clearing = active intruder destroying evidence. Isolate immediately.",
    },
}


def get_attack(name):
    return ATTACKS.get(name)

def get_all():
    return ATTACKS

def mitre_summary():
    return {k: f"{v['mitre_id']} — {v['mitre_tactic']}" for k, v in ATTACKS.items()}
