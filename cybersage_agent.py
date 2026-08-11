import threading
import time
import subprocess
import sys
import os
import webbrowser
from datetime import datetime
import pystray
from PIL import Image, ImageDraw

# Windows toast notification
try:
    from winotify import Notification, audio
    TOAST_AVAILABLE = True
except ImportError:
    TOAST_AVAILABLE = False

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from main import run_pipeline

# ═══════════════════════════════════════════════════════════════
# CyberSage 2.0 — System Tray Agent
# Windows toast notification (bottom right, like Defender)
# No full-screen popup — clean and professional
# ═══════════════════════════════════════════════════════════════

PROJECT_DIR       = os.path.dirname(os.path.abspath(__file__))
dashboard_process = None

agent = {
    "running"   : True,
    "scan_count": 0,
    "status"    : "MONITORING"
}

_alert_cooldown        = {}
ALERT_COOLDOWN_SECONDS = 300


def make_shield(color="green"):
    img  = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cols = {"green": (0,200,0), "red": (220,50,50), "orange": (255,165,0)}
    c    = cols.get(color, (0,200,0))
    draw.polygon([(32,4),(60,16),(60,38),(32,62),(4,38),(4,16)], fill=c)
    dark = tuple(max(0, x-60) for x in c)
    draw.polygon([(32,14),(52,24),(52,40),(32,54),(12,40),(12,24)], fill=dark)
    if color == "green":
        draw.line([(22,34),(30,44),(46,24)], fill="white", width=3)
    elif color == "red":
        draw.line([(22,22),(42,42)], fill="white", width=3)
        draw.line([(42,22),(22,42)], fill="white", width=3)
    return img


def open_dashboard():
    global dashboard_process
    def _open():
        global dashboard_process
        try:
            if dashboard_process is None or dashboard_process.poll() is not None:
                dashboard_process = subprocess.Popen(
                    [sys.executable,
                     os.path.join(PROJECT_DIR, "dashboard", "app.py")],
                    cwd=PROJECT_DIR
                )
                time.sleep(3)
            webbrowser.open("http://localhost:5000")
        except Exception as e:
            print(f"Dashboard error: {e}")
    threading.Thread(target=_open, daemon=True).start()


def show_toast_notification(attacks, risk_score):
    """
    Show Windows toast notification (bottom right corner)
    exactly like Microsoft Defender does it.
    No full screen popup — clean, non-intrusive.
    """

    attack_name = attacks[0].get('name', attacks[0].get('pattern', 'Unknown'))
    mitre_id    = attacks[0].get('mitre_id', '')
    count       = len(attacks)

    if count > 1:
        body = f"{count} attacks detected\n{attack_name} + {count-1} more\nMITRE: {mitre_id} | Risk: {risk_score}/100"
    else:
        body = f"{attack_name}\nMITRE: {mitre_id} | Risk: {risk_score}/100\nClick to view details →"

    # Method 1: Try winotify (best Windows toast)
    if TOAST_AVAILABLE:
        try:
            toast = Notification(
                app_id   = "CyberSage 2.0",
                title    = "⚠️ ATTACK DETECTED",
                msg      = body,
                duration = "long",
                icon     = os.path.join(PROJECT_DIR, "shield_icon.png")
                           if os.path.exists(os.path.join(PROJECT_DIR, "shield_icon.png"))
                           else ""
            )
            toast.set_audio(audio.Default, loop=False)
            toast.add_actions(label="View Dashboard",
                            launch="http://localhost:5000")
            toast.show()
            print(f"  🔔 Toast notification sent: {attack_name}")
            return
        except Exception as e:
            print(f"  winotify error: {e}")

    # Method 2: PowerShell toast (built into Windows — no install needed)
    try:
        ps_script = f"""
[Windows.UI.Notifications.ToastNotificationManager,
 Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null
[Windows.UI.Notifications.ToastNotification,
 Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument,
 Windows.Data.Xml.Dom, ContentType=WindowsRuntime] | Out-Null

$template = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>⚠️ CyberSage — Attack Detected</text>
      <text>{attack_name}</text>
      <text>MITRE: {mitre_id} | Risk: {risk_score}/100</text>
    </binding>
  </visual>
  <actions>
    <action content="View Dashboard"
            arguments="http://localhost:5000"
            activationType="protocol"/>
  </actions>
</toast>
"@

$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($template)
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(
    "CyberSage 2.0"
).Show($toast)
"""
        subprocess.Popen(
            ["powershell", "-WindowStyle", "Hidden",
             "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        print(f"  🔔 Windows toast sent: {attack_name}")

    except Exception as e:
        print(f"  PowerShell toast error: {e}")
        # Method 3: Tray balloon (fallback — simplest)
        _show_tray_balloon(attack_name, risk_score)


def _show_tray_balloon(attack_name, risk_score):
    """
    Fallback: show balloon tip via PowerShell
    Still appears in notification area
    """
    try:
        ps = f"""
Add-Type -AssemblyName System.Windows.Forms
$balloon = New-Object System.Windows.Forms.NotifyIcon
$balloon.Icon = [System.Drawing.SystemIcons]::Warning
$balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
$balloon.BalloonTipTitle = "CyberSage — Attack Detected"
$balloon.BalloonTipText = "{attack_name}`nRisk: {risk_score}/100`nClick View Details on dashboard"
$balloon.Visible = $true
$balloon.ShowBalloonTip(10000)
Start-Sleep -Seconds 10
$balloon.Dispose()
"""
        subprocess.Popen(
            ["powershell", "-WindowStyle", "Hidden",
             "-ExecutionPolicy", "Bypass", "-Command", ps],
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        print(f"  🔔 Balloon notification: {attack_name}")
    except Exception as e:
        print(f"  Balloon error: {e}")


def background_scan(tray_icon):
    print("🛡️  Background scanner started — every 30 seconds")
    while agent["running"]:
        try:
            tray_icon.icon  = make_shield("orange")
            tray_icon.title = "CyberSage — Scanning..."

            state = run_pipeline(max_events=4000)
            agent["scan_count"] += 1

            if state and state.get("attacks"):
                attacks    = state["attacks"]
                risk_score = state.get("risk_score", 0)

                tray_icon.icon  = make_shield("red")
                tray_icon.title = f"⚠️ UNDER ATTACK! Risk: {risk_score}/100"

                # Cooldown — only alert once per attack
                new_attacks = []
                now         = datetime.now()
                for atk in attacks:
                    pat          = atk.get("pattern", "UNKNOWN")
                    last_alerted = _alert_cooldown.get(pat)
                    if last_alerted is None or \
                       (now - last_alerted).total_seconds() > ALERT_COOLDOWN_SECONDS:
                        new_attacks.append(atk)
                        _alert_cooldown[pat] = now

                if new_attacks:
                    # Show Windows toast notification (bottom right)
                    show_toast_notification(new_attacks, risk_score)
                else:
                    print(f"  ⏳ Alert cooldown active — no notification")

            else:
                if _alert_cooldown:
                    _alert_cooldown.clear()
                agent["status"] = "MONITORING"
                tray_icon.icon  = make_shield("green")
                tray_icon.title = f"CyberSage — Secure | Scans: {agent['scan_count']}"

        except Exception as e:
            print(f"Scan error: {e}")
            tray_icon.icon  = make_shield("green")
            tray_icon.title = "CyberSage — Monitoring"

        time.sleep(30)


def scan_once(tray_icon):
    try:
        tray_icon.icon  = make_shield("orange")
        state = run_pipeline(max_events=4000)
        if state and state.get("attacks"):
            attacks    = state["attacks"]
            risk_score = state.get("risk_score", 0)
            tray_icon.icon = make_shield("red")
            show_toast_notification(attacks, risk_score)
            now = datetime.now()
            for atk in attacks:
                _alert_cooldown[atk.get("pattern","?")] = now
        else:
            _alert_cooldown.clear()
            tray_icon.icon  = make_shield("green")
            tray_icon.title = "CyberSage — System Clean"
    except Exception as e:
        print(f"Manual scan error: {e}")
        tray_icon.icon = make_shield("green")


def main():
    # Try to install winotify for best toast notifications
    print("=" * 52)
    print("  🛡️  CyberSage 2.0 — AI Cyber Defense Agent")
    print("=" * 52)
    print("  Notification : Windows toast (bottom right)")
    print("  Scans        : Every 30 seconds")
    print("  Dashboard    : http://localhost:5000")
    print("=" * 52)

    # Auto install winotify if not present
    if not TOAST_AVAILABLE:
        print("\n  Installing toast notification library...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install",
                 "winotify", "-q"],
                capture_output=True
            )
            print("  ✅ winotify installed — restart for best notifications")
        except:
            print("  ⚠️  winotify unavailable — using PowerShell toast")

    print()

    icon_img = make_shield("green")

    menu = pystray.Menu(
        pystray.MenuItem("🛡️  CyberSage 2.0", None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(
            "⚡ Scan Now",
            lambda i, _: threading.Thread(
                target=scan_once, args=(i,), daemon=True
            ).start()
        ),
        pystray.MenuItem(
            "📊 Open Dashboard",
            lambda i, _: open_dashboard()
        ),
        pystray.MenuItem(
            "🔔 Reset Alert Cooldowns",
            lambda i, _: [
                _alert_cooldown.clear(),
                print("  🔔 Cooldowns reset")
            ]
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(
            "❌ Exit CyberSage",
            lambda i, _: [
                agent.__setitem__("running", False),
                i.stop()
            ]
        ),
    )

    tray = pystray.Icon(
        name  = "CyberSage2",
        icon  = icon_img,
        title = "CyberSage 2.0 — Starting...",
        menu  = menu,
    )

    threading.Thread(
        target=background_scan,
        args=(tray,),
        daemon=True
    ).start()

    print("✅ CyberSage 2.0 running!")
    print("   → Shield icon in system tray (bottom-right)")
    print("   → Right-click shield for options")
    print("   → Attack alerts appear as Windows notifications\n")

    tray.run()


if __name__ == "__main__":
    main()