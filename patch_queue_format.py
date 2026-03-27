#!/usr/bin/env python3
"""Patch _send_to_wazuh_queue to use Wazuh header format."""
from pathlib import Path
import py_compile

path = Path('/var/ossec/var/hw_monitor/hw_change_detector.py')
text = path.read_text(encoding='utf-8')

old = '''def _send_to_wazuh_queue(socket_path, alert_data):
    """Wazuh queue socketiga JSON alert yuborish"""
    import socket as sock_module
    try:
        # Agent message format: id:command:data
        # Bizning case'da: socket orqali JSON yuborialadi
        msg = json.dumps(alert_data, ensure_ascii=False)

        # Socket orqali yuborish (unix domain socket)
        try:
            s = sock_module.socket(sock_module.AF_UNIX, sock_module.SOCK_DGRAM)
            s.connect(socket_path)
            s.send(msg.encode())
            s.close()
        except Exception:
            # Backup: File orqali yozish (direct)
            with open("/tmp/hw_changes_queue.log", "a") as f:
                f.write(f"{msg}\\n")
    except Exception as e:
        print(f"{YELLOW}[!] Queue yozish xatosi: {e}{NC}")
'''

new = '''def _send_to_wazuh_queue(socket_path, alert_data):
    """Wazuh queue socketiga alert yuborish"""
    import socket as sock_module
    try:
        # Wazuh analysisd format: <queue>:<location>:<message>
        payload = json.dumps(alert_data, ensure_ascii=False)
        msg = f"1:hw_change_detector:{payload}"

        try:
            s = sock_module.socket(sock_module.AF_UNIX, sock_module.SOCK_DGRAM)
            s.connect(socket_path)
            s.send(msg.encode('utf-8'))
            s.close()
        except Exception:
            # Backup: for troubleshooting when queue socket is unavailable
            with open('/tmp/hw_changes_queue.log', 'a', encoding='utf-8') as f:
                f.write(msg + '\\n')
    except Exception as e:
        print(f"{YELLOW}[!] Queue yozish xatosi: {e}{NC}")
'''

if old not in text:
    # Fallback if spacing/comment changed: patch only key lines
    if "msg = json.dumps(alert_data, ensure_ascii=False)" in text:
        text = text.replace(
            "msg = json.dumps(alert_data, ensure_ascii=False)",
            "payload = json.dumps(alert_data, ensure_ascii=False)\\n        msg = f\"1:hw_change_detector:{payload}\"",
            1,
        )
        text = text.replace("s.send(msg.encode())", "s.send(msg.encode('utf-8'))", 1)
    else:
        raise SystemExit('Target block not found; manual patch needed')
else:
    text = text.replace(old, new, 1)

path.write_text(text, encoding='utf-8')
py_compile.compile(str(path), doraise=True)
print('[OK] queue format patch applied and syntax OK')
