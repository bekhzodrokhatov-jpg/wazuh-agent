#!/usr/bin/env python3
"""Fix _send_to_wazuh_queue to use correct Wazuh analysisd message format"""

filepath = '/var/ossec/var/hw_monitor/hw_change_detector.py'
with open(filepath, 'r') as f:
    content = f.read()

# Find and replace _send_to_wazuh_queue function
old_func = '''def _send_to_wazuh_queue(socket_path, alert_data):
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
        print(f"{YELLOW}[!] Queue yozish xatosi: {e}{NC}")'''

new_func = '''def _send_to_wazuh_queue(socket_path, alert_data):
    """Wazuh queue socketiga JSON alert yuborish"""
    import socket as sock_module
    try:
        msg = json.dumps(alert_data, ensure_ascii=False)
        # Wazuh analysisd socket format: <queue>:<location>:<message>
        # queue=1 (LOCALFILE_MQ), location=hw_change_detector
        wazuh_msg = "1:hw_change_detector:" + msg
        
        try:
            s = sock_module.socket(sock_module.AF_UNIX, sock_module.SOCK_DGRAM)
            s.connect(socket_path)
            s.send(wazuh_msg.encode())
            s.close()
        except Exception:
            with open("/tmp/hw_changes_queue.log", "a") as f:
                f.write(msg + "\\n")
    except Exception as e:
        print(f"{YELLOW}[!] Queue yozish xatosi: {e}{NC}")'''

if old_func in content:
    content = content.replace(old_func, new_func)
    with open(filepath, 'w') as f:
        f.write(content)
    print("[OK] _send_to_wazuh_queue fixed with Wazuh message format")
else:
    # Try a more flexible search
    if 'wazuh_msg = "1:hw_change_detector:"' in content:
        print("[OK] _send_to_wazuh_queue already has correct format")
    else:
        # Find the function and replace it line by line
        lines = content.split('\n')
        func_start = -1
        func_end = -1
        for i, line in enumerate(lines):
            if 'def _send_to_wazuh_queue(' in line:
                func_start = i
            elif func_start >= 0 and line and not line.startswith(' ') and not line.startswith('\t') and not line == '' and i > func_start + 1:
                func_end = i
                break
        
        if func_start >= 0:
            if func_end < 0:
                func_end = len(lines)
            
            new_func_lines = [
                'def _send_to_wazuh_queue(socket_path, alert_data):',
                '    """Wazuh queue socketiga JSON alert yuborish"""',
                '    import socket as sock_module',
                '    try:',
                '        msg = json.dumps(alert_data, ensure_ascii=False)',
                '        # Wazuh analysisd socket format: <queue>:<location>:<message>',
                '        wazuh_msg = "1:hw_change_detector:" + msg',
                '        ',
                '        try:',
                '            s = sock_module.socket(sock_module.AF_UNIX, sock_module.SOCK_DGRAM)',
                '            s.connect(socket_path)',
                '            s.send(wazuh_msg.encode())',
                '            s.close()',
                '        except Exception:',
                '            with open("/tmp/hw_changes_queue.log", "a") as f:',
                '                f.write(msg + "\\n")',
                '    except Exception as e:',
                '        print(f"{YELLOW}[!] Queue yozish xatosi: {e}{NC}")',
            ]
            
            lines = lines[:func_start] + new_func_lines + ['', ''] + lines[func_end:]
            content = '\n'.join(lines)
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"[OK] _send_to_wazuh_queue replaced (lines {func_start}-{func_end})")
        else:
            print("[FAIL] Could not find _send_to_wazuh_queue function")

# Also verify the decoder prematch matches the JSON start
# The decoder expects: ^{"scan_type":"hw_change_detection"
# But the message sent via socket will be prefixed with "1:hw_change_detector:"
# Wazuh strips the header, so analysisd sees the raw JSON after location

# Verify syntax
import py_compile
try:
    py_compile.compile(filepath, doraise=True)
    print("[OK] Syntax check PASSED")
except py_compile.PyCompileError as e:
    print(f"[FAIL] Syntax check FAILED: {e}")

# Also verify ossec.conf has correct rule_ids
ossec_path = '/var/ossec/etc/ossec.conf'
with open(ossec_path, 'r') as f:
    oc = f.read()
if '100201' in oc:
    print("[OK] ossec.conf has 100201")
else:
    print("[WARN] ossec.conf missing 100201")
