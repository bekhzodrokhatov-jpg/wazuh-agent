#!/usr/bin/env python3
"""Check all fix results"""
import subprocess

# Read queue fix status
checks = []

# Check 1: decoder files
with open('/var/ossec/etc/decoders/hw_detector_decoder.xml') as f:
    d1 = f.read()
if 'JSON_Decoder' in d1 and '<type>' not in d1:
    checks.append("[OK] hw_detector_decoder.xml - uses JSON_Decoder")
else:
    checks.append("[FAIL] hw_detector_decoder.xml - still has old format")

with open('/var/ossec/etc/decoders/hw_change_decoder.xml') as f:
    d2 = f.read()
if 'JSON_Decoder' in d2 and '<type>' not in d2:
    checks.append("[OK] hw_change_decoder.xml - uses JSON_Decoder")
else:
    checks.append("[FAIL] hw_change_decoder.xml - still has old format")

# Check 2: ossec.conf
with open('/var/ossec/etc/ossec.conf') as f:
    oc = f.read()
if '100201' in oc and '100202' in oc:
    checks.append("[OK] ossec.conf has rule_ids 100201, 100202")
else:
    checks.append("[FAIL] ossec.conf missing 100201/100202")

# Check 3: hw_change_detector.py wazuh queue format
with open('/var/ossec/var/hw_monitor/hw_change_detector.py') as f:
    hw = f.read()
if '1:hw_change_detector:' in hw:
    checks.append("[OK] _send_to_wazuh_queue uses correct format")
else:
    checks.append("[FAIL] _send_to_wazuh_queue missing wazuh header format")

if 'except Exception as e:' in hw and '_mark_alerts_sent' in hw:
    checks.append("[OK] _send_alerts has except block")
else:
    checks.append("[FAIL] _send_alerts missing except block")

# Check 4: Syntax
import py_compile
try:
    py_compile.compile('/var/ossec/var/hw_monitor/hw_change_detector.py', doraise=True)
    checks.append("[OK] hw_change_detector.py syntax OK")
except py_compile.PyCompileError as e:
    checks.append(f"[FAIL] Syntax error: {e}")

# Check 5: Wazuh manager status
result = subprocess.run(['systemctl', 'is-active', 'wazuh-manager'], capture_output=True, text=True)
status = result.stdout.strip()
checks.append(f"[{'OK' if status == 'active' else 'FAIL'}] wazuh-manager: {status}")

output = '\n'.join(checks)
print(output)
with open('/tmp/check_results.txt', 'w') as f:
    f.write(output + '\n')
