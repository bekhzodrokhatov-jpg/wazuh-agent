#!/usr/bin/env python3
"""Restart wazuh-manager and write status to /tmp/restart_status.txt"""
import subprocess
import time

result = subprocess.run(['systemctl', 'restart', 'wazuh-manager'], 
                       capture_output=True, text=True, timeout=120)

time.sleep(3)

status = subprocess.run(['systemctl', 'is-active', 'wazuh-manager'],
                       capture_output=True, text=True)

output = []
output.append(f"RESTART_RC={result.returncode}")
output.append(f"STDOUT={result.stdout.strip()}")
output.append(f"STDERR={result.stderr.strip()}")
output.append(f"STATUS={status.stdout.strip()}")

if status.stdout.strip() == 'active':
    output.append("RESULT=SUCCESS")
else:
    # Get journal logs
    journal = subprocess.run(
        ['journalctl', '-u', 'wazuh-manager', '-n', '10', '--no-pager'],
        capture_output=True, text=True)
    output.append(f"JOURNAL={journal.stdout}")
    output.append("RESULT=FAILED")

text = '\n'.join(output)
print(text)
with open('/tmp/restart_status.txt', 'w') as f:
    f.write(text + '\n')
