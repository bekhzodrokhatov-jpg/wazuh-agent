#!/usr/bin/env python3
"""Repair broken queue-format patch and enforce valid send logic."""
from pathlib import Path
import py_compile

path = Path('/var/ossec/var/hw_monitor/hw_change_detector.py')
lines = path.read_text(encoding='utf-8').splitlines()

out = []
for line in lines:
    # Fix broken one-line insertion with literal \n sequence
    if 'payload = json.dumps(alert_data, ensure_ascii=False)\\n        msg = f"1:hw_change_detector:{payload}"' in line:
        indent = line[: len(line) - len(line.lstrip())]
        out.append(indent + 'payload = json.dumps(alert_data, ensure_ascii=False)')
        out.append(indent + 'msg = f"1:hw_change_detector:{payload}"')
        continue

    # Also normalize old raw-json line if present
    if line.strip() == 'msg = json.dumps(alert_data, ensure_ascii=False)':
        indent = line[: len(line) - len(line.lstrip())]
        out.append(indent + 'payload = json.dumps(alert_data, ensure_ascii=False)')
        out.append(indent + 'msg = f"1:hw_change_detector:{payload}"')
        continue

    # Ensure utf-8 explicit encoding
    if line.strip() == 's.send(msg.encode())':
        indent = line[: len(line) - len(line.lstrip())]
        out.append(indent + "s.send(msg.encode('utf-8'))")
        continue

    out.append(line)

path.write_text('\n'.join(out) + '\n', encoding='utf-8')
py_compile.compile(str(path), doraise=True)
print('[OK] Repaired queue format and syntax')
