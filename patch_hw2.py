#!/usr/bin/env python3
filepath = '/var/ossec/var/hw_monitor/hw_change_detector.py'
with open(filepath, 'r') as f:
    content = f.read()

# Fix _send_alerts(changes) -> _send_alerts(conn, changes) in _run_test
content = content.replace('        _send_alerts(changes)', '        _send_alerts(conn, changes)')

with open(filepath, 'w') as f:
    f.write(content)

print('Patch 2 applied: _send_alerts(conn, changes)')
import py_compile
try:
    py_compile.compile(filepath, doraise=True)
    print('SYNTAX CHECK: OK')
except py_compile.PyCompileError as e:
    print('SYNTAX CHECK FAILED:', str(e))
