#!/usr/bin/env python3
"""Combined patch for hw_change_detector.py"""
filepath = '/var/ossec/var/hw_monitor/hw_change_detector.py'

with open(filepath, 'r') as f:
    lines = f.readlines()

print('Original total lines:', len(lines))

# Check if except is already there after line 444
needs_except = True
for i in range(443, min(448, len(lines))):
    if 'except Exception' in lines[i]:
        needs_except = False
        break

if needs_except:
    # Find the line with _mark_alerts_sent inside _send_alerts
    insert_idx = None
    for i in range(len(lines)):
        if '        _mark_alerts_sent(conn, changes)' in lines[i]:
            # Check next lines - if no except follows
            found_except = False
            for j in range(i+1, min(i+4, len(lines))):
                if 'except' in lines[j]:
                    found_except = True
                    break
                if lines[j].strip() and not lines[j].strip().startswith('#') and not lines[j] == '\n':
                    if 'def ' in lines[j]:
                        break
            if not found_except:
                insert_idx = i + 1
                break
    
    if insert_idx:
        except_lines = ['    except Exception as e:\n', '        print("Alert yozish xatosi: " + str(e))\n']
        lines = lines[:insert_idx] + except_lines + lines[insert_idx:]
        print('Patch 1: Added except block after line', insert_idx)
    else:
        print('Patch 1: Could not find insertion point')
else:
    print('Patch 1: except block already exists, skipping')

# Patch 2: Fix _send_alerts(changes) -> _send_alerts(conn, changes) in _run_test
content = ''.join(lines)
old = '        _send_alerts(changes)'
new = '        _send_alerts(conn, changes)'
if old in content:
    content = content.replace(old, new)
    print('Patch 2: Fixed _send_alerts(changes) -> _send_alerts(conn, changes)')
else:
    print('Patch 2: Already fixed or not found')

with open(filepath, 'w') as f:
    f.write(content)

print('Total lines after patch:', len(content.splitlines()))

import py_compile
try:
    py_compile.compile(filepath, doraise=True)
    print('SYNTAX CHECK: OK')
except py_compile.PyCompileError as e:
    print('SYNTAX CHECK FAILED:', str(e))
