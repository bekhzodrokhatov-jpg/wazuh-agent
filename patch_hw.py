#!/usr/bin/env python3
filepath = '/var/ossec/var/hw_monitor/hw_change_detector.py'
with open(filepath, 'r') as f:
    lines = f.readlines()
insert_after = 444
except_lines = ['    except Exception as e:\n', '        print("Alert yozish xatosi: " + str(e))\n']
new_lines = lines[:insert_after] + except_lines + lines[insert_after:]
with open(filepath, 'w') as f:
    f.writelines(new_lines)
print('Patch applied. New total lines:', len(new_lines))
import py_compile
try:
    py_compile.compile(filepath, doraise=True)
    print('SYNTAX CHECK: OK')
except py_compile.PyCompileError as e:
    print('SYNTAX CHECK FAILED:', str(e))
