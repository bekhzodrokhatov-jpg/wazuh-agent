#!/usr/bin/env python3
"""Run hw_change_detector --test and capture output"""
import subprocess, sys

result = subprocess.run(
    [sys.executable, '/var/ossec/var/hw_monitor/hw_change_detector.py', '--test'],
    capture_output=True, text=True, timeout=30
)

output = f"RC={result.returncode}\n---STDOUT---\n{result.stdout}\n---STDERR---\n{result.stderr}\n"
print(output)
with open('/tmp/test_output.txt', 'w') as f:
    f.write(output)
