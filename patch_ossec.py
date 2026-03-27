#!/usr/bin/env python3
"""Add hw_change alert rule_ids to Telegram integration in ossec.conf"""
filepath = '/var/ossec/etc/ossec.conf'

with open(filepath, 'r') as f:
    content = f.read()

# Check if 100201 already in integration
if '100201' in content:
    print('Rule IDs 100201/100202 already in ossec.conf')
else:
    # Find existing custom-telegram integration and update rule_id to include hw rules
    old = '<rule_id>100101</rule_id>'
    new = '<rule_id>100101, 100201, 100202</rule_id>'
    if old in content:
        content = content.replace(old, new)
        with open(filepath, 'w') as f:
            f.write(content)
        print('Updated rule_id to include 100201, 100202')
    else:
        print('Could not find existing rule_id line')

# Verify
with open(filepath, 'r') as f:
    for line in f:
        if 'custom-telegram' in line or '100201' in line or 'rule_id' in line:
            print(line.strip())
