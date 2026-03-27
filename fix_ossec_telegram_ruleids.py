#!/usr/bin/env python3
from pathlib import Path
import re

cfg = Path('/var/ossec/etc/ossec.conf')
text = cfg.read_text(encoding='utf-8', errors='ignore')

wanted = ['100101', '100103', '100112', '100201', '100202']

for name in ['custom-telegram', 'custom-hw-validator.py']:
    pattern = rf'(<integration>\s*<name>{re.escape(name)}</name>.*?<rule_id>)([^<]*)(</rule_id>)'
    m = re.search(pattern, text, re.DOTALL)
    if not m:
        continue
    ids = [x.strip() for x in m.group(2).split(',') if x.strip()]
    if name == 'custom-hw-validator.py':
        new_ids = '199999'
    else:
        merged = []
        for item in ids + wanted:
            if item and item not in merged:
                merged.append(item)
        new_ids = ', '.join(merged)
    text = text[:m.start(2)] + new_ids + text[m.end(2):]

cfg.write_text(text, encoding='utf-8')
print('[OK] updated ossec.conf integration rule_ids')
