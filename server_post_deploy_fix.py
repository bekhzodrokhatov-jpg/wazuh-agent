#!/usr/bin/env python3
from pathlib import Path

# 1) Normalize integration script line endings
for p in [
    Path('/var/ossec/integrations/custom-telegram'),
    Path('/var/ossec/integrations/custom-hw-validator.py'),
]:
    if p.exists():
        b = p.read_bytes().replace(b'\r\n', b'\n').replace(b'\r', b'\n')
        p.write_bytes(b)
        print('[OK] normalized', p)

# 2) Prevent duplicate Telegram messages by disabling hw_change IDs on custom-hw-validator.py integration block
cfg = Path('/var/ossec/etc/ossec.conf')
text = cfg.read_text(encoding='utf-8', errors='ignore')
needle = '<name>custom-hw-validator.py</name>'
if needle in text:
    start = text.rfind('<integration>', 0, text.find(needle))
    end = text.find('</integration>', text.find(needle))
    if start != -1 and end != -1:
        end += len('</integration>')
        block = text[start:end]
        if '<rule_id>' in block:
            import re
            block2 = re.sub(r'<rule_id>[^<]*</rule_id>', '<rule_id>199999</rule_id>', block)
            text = text[:start] + block2 + text[end:]
            cfg.write_text(text, encoding='utf-8')
            print('[OK] ossec.conf custom-hw-validator rule_id set to 199999')

print('[DONE] server post deploy fix complete')
