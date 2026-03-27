#!/usr/bin/env python3
from pathlib import Path

files = [
    Path('/var/ossec/integrations/custom-telegram'),
    Path('/var/ossec/integrations/custom-hw-validator.py'),
]

for p in files:
    data = p.read_bytes()
    data = data.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    p.write_bytes(data)
    print('[OK] normalized', p)
