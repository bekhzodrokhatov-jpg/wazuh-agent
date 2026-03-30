#!/usr/bin/env python3
"""Comprehensive fix: decoders, ossec.conf, and hw_change_detector.py"""
import os
import py_compile

results = []

# ===== 1. Fix hw_detector_decoder.xml =====
hw_detector_decoder = '''<decoder name="hw_detector">
  <prematch>^{"scan_type":"hw_fraud_detection"</prematch>
</decoder>

<decoder name="hw_detector_fields">
  <parent>hw_detector</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
'''
path1 = '/var/ossec/etc/decoders/hw_detector_decoder.xml'
with open(path1, 'w') as f:
    f.write(hw_detector_decoder)
results.append(f"[OK] Fixed {path1}")

# ===== 2. Fix hw_change_decoder.xml =====
hw_change_decoder = '''<decoder name="hw_change_json">
  <prematch>^{"scan_type":"hw_change_detection"</prematch>
</decoder>

<decoder name="hw_change_json_fields">
  <parent>hw_change_json</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
'''
path2 = '/var/ossec/etc/decoders/hw_change_decoder.xml'
with open(path2, 'w') as f:
    f.write(hw_change_decoder)
results.append(f"[OK] Fixed {path2}")

# ===== 3. Fix ossec.conf rule_ids for Telegram integration =====
ossec_path = '/var/ossec/etc/ossec.conf'
with open(ossec_path, 'r') as f:
    ossec_content = f.read()

# Check if rule_ids already include all required Telegram rules
required_rule_ids = ['100101', '100103', '100112', '100201', '100202']
if all(rid in ossec_content for rid in required_rule_ids):
    results.append("[OK] ossec.conf already has rule_ids 100101, 100103, 100112, 100201, 100202")
else:
    # Replace the rule_id line - find <rule_id>100101</rule_id>
    old_rule = '<rule_id>100101</rule_id>'
    new_rule = '<rule_id>100101, 100103, 100112, 100201, 100202</rule_id>'
    if old_rule in ossec_content:
        ossec_content = ossec_content.replace(old_rule, new_rule)
        with open(ossec_path, 'w') as f:
            f.write(ossec_content)
        results.append("[OK] ossec.conf updated with rule_ids 100101, 100103, 100112, 100201, 100202")
    else:
        # Try to find any rule_id line in integrations section
        import re
        pattern = r'<rule_id>[^<]*</rule_id>'
        matches = re.findall(pattern, ossec_content)
        results.append(f"[INFO] ossec.conf rule_id entries: {matches}")
        # Force add the rule_ids by finding custom-telegram section
        if 'custom-telegram' in ossec_content:
            # Find the integration block and update it
            pattern2 = r'(<integration>\s*<name>custom-telegram</name>.*?<rule_id>)([^<]*)(</rule_id>)'
            match = re.search(pattern2, ossec_content, re.DOTALL)
            if match:
                current_ids = match.group(2)
                merged = []
                for rid in [x.strip() for x in current_ids.split(',') if x.strip()] + required_rule_ids:
                    if rid not in merged:
                        merged.append(rid)
                new_ids = ', '.join(merged)
                if new_ids != current_ids.strip():
                    ossec_content = ossec_content[:match.start(2)] + new_ids + ossec_content[match.end(2):]
                    with open(ossec_path, 'w') as f:
                        f.write(ossec_content)
                    results.append(f"[OK] ossec.conf rule_id updated: {new_ids}")
                else:
                    results.append("[OK] ossec.conf already has required Telegram rule_ids")
            else:
                results.append("[WARN] Could not find rule_id in custom-telegram block")
        else:
            results.append("[WARN] custom-telegram not found in ossec.conf")

# ===== 4. Fix hw_change_detector.py - ensure except block exists =====
hw_py_path = '/var/ossec/var/hw_monitor/hw_change_detector.py'
with open(hw_py_path, 'r') as f:
    lines = f.readlines()

# Find the _send_alerts function and check for proper try/except
fixed_hw = False
for i, line in enumerate(lines):
    if 'def _send_alerts(' in line:
        # Found the function, now look for the try and make sure there's except
        # Search forward for the try block
        for j in range(i+1, min(i+40, len(lines))):
            if lines[j].strip() == 'try:' and lines[j].startswith('    try:'):
                # This is the main try in _send_alerts. Find the matching except
                # Look for next function def or except at the same indent level
                found_except = False
                for k in range(j+1, min(j+60, len(lines))):
                    stripped = lines[k].strip()
                    if stripped.startswith('except') and lines[k].startswith('    except'):
                        found_except = True
                        break
                    if lines[k].startswith('def ') and not lines[k].startswith('    '):
                        # Hit next top-level function without finding except
                        break
                
                if not found_except:
                    # Insert except block before the next 'def' line
                    # Find the insertion point - after _mark_alerts_sent line
                    for k in range(j+1, min(j+60, len(lines))):
                        if '_mark_alerts_sent' in lines[k]:
                            insert_pos = k + 1
                            except_block = [
                                '    except Exception as e:\n',
                                '        print("[XATO] Alert yuborishda xatolik: " + str(e))\n',
                            ]
                            lines = lines[:insert_pos] + except_block + lines[insert_pos:]
                            fixed_hw = True
                            results.append(f"[OK] Added except block after line {insert_pos}")
                            break
                    break
                else:
                    results.append("[OK] hw_change_detector.py already has except block in _send_alerts")
                break
        break

if fixed_hw:
    with open(hw_py_path, 'w') as f:
        f.writelines(lines)

# Verify syntax
try:
    py_compile.compile(hw_py_path, doraise=True)
    results.append(f"[OK] {hw_py_path} syntax check PASSED")
except py_compile.PyCompileError as e:
    results.append(f"[FAIL] {hw_py_path} syntax check FAILED: {e}")

# ===== 5. Also fix _run_test to pass conn argument =====
with open(hw_py_path, 'r') as f:
    content = f.read()

if '_send_alerts(changes)' in content:
    content = content.replace('_send_alerts(changes)', '_send_alerts(conn, changes)')
    with open(hw_py_path, 'w') as f:
        f.write(content)
    results.append("[OK] Fixed _send_alerts(changes) -> _send_alerts(conn, changes) in _run_test")
    # Verify again
    try:
        py_compile.compile(hw_py_path, doraise=True)
        results.append(f"[OK] Final syntax check PASSED")
    except py_compile.PyCompileError as e:
        results.append(f"[FAIL] Final syntax check FAILED: {e}")
else:
    results.append("[OK] _send_alerts already has conn argument")

# Write results to file for easy reading
output = '\n'.join(results)
print(output)
with open('/tmp/fix_results.txt', 'w') as f:
    f.write(output + '\n')
