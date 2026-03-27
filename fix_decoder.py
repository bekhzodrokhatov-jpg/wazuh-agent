#!/usr/bin/env python3
"""Fix hw_detector_decoder.xml - remove invalid <type>json</type>"""

# Fix hw_detector_decoder.xml
hw_detector_decoder = """<decoder name="hw_detector">
  <prematch>^{"scan_type":"hw_fraud_detection"</prematch>
</decoder>

<decoder name="hw_detector_fields">
  <parent>hw_detector</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
"""

filepath = '/var/ossec/etc/decoders/hw_detector_decoder.xml'
with open(filepath, 'w') as f:
    f.write(hw_detector_decoder)
print(f"[OK] {filepath} fixed")

# Also fix hw_change_decoder.xml
hw_change_decoder = """<decoder name="hw_change_json">
  <prematch>^{"scan_type":"hw_change_detection"</prematch>
</decoder>

<decoder name="hw_change_json_fields">
  <parent>hw_change_json</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
"""

filepath2 = '/var/ossec/etc/decoders/hw_change_decoder.xml'
with open(filepath2, 'w') as f:
    f.write(hw_change_decoder)
print(f"[OK] {filepath2} fixed")

# Verify ossec.conf has correct rule_ids
ossec_path = '/var/ossec/etc/ossec.conf'
with open(ossec_path, 'r') as f:
    content = f.read()

if '100201' in content and '100202' in content:
    print("[OK] ossec.conf has rule_ids 100201, 100202")
else:
    print("[WARN] ossec.conf missing rule_ids 100201/100202")

# Check hw_change_detector.py syntax
import py_compile
hw_py = '/var/ossec/var/hw_monitor/hw_change_detector.py'
try:
    py_compile.compile(hw_py, doraise=True)
    print(f"[OK] {hw_py} syntax OK")
except py_compile.PyCompileError as e:
    print(f"[FAIL] {hw_py} syntax error: {e}")

print("\n[DONE] All fixes applied")
