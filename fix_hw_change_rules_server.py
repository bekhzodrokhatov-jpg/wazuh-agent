#!/usr/bin/env python3
from pathlib import Path

rules = '''<group name="hw_changes,">
  <rule id="100200" level="5">
    <decoded_as>json</decoded_as>
    <field name="scan_type">^hw_change_detection$</field>
    <description>Hardware change event detected.</description>
    <group>hw_detector, hw_changes</group>
  </rule>

  <rule id="100201" level="11">
    <if_sid>100200</if_sid>
    <field name="change_type">^REPLACED$</field>
    <description>HARDWARE REPLACED: Critical component changed (CPU/RAM)!</description>
    <group>hw_detector, hw_changes</group>
  </rule>

  <rule id="100202" level="10">
    <if_sid>100200</if_sid>
    <field name="change_type">^(REMOVED|ADDED)$</field>
    <description>HARDWARE ADDED/REMOVED: Component was added or removed.</description>
    <group>hw_detector, hw_changes</group>
  </rule>

  <rule id="100203" level="4">
    <if_sid>100200</if_sid>
    <field name="change_type">^MODIFIED$</field>
    <description>Hardware component modified (minor change).</description>
    <group>hw_detector, hw_changes</group>
  </rule>
</group>
'''

p = Path('/var/ossec/etc/rules/hw_change_rules.xml')
p.write_text(rules, encoding='utf-8')
print('[OK] wrote', p)
print(p.read_text(encoding='utf-8'))
