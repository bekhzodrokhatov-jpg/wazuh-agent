#!/bin/bash
# Deploy fixed rules and restart Wazuh

echo "=== Deploying fixed rules ==="
cp /tmp/hw_detector_rules.xml /var/ossec/etc/rules/hw_detector_rules.xml
chown root:wazuh /var/ossec/etc/rules/hw_detector_rules.xml
chmod 660 /var/ossec/etc/rules/hw_detector_rules.xml

echo "=== Verifying custom-telegram ==="
ls -la /var/ossec/integrations/custom-telegram
python3 -c "compile(open('/var/ossec/integrations/custom-telegram').read(), 'custom-telegram', 'exec'); print('PYTHON_SYNTAX_OK')"

echo "=== Restarting Wazuh Manager ==="
systemctl restart wazuh-manager
sleep 5

echo "=== Testing rule match ==="
echo '{"scan_type":"hw_fraud_detection","verdict":"TAMPERED","hostname":"TEST","cpu":{"real_cpuid":"i5","reported_registry":"i3"},"ram":{"real_smbios_gb":16},"gpu":{"description":"GTX"},"system":{"manufacturer":"X","product":"Y","board_serial":"Z"}}' | /var/ossec/bin/wazuh-logtest 2>&1 | head -40

echo ""
echo "=== Integration status ==="
grep -i "integrat" /var/ossec/logs/ossec.log | tail -5

echo ""
echo "=== DONE ==="
