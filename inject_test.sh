#!/bin/bash
# Inject a test log through wazuh-logtest to verify decoder/rule matching
# Then directly trigger integration by writing to the queue socket

TESTLOG='{"scan_type":"hw_fraud_detection","verdict":"TAMPERED","hostname":"BEKHZOD","cpu":{"real_cpuid":"Intel(R) Core(TM) i5-9400 CPU","reported_registry":"Intel(R) Core(TM) i3-9400 CPU"},"ram":{"real_smbios_gb":16},"gpu":{"description":"NVIDIA GeForce GTX 1650"},"system":{"manufacturer":"Default string","product":"Default string","board_serial":"Default string"}}'

echo "=== LOGTEST ==="
echo "$TESTLOG" | /var/ossec/bin/wazuh-logtest 2>&1 | head -30

echo ""
echo "=== INJECT VIA QUEUE ==="
# Use the ossec queue socket to inject the log as if from agent 003
/var/ossec/bin/wazuh-logtest -U "003:command_hw_fraud_detection" <<< "$TESTLOG" 2>&1 | head -20

echo ""
echo "=== DIRECT SEND TO ANALYSISD ==="
# Write directly to analysisd queue
echo "1:command_hw_fraud_detection:$TESTLOG" > /var/ossec/queue/sockets/queue 2>&1
echo "Queue write result: $?"

sleep 5
echo ""
echo "=== CHECK NEW ALERTS ==="
grep 100101 /var/ossec/logs/alerts/alerts.json | tail -2 | cut -c1-80

echo ""
echo "=== CHECK TG LOG ==="
cat /tmp/telegram.log 2>/dev/null

echo ""
echo "=== CHECK INTEGRATION ERRORS ==="
grep -i "error\|telegram" /var/ossec/logs/ossec.log | tail -5
