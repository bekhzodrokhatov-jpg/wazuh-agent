#!/bin/bash
set -e
MSG='1:command_hw_detector_run:hw_detector: {"scan_type":"hw_fraud_detection","verdict":"TAMPERED","tampered":true,"registry_tampered":false,"agent":{"name":"BEKHZOD"}}'
printf '%s
' "$MSG" > /var/ossec/queue/sockets/queue
sleep 3
grep -a 100101 /var/ossec/logs/alerts/alerts.json | tail -n 2
