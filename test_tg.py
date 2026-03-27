#!/usr/bin/env python3
import requests
import json
import sys

TOKEN = "8083742152:AAEYW0mAB_Mq_wFdm_SuBiMcj5TfSHztYmY"
CHAT_ID = "-1003744477260"

# 1) Direct API test
print("=== DIRECT API TEST ===")
try:
    r = requests.post(
        f"https://api.telegram.org/bot{TOKEN}/sendMessage",
        json={"chat_id": CHAT_ID, "text": "Direct test from Wazuh server"}
    )
    print(f"Status: {r.status_code}")
    print(f"Response: {r.text[:300]}")
except Exception as e:
    print(f"Error: {e}")

# 2) Test with alert file
print("\n=== ALERT FILE TEST ===")
alert_file = "/tmp/test-alert.json"
try:
    with open(alert_file, 'r') as f:
        content = f.read()
    print(f"File size: {len(content)} bytes")
    alert = json.loads(content)
    print(f"Rule ID: {alert.get('rule',{}).get('id')}")
    print(f"Agent: {alert.get('agent',{}).get('name')}")
    data = alert.get('data', {})
    print(f"Scan type: {data.get('scan_type')}")
    print(f"Verdict: {data.get('verdict')}")
    print(f"CPU real: {data.get('cpu',{}).get('real_cpuid')}")
    print(f"CPU fake: {data.get('cpu',{}).get('reported_registry')}")
except Exception as e:
    print(f"Error: {e}")

# 3) Run the actual integration script
print("\n=== INTEGRATION SCRIPT TEST ===")
sys.argv = ["custom-telegram", alert_file]
try:
    exec(open("/var/ossec/integrations/custom-telegram").read())
    print("Script executed OK")
except Exception as e:
    print(f"Script error: {e}")
    import traceback
    traceback.print_exc()

# 4) Check log
print("\n=== LOG FILE ===")
try:
    with open("/tmp/telegram.log") as f:
        print(f.read()[-500:])
except:
    print("No log file")
