#!/usr/bin/env python3
import sys
import json
import requests

TOKEN = "8083742152:AAEYW0mAB_Mq_wFdm_SuBiMcj5TfSHztYmY"
CHAT_ID = "-1003744477260"

# Read last 100101 alert
with open("/tmp/test-alert.json") as f:
    alert = json.load(f)

agent_name = alert.get('agent', {}).get('name', 'Manager')
timestamp = alert.get('timestamp', 'N/A')
data = alert.get('data', {})

cpu = data.get('cpu', {})
ram = data.get('ram', {})
gpu = data.get('gpu', {})
sys_info = data.get('system', {})
verdict = data.get('verdict', 'N/A')

msg = f"\U0001f534 *BATAFSIL XAVFSIZLIK TAHLILI*\n"
msg += f"\U0001f4bb *PC:* {data.get('hostname', agent_name)}\n"
msg += f"\U0001f552 *Vaqt:* {timestamp}\n\n"

if verdict == "TAMPERED":
    msg += f"\U0001f6a8 *STATUS:* {verdict}\n\n"
else:
    msg += f"\u2705 *STATUS:* {verdict}\n\n"

msg += f"\U0001f9e0 *PROTSESSOR (REAL vs FAKE):*\n"
msg += f"- Haqiqiy: {cpu.get('real_cpuid', 'N/A')}\n"
msg += f"- Soxtasi: {cpu.get('reported_registry', 'N/A')}\n"
msg += f"- Soxtalashtirilganmi? {'HA' if verdict == 'TAMPERED' else 'YOQ'}\n\n"

msg += f"\U0001f4ca *OPERATIV XOTIRA (RAM):*\n"
msg += f"- Umumiy: {ram.get('real_smbios_gb', 'N/A')} GB\n"

msg += f"\n\U0001f3ae *VIDEO KARTA (GPU):*\n"
msg += f"- Model: {gpu.get('description', 'N/A')}\n"

msg += f"\n\u2699 *MOTHERBOARD:*\n"
msg += f"- {sys_info.get('manufacturer', 'N/A')} {sys_info.get('product', 'N/A')}\n"
msg += f"- S/N: {sys_info.get('board_serial', 'N/A')}\n\n"

if verdict == "TAMPERED":
    msg += f"\u274c *DIAGNOZ:* Reystr soxtalashtirilgan!"
else:
    msg += f"\u2705 *DIAGNOZ:* Hardware holati to'g'ri."

url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
r = requests.post(url, json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"})
print(f"STATUS: {r.status_code}")
print(f"RESPONSE: {r.text[:500]}")
