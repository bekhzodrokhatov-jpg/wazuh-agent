# HW-Detector: Complete Wazuh System - FINAL DOCUMENTATION

## ✅ Sistema Status: READY FOR PRODUCTION

Bu dokumentasiya HW-Detector (Hardware Fraud Detection) complete Wazuh integration'ini tavsiflab beradi.

---

## 📋 ARXITEKTURA

```
Windows PC (Agent)          Linux Server (Wazuh Manager)         Telegram
  ┌─────────────────┐       ┌─────────────────────┐            ┌──────────┐
  │ HW-Detector     │       │ hw_change_detector  │            │ Security │
  │ -Wazuh.ps1      │──────▶│ .py (cron)          │───────────▶│  Channel │
  │ (1 min interval)│       │ + SQLite DB         │   Telegram │  @...... │
  └─────────────────┘       │ + Rules/Decoders    │   API      └──────────┘
                            │ + custom-telegram   │            
                            │   integration       │            
                            └─────────────────────┘            
```

---

## 🔧 DEPLOYMENT SUMMARY

### 1. Windows Side (Agent PC)
- **Script**: `HW-Detector-Wazuh.ps1`
- **Location**: `C:\Program Files (x86)\ossec-agent\active-response\bin\`
- **Interval**: 1 daqiqa (agent.conf'dan)
- **Trigger**: Automatic on agent startup + cron interval
- **Logic**: CPU, RAM, GPU, Board serial'ni taqqoslash (real vs registry)
- **Output**: JSON format Wazuh'ga

### 2. Linux Server (Wazuh Manager)
- **Database**: SQLite `/var/ossec/var/db/hw_inventory.db`
  - `pc_inventory` - jami PC'lar ro'yxati
  - `hardware_history` - har PC'ning scan tarix
  - `hardware_changes` - aniqlangan o'zgarishlar

- **Change Detection**: `hw_change_detector.py` (har 1 daqiqada cron bilan)
  - alerts.json'dan 100101 eventlarni o'qib
  - Database'dagi oldingi scan bilan taqqoslash
  - O'zgarishlar aniqlash (CPU/RAM REPLACED, component ADDED/REMOVED)
  - Deduplication: 7 kundan ko'p bir xil alert chiqmaslik

- **Rules & Decoders**:
  - `hw_detector_rules.xml`: 100101/100102 (fraud detection)
  - `hw_change_rules.xml`: 100201/100202/100203 (change detection)
  - `hw_detector_decoder.xml`, `hw_change_decoder.xml`: JSON parsing

- **Telegram Integration**: `custom-telegram`
  - Rule ID 100101 ga bog'langan
  - Bot Token: `8083742152:AAEYW0mAB_Mq_wFdm_SuBiMcj5TfSHztYmY`
  - Chat ID: `-1003744477260` (Security Channel WIUT)

---

## 📊 DATABASE SCHEMA

### pc_inventory
```
agent_id, hostname, first_seen, last_seen, last_fingerprint, last_verdict, scan_count
```

### hardware_history
```
agent_id, hostname, scan_time, 
cpu_real, cpu_reported_wmi, cpu_reported_registry, cpu_tampered,
ram_real_gb, ram_sticks, ram_tampered,
gpu_description, system_*, verdict, tampering_label, ...
```

### hardware_changes
```
agent_id, hostname, change_time, component, field_name,
old_value, new_value, change_type (REPLACED|ADDED|REMOVED),
alert_sent (deduplication flag)
```

---

## 🚨 ALERT RULES

| Rule ID | Level | Trigger | Telegram |
|---------|-------|---------|----------|
| **100101** | 12 | CPU/RAM soxtalashtirilgan (TAMPERED) | ✅ YES |
| **100102** | 4 | CPU/RAM toza (CLEAN) | ❌ NO |
| **100201** | 11 | Hardware component REPLACED | ❌ (future) |
| **100202** | 10 | Hardware ADDED/REMOVED | ❌ (future) |
| **100203** | 4 | Minor change (MODIFIED) | ❌ NO |

---

## 📝 USAGE COMMANDS

### Database Query
```bash
# Status ko'rish
python3 /var/ossec/var/hw_monitor/hw_change_detector.py --stats

# Barcha PC'lar inventory
python3 /var/ossec/var/hw_monitor/hw_change_detector.py --dump

# Bitta PC tarix (Agent ID: 003)
python3 /var/ossec/var/hw_monitor/hw_change_detector.py --history 003

# O'zgarishlar log
python3 /var/ossec/var/hw_monitor/hw_change_detector.py --changes

# Yozuvlarni qayta ishlash (manual)
python3 /var/ossec/var/hw_monitor/hw_change_detector.py --process
```

### Alert Check
```bash
# Telegram log
cat /tmp/telegram.log

# Wazuh alerts
dog /var/ossec/logs/alerts/alerts.json | grep 100101

# Integration log
grep -i "custom-telegram\|100101" /var/ossec/logs/ossec.log | tail -20
```

---

## ⚙️ DEDUPLICATION LOGIC

1. O'zgarish aniqlanganda `hardware_changes` jadvliga `alert_sent=0` bilan saqlanadi
2. `hw_change_detector.py --process` jarayonida:
   - Faqat 7 kundan ko'proq bo'lmagan o'zgarishlar qayta ishlanaladi
   - Shu PC, shu component uchun oldingi 7 kun ichida yuborilgan alert bormi? Tekshiriladi
   - Agar yo'q bo'lsa → alert yuboriladi va `alert_sent=1` qo'yiladi
   - Agar bor bo'lsa → skip qilinadi (duplicate protection)

**Result**: Bir PC uchun bir xil o'zgarish bir hafta uchun **ONLY ONCE** alert chiqadi.

---

## 🧪 TEST SCENARIO

**Simulyasiya**:
1. `C:\Users\Public\hw_state_v11.txt` o'chiring (state file)
2. Agent PowerShell script'ni ishga tushitiring
3. New hardware fingerprint detect bo'ladi
4. Wazuh serverga JSON alert yuboriladi
5. `hw_change_detector.py` --process alarm
6. Telegram'ga alert keladi!

---

## 🔐 SECURITY NOTES

- **Database**: SQLite (file-based) - production'da PostgreSQL tavsiya
- **Socket**: Wazuh queue socket `/var/ossec/queue/sockets/queue`
- **Telegram Token**: EXPOSED - environment variable'da o'tish kerak
- **Credentials**: Linux server root, SSH key-based auth tavsiya

---

## 📦 DEPLOYED FILES

✅ **Windows Side**:
- `HW-Detector-Wazuh.ps1` - Config agent'da, active-response/bin/
- Running interval: 1 min

✅ **Linux Server**:
- `/var/ossec/var/hw_monitor/hw_change_detector.py` - Change detector
- `/var/ossec/etc/rules/hw_detector_rules.xml` - Fraud detection rules  
- `/var/ossec/etc/rules/hw_change_rules.xml` - Change detection rules
- `/var/ossec/etc/decoders/hw_detector_decoder.xml` - Decoder
- `/var/ossec/etc/decoders/hw_change_decoder.xml` - Change decoder
- `/var/ossec/integrations/custom-telegram` - Telegram bot integration
- `/etc/cron.d/wazuh-hw-monitor` - Cron: * * * * * (her daqiqada)

✅ **Database**:
- `/var/ossec/var/db/hw_inventory.db` - SQLite

---

## 🎯 NEXT STEPS (PRODUCTION)

1. **Telegram**: Bot token'ni secure storage (vault, env var)
2. **Database**: PostgreSQL'ga migrate qilish
3. **Dashboard**: Wazuh dashboard'da custom widget qo'shish
4. **Monitoring**: Slack/Teams integratsiyasi
5. **Reporting**: Weekly/monthly fraud detection report
6. **Scaling**: 50+ PC'lar uchun test load

---

## 📞 SUPPORT

**Linux**: 
```
ssh wazuh@192.168.33.29
Status: systemctl status wazuh-manager
Logs: tail -f /var/ossec/logs/ossec.log
```

**Windows Agent**:
```
Status: Get-Service WazuhSvc
Logs: C:\Program Files (x86)\ossec-agent\ossec.log
```

---

**System Ready! ✅**

*Generated: 2026-03-26*
*Version: 1.0 Final*
