#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HW-Detector: Hardware Inventory SQL Integration for Wazuh
=========================================================
Bu skript Wazuh integratord orqali ishga tushadi.
Har bir HW-Detector scan natijasini SQLite bazaga yozadi,
oldingi holatlar bilan taqqoslab, o'zgarishlarni aniqlaydi.

O'rnatish:
  /var/ossec/integrations/hw_inventory_integration.py

Wazuh ossec.conf ga qo'shish:
  <integration>
    <name>custom-hw_inventory_integration.py</name>
    <rule_id>100100</rule_id>
    <alert_format>json</alert_format>
  </integration>
"""

import sys
import os
import json
import sqlite3
import hashlib
import logging
from datetime import datetime

# ============================================================
# Konfiguratsiya
# ============================================================
WAZUH_DIR = "/var/ossec"
DB_PATH = os.path.join(WAZUH_DIR, "var", "db", "hw_inventory.db")
LOG_PATH = os.path.join(WAZUH_DIR, "logs", "hw_inventory.log")
ACTIVE_RESPONSE_LOG = os.path.join(WAZUH_DIR, "logs", "active-responses.log")

# Logging sozlash
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("hw_inventory")


# ============================================================
# Database yaratish/ochish
# ============================================================
def init_database():
    """SQLite database va jadvallarni yaratish"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # PC lar ro'yxati
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pc_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT UNIQUE NOT NULL,
            hostname TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            last_fingerprint TEXT,
            last_verdict TEXT,
            scan_count INTEGER DEFAULT 1
        )
    """)

    # Hardware holati tarixi
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hardware_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            hostname TEXT NOT NULL,
            scan_time TEXT NOT NULL,
            cpu_real TEXT,
            cpu_reported_wmi TEXT,
            cpu_reported_registry TEXT,
            cpu_cores INTEGER,
            cpu_threads INTEGER,
            cpu_max_mhz INTEGER,
            cpu_tampered INTEGER DEFAULT 0,
            cpu_registry_tampered INTEGER DEFAULT 0,
            cpu_description TEXT,
            ram_real_gb REAL,
            ram_reported_gb REAL,
            ram_total_mb INTEGER,
            ram_tampered INTEGER DEFAULT 0,
            ram_stick_count INTEGER,
            ram_sticks_json TEXT,
            ram_description TEXT,
            gpu_info_json TEXT,
            gpu_tampered INTEGER DEFAULT 0,
            gpu_description TEXT,
            board_manufacturer TEXT,
            board_product TEXT,
            board_serial TEXT,
            system_manufacturer TEXT,
            system_product TEXT,
            system_serial TEXT,
            verdict TEXT,
            tampering_label TEXT,
            registry_tampered INTEGER DEFAULT 0,
            registry_details_json TEXT,
            hw_fingerprint TEXT,
            benchmark_score INTEGER,
            FOREIGN KEY (agent_id) REFERENCES pc_inventory(agent_id)
        )
    """)

    # Hardware o'zgarishlar jurnali
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hardware_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            hostname TEXT NOT NULL,
            change_time TEXT NOT NULL,
            component TEXT NOT NULL,
            field_name TEXT,
            old_value TEXT,
            new_value TEXT,
            change_type TEXT NOT NULL,
            alert_sent INTEGER DEFAULT 0,
            FOREIGN KEY (agent_id) REFERENCES pc_inventory(agent_id)
        )
    """)

    # Indekslar
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_hw_history_agent ON hardware_history(agent_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_hw_history_time ON hardware_history(scan_time)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_hw_changes_agent ON hardware_changes(agent_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_hw_changes_time ON hardware_changes(change_time)")

    conn.commit()
    return conn


# ============================================================
# Oldingi holatni olish
# ============================================================
def get_last_scan(conn, agent_id):
    """Agent uchun oxirgi scan natijasini olish"""
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM hardware_history 
        WHERE agent_id = ? 
        ORDER BY scan_time DESC 
        LIMIT 1
    """, (agent_id,))
    row = cursor.fetchone()
    if row:
        return dict(row)
    return None


# ============================================================
# O'zgarishlarni aniqlash
# ============================================================
def detect_changes(conn, agent_id, hostname, old_scan, new_data):
    """Eski va yangi scan natijalarini taqqoslash, o'zgarishlarni aniqlash"""
    changes = []
    now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    if old_scan is None:
        logger.info(f"Birinchi scan: {hostname} (agent: {agent_id})")
        return changes

    hw_data = new_data.get("data", {})

    # === CPU O'ZGARISHI ===
    old_cpu = old_scan.get("cpu_real", "")
    new_cpu = hw_data.get("cpu", {}).get("real_cpuid", "")
    if old_cpu and new_cpu and old_cpu != new_cpu and new_cpu != "N/A":
        old_desc = old_scan.get("cpu_description", old_cpu)
        new_desc = hw_data.get("cpu", {}).get("description", new_cpu)
        changes.append({
            "agent_id": agent_id,
            "hostname": hostname,
            "change_time": now,
            "component": "CPU",
            "field_name": "cpu_model",
            "old_value": old_desc,
            "new_value": new_desc,
            "change_type": "REPLACED"
        })
        logger.warning(f"CPU O'ZGARDI: {hostname} - {old_desc} -> {new_desc}")

    # CPU cores o'zgarishi
    old_cores = old_scan.get("cpu_cores", 0)
    new_cores = hw_data.get("cpu", {}).get("real_cores", 0)
    if old_cores and new_cores and old_cores != new_cores:
        changes.append({
            "agent_id": agent_id,
            "hostname": hostname,
            "change_time": now,
            "component": "CPU",
            "field_name": "cpu_cores",
            "old_value": str(old_cores),
            "new_value": str(new_cores),
            "change_type": "CHANGED"
        })

    # === RAM O'ZGARISHI ===
    old_ram_gb = old_scan.get("ram_real_gb", 0)
    new_ram_gb = hw_data.get("ram", {}).get("real_smbios_gb", 0)
    if old_ram_gb and new_ram_gb and abs(float(old_ram_gb) - float(new_ram_gb)) > 0.5:
        old_ram_desc = old_scan.get("ram_description", f"{old_ram_gb}GB")
        new_ram_desc = hw_data.get("ram", {}).get("description", f"{new_ram_gb}GB")
        changes.append({
            "agent_id": agent_id,
            "hostname": hostname,
            "change_time": now,
            "component": "RAM",
            "field_name": "ram_total",
            "old_value": old_ram_desc,
            "new_value": new_ram_desc,
            "change_type": "REPLACED"
        })
        logger.warning(f"RAM O'ZGARDI: {hostname} - {old_ram_desc} -> {new_ram_desc}")

    # RAM stick soni o'zgarishi
    old_sticks = old_scan.get("ram_stick_count", 0)
    new_sticks = hw_data.get("ram", {}).get("stick_count", 0)
    if old_sticks and new_sticks and old_sticks != new_sticks:
        changes.append({
            "agent_id": agent_id,
            "hostname": hostname,
            "change_time": now,
            "component": "RAM",
            "field_name": "ram_stick_count",
            "old_value": f"{old_sticks} ta stick",
            "new_value": f"{new_sticks} ta stick",
            "change_type": "ADDED" if new_sticks > old_sticks else "REMOVED"
        })

    # RAM sticks batafsil taqqoslash
    try:
        old_sticks_json = json.loads(old_scan.get("ram_sticks_json", "[]") or "[]")
        new_sticks_list = hw_data.get("ram", {}).get("sticks", [])

        # Har bir slotni taqqoslash
        old_slots = {s.get("slot", ""): s for s in old_sticks_json if isinstance(s, dict)}
        new_slots = {s.get("slot", ""): s for s in new_sticks_list if isinstance(s, dict)}

        for slot_name in set(list(old_slots.keys()) + list(new_slots.keys())):
            old_s = old_slots.get(slot_name)
            new_s = new_slots.get(slot_name)

            if old_s and not new_s:
                old_desc = old_s.get("description", f"Slot {slot_name}")
                changes.append({
                    "agent_id": agent_id,
                    "hostname": hostname,
                    "change_time": now,
                    "component": "RAM",
                    "field_name": f"ram_slot_{slot_name}",
                    "old_value": old_desc,
                    "new_value": "BO'SH",
                    "change_type": "REMOVED"
                })
            elif new_s and not old_s:
                new_desc = new_s.get("description", f"Slot {slot_name}")
                changes.append({
                    "agent_id": agent_id,
                    "hostname": hostname,
                    "change_time": now,
                    "component": "RAM",
                    "field_name": f"ram_slot_{slot_name}",
                    "old_value": "BO'SH",
                    "new_value": new_desc,
                    "change_type": "ADDED"
                })
            elif old_s and new_s:
                old_serial = old_s.get("serial", "")
                new_serial = new_s.get("serial", "")
                old_size = old_s.get("size_mb", 0)
                new_size = new_s.get("size_mb", 0)
                if (old_serial != new_serial and old_serial and new_serial) or \
                   (abs(int(old_size) - int(new_size)) > 100):
                    old_desc = old_s.get("description", f"{old_size}MB")
                    new_desc = new_s.get("description", f"{new_size}MB")
                    changes.append({
                        "agent_id": agent_id,
                        "hostname": hostname,
                        "change_time": now,
                        "component": "RAM",
                        "field_name": f"ram_slot_{slot_name}",
                        "old_value": old_desc,
                        "new_value": new_desc,
                        "change_type": "REPLACED"
                    })
    except Exception as e:
        logger.error(f"RAM stick taqqoslash xatosi: {e}")

    # === GPU O'ZGARISHI ===
    old_gpu_desc = old_scan.get("gpu_description", "")
    new_gpu_desc = hw_data.get("gpu", {}).get("description", "")
    if old_gpu_desc and new_gpu_desc and old_gpu_desc != new_gpu_desc and new_gpu_desc != "N/A":
        changes.append({
            "agent_id": agent_id,
            "hostname": hostname,
            "change_time": now,
            "component": "GPU",
            "field_name": "gpu_model",
            "old_value": old_gpu_desc,
            "new_value": new_gpu_desc,
            "change_type": "REPLACED"
        })
        logger.warning(f"GPU O'ZGARDI: {hostname} - {old_gpu_desc} -> {new_gpu_desc}")

    # === BOARD O'ZGARISHI ===
    old_board = old_scan.get("board_serial", "")
    new_board = hw_data.get("system", {}).get("board_serial", "")
    if old_board and new_board and old_board != new_board and new_board != "N/A" and old_board != "N/A":
        old_board_full = f"{old_scan.get('board_manufacturer','')} {old_scan.get('board_product','')}"
        new_sys = hw_data.get("system", {})
        new_board_full = f"{new_sys.get('board_manufacturer','')} {new_sys.get('board_product','')}"
        changes.append({
            "agent_id": agent_id,
            "hostname": hostname,
            "change_time": now,
            "component": "MOTHERBOARD",
            "field_name": "board",
            "old_value": old_board_full.strip(),
            "new_value": new_board_full.strip(),
            "change_type": "REPLACED"
        })

    # === FINGERPRINT O'ZGARISHI (umumiy) ===
    old_fp = old_scan.get("hw_fingerprint", "")
    new_fp = hw_data.get("hw_fingerprint", "")
    if old_fp and new_fp and old_fp != new_fp and not changes:
        # Aniq komponent topilmagan lekin fingerprint o'zgargan
        changes.append({
            "agent_id": agent_id,
            "hostname": hostname,
            "change_time": now,
            "component": "UNKNOWN",
            "field_name": "hw_fingerprint",
            "old_value": old_fp[:16] + "...",
            "new_value": new_fp[:16] + "...",
            "change_type": "CHANGED"
        })

    return changes


# ============================================================
# O'zgarishlarni bazaga yozish va alert yuborish
# ============================================================
def save_changes(conn, changes):
    """O'zgarishlarni hardware_changes jadvaliga yozish"""
    cursor = conn.cursor()
    for change in changes:
        cursor.execute("""
            INSERT INTO hardware_changes 
            (agent_id, hostname, change_time, component, field_name, old_value, new_value, change_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            change["agent_id"], change["hostname"], change["change_time"],
            change["component"], change["field_name"],
            change["old_value"], change["new_value"], change["change_type"]
        ))
    conn.commit()


def send_change_alerts(changes):
    """O'zgarish alertlarini Wazuh active-responses.log ga yozish"""
    try:
        with open(ACTIVE_RESPONSE_LOG, "a") as f:
            for change in changes:
                alert_data = json.dumps(change, ensure_ascii=False)
                f.write(f"hw_change: {alert_data}\n")
                logger.info(f"Alert yuborildi: {change['component']} - {change['hostname']}")
    except Exception as e:
        logger.error(f"Alert yozish xatosi: {e}")


# ============================================================
# Scan natijasini bazaga yozish
# ============================================================
def save_scan(conn, agent_id, hostname, hw_data):
    """Yangi scan natijasini hardware_history ga yozish"""
    cursor = conn.cursor()
    now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    cpu = hw_data.get("cpu", {})
    ram = hw_data.get("ram", {})
    gpu = hw_data.get("gpu", {})
    sys_info = hw_data.get("system", {})
    reg = hw_data.get("registry_tampering", {})
    bm = hw_data.get("benchmark", {})

    # hardware_history ga yozish
    cursor.execute("""
        INSERT INTO hardware_history (
            agent_id, hostname, scan_time,
            cpu_real, cpu_reported_wmi, cpu_reported_registry,
            cpu_cores, cpu_threads, cpu_max_mhz,
            cpu_tampered, cpu_registry_tampered, cpu_description,
            ram_real_gb, ram_reported_gb, ram_total_mb,
            ram_tampered, ram_stick_count, ram_sticks_json, ram_description,
            gpu_info_json, gpu_tampered, gpu_description,
            board_manufacturer, board_product, board_serial,
            system_manufacturer, system_product, system_serial,
            verdict, tampering_label, registry_tampered, registry_details_json,
            hw_fingerprint, benchmark_score
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        agent_id, hostname, now,
        cpu.get("real_cpuid", ""), cpu.get("reported_wmi", ""), cpu.get("reported_registry", ""),
        cpu.get("real_cores", 0), cpu.get("real_threads", 0), cpu.get("real_max_mhz", 0),
        1 if cpu.get("tampered") else 0,
        1 if cpu.get("registry_tampered") else 0,
        cpu.get("description", ""),
        ram.get("real_smbios_gb", 0), ram.get("reported_wmi_gb", 0), ram.get("real_total_mb", 0),
        1 if ram.get("tampered") else 0,
        ram.get("stick_count", 0),
        json.dumps(ram.get("sticks", []), ensure_ascii=False),
        ram.get("description", ""),
        json.dumps(gpu.get("devices", []), ensure_ascii=False),
        1 if gpu.get("tampered") else 0,
        gpu.get("description", ""),
        sys_info.get("board_manufacturer", ""), sys_info.get("board_product", ""),
        sys_info.get("board_serial", ""),
        sys_info.get("manufacturer", ""), sys_info.get("product", ""),
        sys_info.get("serial", ""),
        hw_data.get("verdict", ""),
        hw_data.get("tampering_label", ""),
        1 if reg.get("detected") else 0,
        json.dumps(reg.get("details", []), ensure_ascii=False),
        hw_data.get("hw_fingerprint", ""),
        bm.get("score", 0)
    ))

    # pc_inventory yangilash
    cursor.execute("""
        INSERT INTO pc_inventory (agent_id, hostname, first_seen, last_seen, last_fingerprint, last_verdict, scan_count)
        VALUES (?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(agent_id) DO UPDATE SET
            hostname = excluded.hostname,
            last_seen = excluded.last_seen,
            last_fingerprint = excluded.last_fingerprint,
            last_verdict = excluded.last_verdict,
            scan_count = scan_count + 1
    """, (agent_id, hostname, now, now, hw_data.get("hw_fingerprint", ""), hw_data.get("verdict", "")))

    conn.commit()
    logger.info(f"Scan saqlandi: {hostname} (agent: {agent_id}), verdict: {hw_data.get('verdict', 'N/A')}")


# ============================================================
# Wazuh Integration — asosiy kirish nuqtasi
# ============================================================
def main():
    """Wazuh integratord orqali chaqiriladi"""
    try:
        # Wazuh integration argumentlarini o'qish
        # arg1 = alert file path
        # arg2 = api key (ishlatilmaydi)
        # arg3 = alert json (stdin dan)
        
        alert_file = sys.argv[1] if len(sys.argv) > 1 else None
        
        if alert_file and os.path.exists(alert_file):
            with open(alert_file, 'r') as f:
                alert_data = json.load(f)
        else:
            # stdin dan o'qish
            input_data = sys.stdin.read()
            if not input_data.strip():
                logger.error("Bo'sh input")
                sys.exit(1)
            alert_data = json.loads(input_data)

        # Agent ma'lumotlarini olish
        agent_info = alert_data.get("agent", {})
        agent_id = agent_info.get("id", "unknown")
        hostname = agent_info.get("name", "unknown")

        # HW data ni olish (Wazuh alert tuzilishiga qarab)
        hw_data = alert_data.get("data", {})
        
        if not hw_data or hw_data.get("scan_type") != "hw_fraud_detection":
            logger.debug(f"HW-Detector scan emas, o'tkazib yuborildi: {agent_id}")
            sys.exit(0)

        # Database ni ochish
        conn = init_database()

        try:
            # Oldingi holatni olish
            old_scan = get_last_scan(conn, agent_id)

            # O'zgarishlarni aniqlash
            changes = detect_changes(conn, agent_id, hostname, old_scan, alert_data)

            # Yangi scan ni saqlash
            save_scan(conn, agent_id, hostname, hw_data)

            # O'zgarishlar bo'lsa — alertlar yuborish
            if changes:
                save_changes(conn, changes)
                send_change_alerts(changes)
                logger.warning(f"{hostname}: {len(changes)} ta hardware o'zgarishi aniqlandi!")
            else:
                logger.info(f"{hostname}: O'zgarish yo'q")

        finally:
            conn.close()

    except Exception as e:
        logger.error(f"Xatolik: {e}", exc_info=True)
        sys.exit(1)


# ============================================================
# Standalone test rejimi
# ============================================================
def test_mode():
    """Test rejimi - database va change detection ni tekshirish"""
    print("=" * 60)
    print("  HW-Detector SQL Integration — TEST REJIMI")
    print("=" * 60)
    print()

    # Test DB ni /tmp ga yaratish
    global DB_PATH, LOG_PATH, ACTIVE_RESPONSE_LOG
    DB_PATH = "/tmp/hw_inventory_test.db"
    LOG_PATH = "/tmp/hw_inventory_test.log"
    ACTIVE_RESPONSE_LOG = "/tmp/hw_test_active_response.log"

    conn = init_database()
    print("[+] Database yaratildi:", DB_PATH)

    # 1-scan: birinchi marta
    scan1 = {
        "agent": {"id": "001", "name": "LAB-PC-01"},
        "data": {
            "scan_type": "hw_fraud_detection",
            "version": "2.0",
            "hostname": "LAB-PC-01",
            "verdict": "CLEAN",
            "tampering_label": "HAQIQIY",
            "hw_fingerprint": "abc123def456",
            "cpu": {
                "real_cpuid": "Intel(R) Core(TM) i7-12700K",
                "reported_wmi": "Intel(R) Core(TM) i7-12700K",
                "reported_registry": "Intel(R) Core(TM) i7-12700K",
                "real_cores": 12, "real_threads": 20,
                "real_max_mhz": 3600,
                "tampered": False, "registry_tampered": False,
                "description": "Intel(R) Core(TM) i7-12700K"
            },
            "ram": {
                "real_smbios_gb": 16, "real_kernel_gb": 15.8,
                "reported_wmi_gb": 16, "real_total_mb": 16384,
                "tampered": False, "stick_count": 2,
                "sticks": [
                    {"slot": "DIMM0", "size_mb": 8192, "size_gb": 8,
                     "speed_mhz": 4800, "type": "DDR5",
                     "manufacturer": "Kingston", "part_number": "KF548C38-8",
                     "serial": "SN001", "description": "Kingston 8GB DDR5 4800MHz"},
                    {"slot": "DIMM1", "size_mb": 8192, "size_gb": 8,
                     "speed_mhz": 4800, "type": "DDR5",
                     "manufacturer": "Kingston", "part_number": "KF548C38-8",
                     "serial": "SN002", "description": "Kingston 8GB DDR5 4800MHz"}
                ],
                "description": "Kingston 16GB DDR5 4800MHz"
            },
            "gpu": {
                "devices": [{"pnp_name": "NVIDIA GeForce RTX 3060",
                             "wmi_name": "NVIDIA GeForce RTX 3060",
                             "hardware_id": "PCI\\VEN_10DE&DEV_2503",
                             "tampered": False}],
                "tampered": False,
                "description": "NVIDIA GeForce RTX 3060"
            },
            "registry_tampering": {"detected": False, "label": "HAQIQIY", "details": []},
            "system": {"board_manufacturer": "ASUS", "board_product": "Z690",
                       "board_serial": "BS001", "manufacturer": "ASUS",
                       "product": "Desktop", "serial": "SYS001"},
            "benchmark": {"score": 250000}
        }
    }

    old_scan = get_last_scan(conn, "001")
    changes = detect_changes(conn, "001", "LAB-PC-01", old_scan, scan1)
    save_scan(conn, "001", "LAB-PC-01", scan1["data"])
    print(f"[+] Scan 1 saqlandi (birinchi marta). O'zgarishlar: {len(changes)}")

    # 2-scan: RAM almashtirilgan!
    scan2 = json.loads(json.dumps(scan1))
    scan2["data"]["hw_fingerprint"] = "xyz789new"
    scan2["data"]["ram"]["real_smbios_gb"] = 4
    scan2["data"]["ram"]["real_total_mb"] = 4096
    scan2["data"]["ram"]["stick_count"] = 1
    scan2["data"]["ram"]["sticks"] = [
        {"slot": "DIMM0", "size_mb": 4096, "size_gb": 4,
         "speed_mhz": 3200, "type": "DDR4",
         "manufacturer": "Kingston", "part_number": "KVR32N-4",
         "serial": "SN999", "description": "Kingston 4GB DDR4 3200MHz"}
    ]
    scan2["data"]["ram"]["description"] = "Kingston 4GB DDR4 3200MHz"
    scan2["data"]["verdict"] = "TAMPERED"
    scan2["data"]["tampering_label"] = "SOXTALASHTIRILGAN"
    scan2["data"]["ram"]["tampered"] = True

    old_scan = get_last_scan(conn, "001")
    changes = detect_changes(conn, "001", "LAB-PC-01", old_scan, scan2)
    save_scan(conn, "001", "LAB-PC-01", scan2["data"])

    print(f"[+] Scan 2 saqlandi. O'zgarishlar: {len(changes)}")
    for c in changes:
        print(f"    [{c['component']}] {c['change_type']}: {c['old_value']} -> {c['new_value']}")

    if changes:
        save_changes(conn, changes)
        send_change_alerts(changes)
        print(f"[+] Alertlar yuborildi: {ACTIVE_RESPONSE_LOG}")

    # Statistika
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM hardware_history")
    print(f"\n[*] Jami scan yozuvlari: {cursor.fetchone()[0]}")
    cursor.execute("SELECT COUNT(*) FROM hardware_changes")
    print(f"[*] Jami o'zgarish yozuvlari: {cursor.fetchone()[0]}")
    cursor.execute("SELECT COUNT(*) FROM pc_inventory")
    print(f"[*] Jami PC lar: {cursor.fetchone()[0]}")

    conn.close()
    print(f"\n[+] Test muvaffaqiyatli tugadi!")
    print(f"[+] Test DB: {DB_PATH}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        test_mode()
    else:
        main()
