#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HW-Detector: Hardware Change Detector
======================================
Bu skript cron yoki Wazuh wodle orqali ishga tushadi.
alerts.json dan hw_detector eventlarni o'qib, SQLite bilan 
taqqoslab, o'zgarishlarni aniqlaydi.

Ishlatish:
  # Test rejimi
  python3 hw_change_detector.py --test
  
  # Cron rejimi (har soatda)
  python3 hw_change_detector.py --process
  
  # DB statistikasi
  python3 hw_change_detector.py --stats
  
  # DB dump (barcha PC lar)
  python3 hw_change_detector.py --dump
  
  # Bitta PC tarixini ko'rish
  python3 hw_change_detector.py --history 001
  
  # O'zgarishlar ro'yxati
  python3 hw_change_detector.py --changes
"""

import sys
import os
import json
import sqlite3
import argparse
from datetime import datetime, timedelta

# ============================================================
# Konfiguratsiya
# ============================================================
WAZUH_DIR = "/var/ossec"
DB_PATH = os.path.join(WAZUH_DIR, "var", "db", "hw_inventory.db")
ALERTS_FILE = os.path.join(WAZUH_DIR, "logs", "alerts", "alerts.json")
ACTIVE_RESPONSE_LOG = os.path.join(WAZUH_DIR, "logs", "active-responses.log")
LAST_PROCESS_FILE = os.path.join(WAZUH_DIR, "var", "db", "hw_last_process.txt")

# Ranglar (terminal uchun)
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
NC = '\033[0m'  # No Color
BOLD = '\033[1m'


def init_database():
    """SQLite database va jadvallarni yaratish"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hardware_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            hostname TEXT NOT NULL,
            scan_time TEXT NOT NULL,
            cpu_real TEXT, cpu_reported_wmi TEXT, cpu_reported_registry TEXT,
            cpu_cores INTEGER, cpu_threads INTEGER, cpu_max_mhz INTEGER,
            cpu_tampered INTEGER DEFAULT 0, cpu_registry_tampered INTEGER DEFAULT 0,
            cpu_description TEXT,
            ram_real_gb REAL, ram_reported_gb REAL, ram_total_mb INTEGER,
            ram_tampered INTEGER DEFAULT 0, ram_stick_count INTEGER,
            ram_sticks_json TEXT, ram_description TEXT,
            gpu_info_json TEXT, gpu_tampered INTEGER DEFAULT 0, gpu_description TEXT,
            board_manufacturer TEXT, board_product TEXT, board_serial TEXT,
            system_manufacturer TEXT, system_product TEXT, system_serial TEXT,
            verdict TEXT, tampering_label TEXT,
            registry_tampered INTEGER DEFAULT 0, registry_details_json TEXT,
            hw_fingerprint TEXT, benchmark_score INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hardware_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL, hostname TEXT NOT NULL,
            change_time TEXT NOT NULL, component TEXT NOT NULL,
            field_name TEXT, old_value TEXT, new_value TEXT,
            change_type TEXT NOT NULL, alert_sent INTEGER DEFAULT 0
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_hw_history_agent ON hardware_history(agent_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_hw_changes_agent ON hardware_changes(agent_id)")
    conn.commit()
    return conn


# ============================================================
# Alertlarni qayta ishlash
# ============================================================
def process_alerts():
    """alerts.json dan yangi hw_detector eventlarni o'qib qayta ishlash"""
    if not os.path.exists(ALERTS_FILE):
        print(f"{RED}[!] Alerts fayl topilmadi: {ALERTS_FILE}{NC}")
        return

    # Oxirgi ishlov berilgan pozitsiyani o'qish
    last_pos = 0
    if os.path.exists(LAST_PROCESS_FILE):
        try:
            with open(LAST_PROCESS_FILE, 'r') as f:
                last_pos = int(f.read().strip())
        except:
            last_pos = 0

    conn = init_database()
    processed = 0
    changes_total = 0
    alerts_sent = 0

    try:
        with open(ALERTS_FILE, 'r') as f:
            f.seek(last_pos)
            for line in f:
                try:
                    alert = json.loads(line.strip())
                    # Faqat hw_detector alertlarni qayta ishlash
                    rule_groups = alert.get("rule", {}).get("groups", [])
                    data = alert.get("data", {})

                    if "hw_detector" not in rule_groups and data.get("scan_type") != "hw_fraud_detection":
                        continue

                    if data.get("scan_type") != "hw_fraud_detection":
                        continue

                    agent_info = alert.get("agent", {})
                    agent_id = agent_info.get("id", "unknown")
                    hostname = data.get("hostname", agent_info.get("name", "unknown"))

                    # Oldingi skanerni olish
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT * FROM hardware_history
                        WHERE agent_id = ? ORDER BY scan_time DESC LIMIT 1
                    """, (agent_id,))
                    old_scan = cursor.fetchone()
                    if old_scan:
                        old_scan = dict(old_scan)

                    # O'zgarishlarni aniqlash
                    changes = _detect_changes(agent_id, hostname, old_scan, data)

                    # Yangi scan ni saqlash
                    _save_scan(conn, agent_id, hostname, data)

                    # O'zgarishlar bo'lsa saqlash
                    if changes:
                        change_ids = _save_changes(conn, changes)
                        # Faqat yuborish kerak bo'lgan alertlarni filtr qilish
                        alerts_to_send = _filter_unsent_alerts(conn, change_ids)
                        if alerts_to_send:
                            _send_alerts(conn, alerts_to_send)
                            alerts_sent += len(alerts_to_send)
                        changes_total += len(changes)

                    processed += 1

                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"{RED}[!] Xatolik: {e}{NC}")
                    continue

            # Oxirgi pozitsiyani saqlash
            new_pos = f.tell()

        os.makedirs(os.path.dirname(LAST_PROCESS_FILE), exist_ok=True)
        with open(LAST_PROCESS_FILE, 'w') as f:
            f.write(str(new_pos))

    finally:
        conn.close()

    print(f"{GREEN}[+] {processed} ta scan qayta ishlandi{NC}")
    if changes_total > 0:
        print(f"{YELLOW}[!] {changes_total} ta hardware o'zgarishi aniqlandi!{NC}")
        print(f"{CYAN}[+] {alerts_sent} ta alert yuborildi{NC}")


def _detect_changes(agent_id, hostname, old_scan, new_data):
    """O'zgarishlarni aniqlash"""
    changes = []
    now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    if old_scan is None:
        return changes

    # CPU
    old_cpu = old_scan.get("cpu_real", "")
    new_cpu = new_data.get("cpu", {}).get("real_cpuid", "")
    if old_cpu and new_cpu and old_cpu != new_cpu and new_cpu != "N/A":
        changes.append({
            "agent_id": agent_id, "hostname": hostname, "change_time": now,
            "component": "CPU", "field_name": "cpu_model",
            "old_value": old_scan.get("cpu_description", old_cpu),
            "new_value": new_data.get("cpu", {}).get("description", new_cpu),
            "change_type": "REPLACED"
        })

    # RAM hajmi
    old_ram = old_scan.get("ram_real_gb", 0)
    new_ram = new_data.get("ram", {}).get("real_smbios_gb", 0)
    if old_ram and new_ram and abs(float(old_ram) - float(new_ram)) > 0.5:
        changes.append({
            "agent_id": agent_id, "hostname": hostname, "change_time": now,
            "component": "RAM", "field_name": "ram_total",
            "old_value": old_scan.get("ram_description", f"{old_ram}GB"),
            "new_value": new_data.get("ram", {}).get("description", f"{new_ram}GB"),
            "change_type": "REPLACED"
        })

    # RAM sticks
    try:
        old_sticks = json.loads(old_scan.get("ram_sticks_json", "[]") or "[]")
        new_sticks = new_data.get("ram", {}).get("sticks", [])
        old_slots = {s.get("slot", ""): s for s in old_sticks if isinstance(s, dict)}
        new_slots = {s.get("slot", ""): s for s in new_sticks if isinstance(s, dict)}

        for slot in set(list(old_slots.keys()) + list(new_slots.keys())):
            old_s = old_slots.get(slot)
            new_s = new_slots.get(slot)
            if old_s and not new_s:
                changes.append({
                    "agent_id": agent_id, "hostname": hostname, "change_time": now,
                    "component": "RAM", "field_name": f"ram_slot_{slot}",
                    "old_value": old_s.get("description", ""), "new_value": "BO'SH",
                    "change_type": "REMOVED"
                })
            elif new_s and not old_s:
                changes.append({
                    "agent_id": agent_id, "hostname": hostname, "change_time": now,
                    "component": "RAM", "field_name": f"ram_slot_{slot}",
                    "old_value": "BO'SH", "new_value": new_s.get("description", ""),
                    "change_type": "ADDED"
                })
            elif old_s and new_s:
                if (old_s.get("serial", "") != new_s.get("serial", "") and old_s.get("serial")) or \
                   abs(int(old_s.get("size_mb", 0)) - int(new_s.get("size_mb", 0))) > 100:
                    changes.append({
                        "agent_id": agent_id, "hostname": hostname, "change_time": now,
                        "component": "RAM", "field_name": f"ram_slot_{slot}",
                        "old_value": old_s.get("description", ""),
                        "new_value": new_s.get("description", ""),
                        "change_type": "REPLACED"
                    })
    except:
        pass

    # GPU
    old_gpu = old_scan.get("gpu_description", "")
    new_gpu = new_data.get("gpu", {}).get("description", "")
    if old_gpu and new_gpu and old_gpu != new_gpu and new_gpu != "N/A":
        changes.append({
            "agent_id": agent_id, "hostname": hostname, "change_time": now,
            "component": "GPU", "field_name": "gpu_model",
            "old_value": old_gpu, "new_value": new_gpu,
            "change_type": "REPLACED"
        })

    return changes


def _save_scan(conn, agent_id, hostname, data):
    """Scan natijasini saqlash"""
    cursor = conn.cursor()
    now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    cpu = data.get("cpu", {})
    ram = data.get("ram", {})
    gpu = data.get("gpu", {})
    sys_info = data.get("system", {})
    reg = data.get("registry_tampering", {})
    bm = data.get("benchmark", {})

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
        data.get("verdict", ""), data.get("tampering_label", ""),
        1 if reg.get("detected") else 0,
        json.dumps(reg.get("details", []), ensure_ascii=False),
        data.get("hw_fingerprint", ""),
        bm.get("score", 0)
    ))

    cursor.execute("""
        INSERT INTO pc_inventory (agent_id, hostname, first_seen, last_seen, last_fingerprint, last_verdict, scan_count)
        VALUES (?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(agent_id) DO UPDATE SET
            hostname = excluded.hostname, last_seen = excluded.last_seen,
            last_fingerprint = excluded.last_fingerprint,
            last_verdict = excluded.last_verdict,
            scan_count = scan_count + 1
    """, (agent_id, hostname, now, now, data.get("hw_fingerprint", ""), data.get("verdict", "")))
    conn.commit()


def _save_changes(conn, changes):
    """O'zgarishlarni saqlash va ID'larni qaytarish"""
    cursor = conn.cursor()
    change_ids = []
    for c in changes:
        cursor.execute("""
            INSERT INTO hardware_changes 
            (agent_id, hostname, change_time, component, field_name, old_value, new_value, change_type, alert_sent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
        """, (c["agent_id"], c["hostname"], c["change_time"],
              c["component"], c["field_name"], c["old_value"], c["new_value"], c["change_type"]))
        change_ids.append(cursor.lastrowid)
    conn.commit()
    return change_ids


def _filter_unsent_alerts(conn, change_ids):
    """Faqat yuborish kerak bo'lgan alertlarni filtr qilish (deduplication)
    - 7 kun ichida bir xil component/field/agent uchun bir alert
    - alert_sent=0 bo'lgan alertlar
    """
    if not change_ids:
        return []
    
    cursor = conn.cursor()
    unsent_alerts = []
    week_ago = (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    for change_id in change_ids:
        # Hozirgi change ni o'qish
        cursor.execute("SELECT * FROM hardware_changes WHERE id = ?", (change_id,))
        current = cursor.fetchone()
        if not current:
            continue
        
        # Shu PC, shu component, shu field uchun 7 kun ichida boshqa yuborilgan alert bormi?
        cursor.execute("""
            SELECT id FROM hardware_changes
            WHERE agent_id = ? AND component = ? AND field_name = ?
                AND change_time > ? AND alert_sent = 1 AND id != ?
            ORDER BY change_time DESC LIMIT 1
        """, (current['agent_id'], current['component'], current['field_name'], week_ago, change_id))
        
        previous_alert = cursor.fetchone()
        if not previous_alert:
            # Oldingi alert yo'q, shuning uchun yuborish kerak
            unsent_alerts.append(dict(current))
    
    return unsent_alerts


def _mark_alerts_sent(conn, changes):
    """Alertlarni yuborilgan deb belgilash"""
    cursor = conn.cursor()
    for c in changes:
        # Change dict'dan ID ni qidirish
        cursor.execute("""
            UPDATE hardware_changes 
            SET alert_sent = 1 
            WHERE agent_id = ? AND component = ? AND field_name = ? AND change_time = ?
            LIMIT 1
        """, (c['agent_id'], c['component'], c['field_name'], c['change_time']))
    conn.commit()


def _send_alerts(conn, changes):
    """Alert yuborish - deduplication bilan, va alert_sent belgilash"""
    try:
        # Wazuh queue socketini tayyorlash
        alert_socket = "/var/ossec/queue/sockets/queue"
        
        for c in changes:
            # 1. Active response logga yozish (legacy)
            try:
                with open(ACTIVE_RESPONSE_LOG, "a") as f:
                    f.write(f"hw_change: {json.dumps(c, ensure_ascii=False)}\n")
            except:
                pass
            
            # 2. Wazuh JSON alertini tayyorlash va yuborish
            try:
                wazuh_alert = _create_wazuh_json_alert(c)
                if os.path.exists(alert_socket):
                    # Socket orqali Wazuh'ga yuborish
                    _send_to_wazuh_queue(alert_socket, wazuh_alert)
                else:
                    # Backup: File orqali yozish
                    _send_to_wazuh_queue(alert_socket, wazuh_alert)
            except Exception as e:
                print(f"{YELLOW}[!] Wazuh alert yuborish xatosi: {e}{NC}")
        
        # Barcha alertlarni yuborilgan deb belgilash
        _mark_alerts_sent(conn, changes)
    except Exception as e:
        print(f"{RED}[!] Alert yozish xatosi: {e}{NC}")


def _create_wazuh_json_alert(change):
    """Wazuh JSON alertini yaratish"""
    # Change type'ga asosiy rule ID tanlash
    rule_id = 100201 if change["change_type"] == "REPLACED" else 100202
    
    alert_data = {
        "scan_type": "hw_change_detection",
        "agent_id": change["agent_id"],
        "hostname": change["hostname"],
        "change_time": change["change_time"],
        "component": change["component"],
        "field_name": change["field_name"],
        "old_value": change.get("old_value", ""),
        "new_value": change.get("new_value", ""),
        "change_type": change["change_type"],
        "rule_id": rule_id
    }
    return alert_data


def _send_to_wazuh_queue(socket_path, alert_data):
    """Wazuh queue socketiga JSON alert yuborish"""
    import socket as sock_module
    try:
        # Agent message format: id:command:data
        # Bizning case'da: socket orqali JSON yuborialadi
        msg = json.dumps(alert_data, ensure_ascii=False)
        
        # Socket orqali yuborish (unix domain socket)
        try:
            s = sock_module.socket(sock_module.AF_UNIX, sock_module.SOCK_DGRAM)
            s.connect(socket_path)
            s.send(msg.encode())
            s.close()
        except Exception:
            # Backup: File orqali yozish (direct)
            with open("/tmp/hw_changes_queue.log", "a") as f:
                f.write(f"{msg}\n")
    except Exception as e:
        print(f"{YELLOW}[!] Queue yozish xatosi: {e}{NC}")


# ============================================================
# CLI buyruqlari
# ============================================================
def show_stats():
    """Database statistikasi"""
    conn = init_database()
    cursor = conn.cursor()

    print(f"\n{CYAN}{'='*60}{NC}")
    print(f"{BOLD}  HW-DETECTOR DATABASE STATISTIKASI{NC}")
    print(f"{CYAN}{'='*60}{NC}\n")

    cursor.execute("SELECT COUNT(*) FROM pc_inventory")
    print(f"  Jami PC lar:              {cursor.fetchone()[0]}")

    cursor.execute("SELECT COUNT(*) FROM hardware_history")
    print(f"  Jami scan yozuvlari:      {cursor.fetchone()[0]}")

    cursor.execute("SELECT COUNT(*) FROM hardware_changes")
    print(f"  Jami o'zgarish yozuvlari: {cursor.fetchone()[0]}")

    cursor.execute("SELECT COUNT(*) FROM pc_inventory WHERE last_verdict='TAMPERED'")
    tampered = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM pc_inventory WHERE last_verdict='CLEAN'")
    clean = cursor.fetchone()[0]

    print(f"\n  {RED}TAMPERED (soxtalashtirish): {tampered}{NC}")
    print(f"  {GREEN}CLEAN (toza):              {clean}{NC}")

    # Oxirgi skanlar
    print(f"\n{YELLOW}  Oxirgi 5 ta scan:{NC}")
    cursor.execute("""
        SELECT hostname, scan_time, verdict, tampering_label 
        FROM hardware_history ORDER BY scan_time DESC LIMIT 5
    """)
    for row in cursor.fetchall():
        v_color = RED if row[2] == "TAMPERED" else GREEN
        print(f"    {row[0]:20s} {row[1]:25s} {v_color}{row[2]:10s}{NC} {row[3]}")

    conn.close()
    print()


def dump_inventory():
    """Barcha PC malumotlari"""
    conn = init_database()
    cursor = conn.cursor()

    print(f"\n{CYAN}{'='*70}{NC}")
    print(f"{BOLD}  BARCHA PC LAR HARDWARE MA'LUMOTLARI{NC}")
    print(f"{CYAN}{'='*70}{NC}\n")

    cursor.execute("""
        SELECT p.agent_id, p.hostname, p.last_seen, p.last_verdict, p.scan_count,
               h.cpu_description, h.ram_description, h.gpu_description,
               h.tampering_label, h.benchmark_score,
               h.board_manufacturer, h.board_product,
               h.registry_tampered
        FROM pc_inventory p
        LEFT JOIN hardware_history h ON h.agent_id = p.agent_id
            AND h.scan_time = (SELECT MAX(scan_time) FROM hardware_history WHERE agent_id = p.agent_id)
        ORDER BY p.hostname
    """)

    for row in cursor.fetchall():
        v_color = RED if row[3] == "TAMPERED" else GREEN
        reg_label = f"{RED}SOXTALASHTIRILGAN{NC}" if row[12] else f"{GREEN}HAQIQIY{NC}"

        print(f"  {BOLD}PC: {row[1]}{NC} (Agent ID: {row[0]})")
        print(f"    Oxirgi scan:    {row[2]}")
        print(f"    Scan soni:      {row[4]}")
        print(f"    Verdict:        {v_color}{row[3]}{NC}")
        print(f"    Registr holati: {reg_label}")
        print(f"    CPU:            {row[5] or 'N/A'}")
        print(f"    RAM:            {row[6] or 'N/A'}")
        print(f"    GPU:            {row[7] or 'N/A'}")
        print(f"    Board:          {row[10] or ''} {row[11] or ''}")
        print(f"    Benchmark:      {row[9] or 0}")
        print(f"    {'â”€'*50}")

    conn.close()
    print()


def show_history(agent_id):
    """Bitta PC ning hardware tarixi"""
    conn = init_database()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT hostname FROM pc_inventory WHERE agent_id = ?
    """, (agent_id,))
    row = cursor.fetchone()
    if not row:
        print(f"{RED}[!] Agent {agent_id} topilmadi{NC}")
        conn.close()
        return

    hostname = row[0]
    print(f"\n{CYAN}{'='*60}{NC}")
    print(f"{BOLD}  {hostname} (Agent: {agent_id}) â€” HARDWARE TARIXI{NC}")
    print(f"{CYAN}{'='*60}{NC}\n")

    cursor.execute("""
        SELECT scan_time, cpu_description, ram_description, gpu_description,
               verdict, tampering_label, hw_fingerprint, benchmark_score
        FROM hardware_history
        WHERE agent_id = ?
        ORDER BY scan_time DESC
        LIMIT 20
    """, (agent_id,))

    for row in cursor.fetchall():
        v_color = RED if row[4] == "TAMPERED" else GREEN
        print(f"  {YELLOW}[{row[0]}]{NC}")
        print(f"    CPU:  {row[1]}")
        print(f"    RAM:  {row[2]}")
        print(f"    GPU:  {row[3]}")
        print(f"    Status: {v_color}{row[4]}{NC} | {row[5]}")
        print(f"    Fingerprint: {row[6][:24]}...")
        print()

    # O'zgarishlar
    cursor.execute("""
        SELECT change_time, component, field_name, old_value, new_value, change_type
        FROM hardware_changes
        WHERE agent_id = ?
        ORDER BY change_time DESC
        LIMIT 20
    """, (agent_id,))
    changes = cursor.fetchall()

    if changes:
        print(f"\n  {RED}O'ZGARISHLAR TARIXI:{NC}\n")
        for c in changes:
            print(f"  {YELLOW}[{c[0]}]{NC} {c[1]} â€” {c[5]}")
            print(f"    Oldingi: {c[3]}")
            print(f"    Hozirgi: {c[4]}")
            print()

    conn.close()


def show_changes():
    """Barcha o'zgarishlar ro'yxati"""
    conn = init_database()
    cursor = conn.cursor()

    print(f"\n{RED}{'='*70}{NC}")
    print(f"{BOLD}  HARDWARE O'ZGARISHLAR JURNALI{NC}")
    print(f"{RED}{'='*70}{NC}\n")

    cursor.execute("""
        SELECT change_time, hostname, agent_id, component, field_name,
               old_value, new_value, change_type
        FROM hardware_changes
        ORDER BY change_time DESC
        LIMIT 50
    """)

    rows = cursor.fetchall()
    if not rows:
        print(f"  {GREEN}Hozircha o'zgarish topilmadi{NC}")
    else:
        for r in rows:
            type_color = RED if r[7] == "REPLACED" else YELLOW
            print(f"  {YELLOW}[{r[0]}]{NC} {BOLD}{r[1]}{NC} (Agent: {r[2]})")
            print(f"    {r[3]} â€” {type_color}{r[7]}{NC}")
            print(f"    Oldingi: {r[5]}")
            print(f"    Hozirgi: {r[6]}")
            print()

    conn.close()


# ============================================================
# Main
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="HW-Detector: Hardware Change Detector â€” SQLite database boshqaruvi"
    )
    parser.add_argument("--process", action="store_true",
                       help="alerts.json dan yangi eventlarni o'qib qayta ishlash")
    parser.add_argument("--stats", action="store_true",
                       help="Database statistikasi")
    parser.add_argument("--dump", action="store_true",
                       help="Barcha PC lar hardware ma'lumotlari")
    parser.add_argument("--history", metavar="AGENT_ID",
                       help="Bitta PC hardware tarixi (agent ID kerak)")
    parser.add_argument("--changes", action="store_true",
                       help="Barcha hardware o'zgarishlar ro'yxati")
    parser.add_argument("--test", action="store_true",
                       help="Test rejimi")
    parser.add_argument("--db-path", metavar="PATH",
                       help="Custom database path")

    args = parser.parse_args()

    if args.db_path:
        global DB_PATH
        DB_PATH = args.db_path

    if args.test:
        _run_test()
    elif args.process:
        process_alerts()
    elif args.stats:
        show_stats()
    elif args.dump:
        dump_inventory()
    elif args.history:
        show_history(args.history)
    elif args.changes:
        show_changes()
    else:
        parser.print_help()


def _run_test():
    """Test rejimi"""
    global DB_PATH, ACTIVE_RESPONSE_LOG
    DB_PATH = "/tmp/hw_inventory_test.db"
    ACTIVE_RESPONSE_LOG = "/tmp/hw_test_active_response.log"

    # Eski test DB ni tozalash
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = init_database()
    print(f"\n{GREEN}[+] Test database yaratildi: {DB_PATH}{NC}")

    # 1-scan
    scan1_data = {
        "scan_type": "hw_fraud_detection", "version": "2.0",
        "hostname": "LAB-PC-05", "verdict": "CLEAN",
        "tampering_label": "HAQIQIY", "hw_fingerprint": "fp_original_123",
        "cpu": {"real_cpuid": "Intel(R) Core(TM) i7-12700K", "reported_wmi": "Intel(R) Core(TM) i7-12700K",
                "reported_registry": "Intel(R) Core(TM) i7-12700K", "real_cores": 12, "real_threads": 20,
                "real_max_mhz": 3600, "tampered": False, "registry_tampered": False,
                "description": "Intel(R) Core(TM) i7-12700K"},
        "ram": {"real_smbios_gb": 16, "reported_wmi_gb": 16, "real_total_mb": 16384,
                "tampered": False, "stick_count": 2,
                "sticks": [
                    {"slot": "DIMM0", "size_mb": 8192, "size_gb": 8, "speed_mhz": 4800,
                     "type": "DDR5", "manufacturer": "Kingston", "serial": "SN001",
                     "description": "Kingston 8GB DDR5 4800MHz"},
                    {"slot": "DIMM1", "size_mb": 8192, "size_gb": 8, "speed_mhz": 4800,
                     "type": "DDR5", "manufacturer": "Kingston", "serial": "SN002",
                     "description": "Kingston 8GB DDR5 4800MHz"}
                ],
                "description": "Kingston 16GB DDR5 4800MHz"},
        "gpu": {"devices": [], "tampered": False, "description": "NVIDIA GeForce RTX 3060"},
        "registry_tampering": {"detected": False, "label": "HAQIQIY", "details": []},
        "system": {"board_manufacturer": "ASUS", "board_product": "Z690", "board_serial": "BS001",
                   "manufacturer": "ASUS", "product": "Desktop", "serial": "SYS001"},
        "benchmark": {"score": 250000}
    }

    _save_scan(conn, "005", "LAB-PC-05", scan1_data)
    print(f"{GREEN}[+] Scan 1 saqlandi (asl holat){NC}")
    print(f"    CPU: {scan1_data['cpu']['description']}")
    print(f"    RAM: {scan1_data['ram']['description']}")
    print(f"    GPU: {scan1_data['gpu']['description']}")

    # 2-scan: RAM almashtirilgan
    import copy
    scan2_data = copy.deepcopy(scan1_data)
    scan2_data["hw_fingerprint"] = "fp_changed_456"
    scan2_data["verdict"] = "TAMPERED"
    scan2_data["tampering_label"] = "SOXTALASHTIRILGAN"
    scan2_data["ram"]["real_smbios_gb"] = 4
    scan2_data["ram"]["real_total_mb"] = 4096
    scan2_data["ram"]["tampered"] = True
    scan2_data["ram"]["stick_count"] = 1
    scan2_data["ram"]["sticks"] = [{
        "slot": "DIMM0", "size_mb": 4096, "size_gb": 4, "speed_mhz": 3200,
        "type": "DDR4", "manufacturer": "Kingston", "serial": "SN999",
        "description": "Kingston 4GB DDR4 3200MHz"
    }]
    scan2_data["ram"]["description"] = "Kingston 4GB DDR4 3200MHz"

    cursor = conn.cursor()
    cursor.execute("SELECT * FROM hardware_history WHERE agent_id = ? ORDER BY scan_time DESC LIMIT 1", ("005",))
    old_scan = cursor.fetchone()
    if old_scan:
        old_scan = dict(old_scan)

    changes = _detect_changes("005", "LAB-PC-05", old_scan, scan2_data)
    _save_scan(conn, "005", "LAB-PC-05", scan2_data)

    if changes:
        _save_changes(conn, changes)
        _send_alerts(changes)

    print(f"\n{YELLOW}[+] Scan 2 saqlandi (RAM almashtirilgan!){NC}")
    print(f"    {RED}O'zgarishlar topildi: {len(changes)} ta{NC}")
    for c in changes:
        print(f"\n    {BOLD}[{c['component']}] {c['change_type']}:{NC}")
        print(f"      Oldingi: {c['old_value']}")
        print(f"      Hozirgi: {c['new_value']}")

    conn.close()
    print(f"\n{GREEN}[+] Test muvaffaqiyatli tugadi!{NC}")
    print(f"    Database: {DB_PATH}")
    if os.path.exists(ACTIVE_RESPONSE_LOG):
        print(f"    Alertlar: {ACTIVE_RESPONSE_LOG}")
    print()


if __name__ == "__main__":
    main()
