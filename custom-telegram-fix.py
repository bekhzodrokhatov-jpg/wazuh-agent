#!/usr/bin/env python3
import json
import sqlite3
import sys
import time

import requests

# --- CONFIGURATION ---
TOKEN = "8083742152:AAEYW0mAB_Mq_wFdm_SuBiMcj5TfSHztYmY"
CHAT_ID = "-1003744477260"
DB_PATH = "/var/ossec/var/db/hw_inventory.db"
STATE_PATH = "/tmp/custom_telegram_state.json"
LOG_PATH = "/tmp/telegram.log"


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)


def _extract_data(alert):
    data = alert.get("data", {})
    if isinstance(data, dict) and data.get("scan_type"):
        return data

    full_log = alert.get("full_log", "")
    if isinstance(full_log, str) and full_log:
        try:
            return json.loads(full_log)
        except Exception:
            pass
    # Strip known Wazuh log prefixes (e.g. "hw_detector: {...}\r")
    if isinstance(full_log, str) and full_log:
        stripped = full_log.strip()
        for prefix in ("hw_detector: ", "hw_detector:", "hw_change: ", "hw_change:"):
            if stripped.startswith(prefix):
                stripped = stripped[len(prefix):].strip()
                break
        try:
            return json.loads(stripped)
        except Exception:
            pass

    win_msg = (
        alert.get("data", {})
        .get("win", {})
        .get("eventdata", {})
        .get("message")
    )
    if isinstance(win_msg, str) and win_msg:
        try:
            return json.loads(win_msg)
        except Exception:
            pass

    return data if isinstance(data, dict) else {}


def _load_state():
    state = _read_json(STATE_PATH)
    if not isinstance(state, dict):
        state = {}
    state.setdefault("verdict_by_host", {})
    state.setdefault("hw_change_batches", {})
    return state


def _save_state(state):
    # Keep state bounded so /tmp does not grow forever.
    batches = state.get("hw_change_batches", {})
    if len(batches) > 1000:
        keep = dict(sorted(batches.items(), key=lambda kv: kv[1], reverse=True)[:500])
        state["hw_change_batches"] = keep
    _write_json(STATE_PATH, state)


def _latest_inventory(agent_id, hostname):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    if agent_id:
        cur.execute(
            """
            SELECT * FROM hardware_history
            WHERE agent_id = ?
            ORDER BY scan_time DESC
            LIMIT 1
            """,
            (agent_id,),
        )
        row = cur.fetchone()
        if row:
            conn.close()
            return dict(row)

    cur.execute(
        """
        SELECT * FROM hardware_history
        WHERE hostname = ?
        ORDER BY scan_time DESC
        LIMIT 1
        """,
        (hostname,),
    )
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else {}


def _batch_changes(agent_id, hostname, change_time):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        """
        SELECT component, field_name, old_value, new_value, change_type
        FROM hardware_changes
        WHERE hostname = ? AND change_time = ?
        ORDER BY id ASC
        """,
        (hostname, change_time),
    )
    rows = [dict(r) for r in cur.fetchall()]

    if not rows and agent_id:
        cur.execute(
            """
            SELECT component, field_name, old_value, new_value, change_type
            FROM hardware_changes
            WHERE agent_id = ? AND change_time = ?
            ORDER BY id ASC
            """,
            (agent_id, change_time),
        )
        rows = [dict(r) for r in cur.fetchall()]

    conn.close()
    return rows


def _safe_json(text, default):
    if not text:
        return default
    try:
        return json.loads(text)
    except Exception:
        return default


def _format_slots(ram_obj):
    sticks = ram_obj.get("sticks", []) if isinstance(ram_obj, dict) else []
    if not isinstance(sticks, list) or not sticks:
        return ["- Slotlar haqida ma'lumot topilmadi"]

    lines = []
    for i, s in enumerate(sticks, 1):
        if not isinstance(s, dict):
            continue
        size = s.get("size_gb", "N/A")
        man = s.get("manufacturer", "Unknown")
        serial = s.get("serial", "N/A")
        lines.append(f"- Slot {i}: {size}GB {man} (S/N: {serial})")

    return lines if lines else ["- Slotlar haqida ma'lumot topilmadi"]


def _format_detailed_message(hostname, timestamp, verdict, cpu, ram, gpu, system_info, registry_tampered, changes):
    status = verdict or "UNKNOWN"
    if status == "TAMPERED":
        status_line = "\U0001f6a8 STATUS: TAMPERED"
    elif status in ("HARDWARE_CHANGED", "CHANGED", "UNKNOWN"):
        status_line = "\u26a0\ufe0f STATUS: HARDWARE_CHANGED"
    else:
        status_line = "\u2705 STATUS: CLEAN"

    real_cpu = cpu.get("real_cpuid") or cpu.get("real") or "N/A"
    fake_cpu = cpu.get("reported_registry") or cpu.get("reported_wmi") or "N/A"

    reg_text = "HA \u26a0\ufe0f" if registry_tampered else "YO'Q"
    fake_suffix = " \u274c" if registry_tampered else ""

    ram_total = ram.get("real_smbios_gb") if isinstance(ram, dict) else None
    ram_total = ram_total if ram_total not in (None, "") else "N/A"

    gpu_model = gpu.get("description") if isinstance(gpu, dict) else None
    gpu_model = gpu_model if gpu_model else "N/A"

    board_m = system_info.get("manufacturer", "N/A") if isinstance(system_info, dict) else "N/A"
    board_p = system_info.get("product", "N/A") if isinstance(system_info, dict) else "N/A"
    board_s = system_info.get("board_serial", "N/A") if isinstance(system_info, dict) else "N/A"

    lines = [
        "\U0001f534 BATAFSIL XAVFSIZLIK TAHLILI OS: HAQIQIY HOLAT",
        f"\U0001f4bb PC: {hostname}",
        f"\U0001f552 Vaqt: {timestamp}",
        "",
        status_line,
        "",
        "\U0001f9e0 PROTSESSOR (REAL vs FAKE):",
        f"- Haqiqiy: {real_cpu}",
        f"- Soxtasi: {fake_cpu}{fake_suffix}",
        f"- Reystrdan soxtalashtirilganmi? {reg_text}",
        "",
        "\U0001f4df OPERATIV XOTIRA (RAM):",
        f"- Umumiy: {ram_total} GB",
    ]
    lines.extend(_format_slots(ram))

    lines.extend(
        [
            "",
            "\U0001f3ae VIDEO KARTA (GPU):",
            f"- Model: {gpu_model}",
            "",
            "\u2699\ufe0f MOTHERBOARD:",
            f"- {board_m} {board_p}",
            f"- S/N: {board_s}",
        ]
    )

    if changes:
        lines.append("")
        lines.append("\U0001f527 HARDWARE O'ZGARISHLAR:")
        for c in changes:
            comp = c.get("component", "HW")
            ctype = c.get("change_type", "CHANGED")
            old_v = c.get("old_value", "") or "N/A"
            new_v = c.get("new_value", "") or "N/A"
            lines.append(f"- [{comp}] {ctype}: {old_v} -> {new_v}")

    lines.append("")
    if registry_tampered:
        lines.append("\u274c DIAGNOZ: Kompyuter operatsion tizimi (Reystr) ma'lumotlari soxtalashtirilganligi aniqlandi.")
    elif verdict == "TAMPERED":
        lines.append("\u274c DIAGNOZ: CPU/RAM/GPU real holat bilan WMI/Reystr ma'lumotlari mos kelmaydi, soxtalashtirish aniqlandi.")
    elif changes:
        lines.append("\u26a0\ufe0f DIAGNOZ: Hardware almashtirilgani yoki konfiguratsiya o'zgargani aniqlandi.")
    else:
        lines.append("\u2705 DIAGNOZ: Kompyuterning hardware holati to'g'ri.")
    return "\n".join(lines)


def _send_telegram(message, timestamp):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    resp = requests.post(
        url,
        json={"chat_id": CHAT_ID, "text": message, "disable_web_page_preview": True},
        timeout=20,
    )
    with open(LOG_PATH, "a", encoding="utf-8") as lf:
        lf.write(f"{timestamp} status={resp.status_code} body={resp.text}\n")


def main():
    alert_file = sys.argv[1]
    alert = _read_json(alert_file)
    if not alert:
        return

    data = _extract_data(alert)
    scan_type = data.get("scan_type")
    if scan_type not in ("hw_fraud_detection", "hw_change_detection"):
        return

    agent_name = alert.get("agent", {}).get("name", "Manager")
    hostname = data.get("hostname") or agent_name
    agent_id = data.get("agent_id") or alert.get("agent", {}).get("id", "")
    timestamp = alert.get("timestamp", "N/A")

    state = _load_state()

    if scan_type == "hw_fraud_detection":
        verdict = data.get("verdict", "UNKNOWN")
        prev = state["verdict_by_host"].get(hostname)
        if prev == verdict:
            return

        cpu = data.get("cpu", {}) if isinstance(data.get("cpu"), dict) else {}
        ram = data.get("ram", {}) if isinstance(data.get("ram"), dict) else {}
        gpu = data.get("gpu", {}) if isinstance(data.get("gpu"), dict) else {}
        system_info = data.get("system", {}) if isinstance(data.get("system"), dict) else {}
        reg_tampered = bool(data.get("registry_tampered") or cpu.get("registry_tampered"))

        message = _format_detailed_message(
            hostname,
            timestamp,
            verdict,
            cpu,
            ram,
            gpu,
            system_info,
            reg_tampered,
            [],
        )
        _send_telegram(message, timestamp)
        state["verdict_by_host"][hostname] = verdict
        _save_state(state)
        return

    change_time = data.get("change_time", "")
    batch_key = f"{hostname}|{change_time}"
    if state["hw_change_batches"].get(batch_key):
        return

    inv = _latest_inventory(agent_id, hostname)
    cpu = {
        "real_cpuid": inv.get("cpu_real", "N/A"),
        "reported_registry": inv.get("cpu_reported_registry", "N/A"),
        "registry_tampered": bool(inv.get("cpu_registry_tampered", 0)),
    }
    ram = {
        "real_smbios_gb": inv.get("ram_real_gb", "N/A"),
        "sticks": _safe_json(inv.get("ram_sticks_json", "[]"), []),
    }
    gpu = {
        "description": inv.get("gpu_description", "N/A"),
    }
    system_info = {
        "manufacturer": inv.get("board_manufacturer", "N/A"),
        "product": inv.get("board_product", "N/A"),
        "board_serial": inv.get("board_serial", "N/A"),
    }
    verdict = inv.get("verdict", "HARDWARE_CHANGED") if inv else "HARDWARE_CHANGED"
    reg_tampered = bool(inv.get("registry_tampered", 0)) if inv else False

    changes = _batch_changes(agent_id, hostname, change_time)
    if not changes:
        changes = [
            {
                "component": data.get("component", "HW"),
                "change_type": data.get("change_type", "CHANGED"),
                "old_value": data.get("old_value", "N/A"),
                "new_value": data.get("new_value", "N/A"),
            }
        ]

    message = _format_detailed_message(
        hostname,
        timestamp,
        verdict,
        cpu,
        ram,
        gpu,
        system_info,
        reg_tampered,
        changes,
    )
    _send_telegram(message, timestamp)

    state["hw_change_batches"][batch_key] = int(time.time())
    _save_state(state)


if __name__ == "__main__":
    main()
