def _send_alerts(conn, changes):
    try:
        alert_socket = "/var/ossec/queue/sockets/queue"
        for c in changes:
            try:
                with open(ACTIVE_RESPONSE_LOG, "a") as f:
                    f.write(f"hw_change: {json.dumps(c, ensure_ascii=False)}\n")
            except Exception:
                pass
            try:
                wazuh_alert = _create_wazuh_json_alert(c)
                if os.path.exists(alert_socket):
                    _send_to_wazuh_queue(alert_socket, wazuh_alert)
                else:
                    _send_to_wazuh_queue(alert_socket, wazuh_alert)
            except Exception as e:
                print(f"{YELLOW}[!] Wazuh alert yuborish xatosi: {e}{NC}")
        _mark_alerts_sent(conn, changes)
    except Exception as e:
        print(f"{RED}[!] Alert yozish xatosi: {e}{NC}")
