#!/bin/bash

# HW-Detector v2.0 - Deploy and Management Script (Fixed Syntax)
# -----------------------------------------------------------

# Ranglar
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

WAZUH_DIR="/var/ossec"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Log funksiyalari
log_info() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; exit 1; }
log_step() { echo -e "${BLUE}[*]${NC} ${BOLD}$1${NC}"; }

# -----------------------------------------------------------
# 3-QADAM: Natijalarni ko'rish
# -----------------------------------------------------------

show_results() {
    log_step "===== NATIJALAR ====="
    echo ""

    ALERTS_FILE="$WAZUH_DIR/logs/alerts/alerts.json"
    if [ ! -f "$ALERTS_FILE" ]; then
        log_warn "Alerts fayl topilmadi: $ALERTS_FILE"
        return
    fi
    
    echo -e "${YELLOW}${BOLD}--- DEBUG MA'LUMOT (Tekshirish uchun) ---${NC}"
    RAW_ALERTS=$(grep "hw_fraud_detection" "$ALERTS_FILE" | tail -2)
    if [ -z "$RAW_ALERTS" ]; then
        echo "Linux serverga (alerts.json) GA HICH NIMA KELMAGAN! Sabab Windowsda!"
    else
        echo "Linux serverga ma'lumot kelgan! Natijalarni parslash..."
    fi
    echo -e "${YELLOW}${BOLD}-----------------------------------------${NC}"
    echo ""

    log_info "Oxirgi HW-Detector natijalar..."
    echo ""

    # TAMPERED natijalar
    echo -e "${RED}${BOLD}========== SOXTALASHTIRILGAN PC LAR ==========${NC}"
    echo ""
    TAMPERED=$(grep "hw_fraud_detection" "$ALERTS_FILE" | grep "TAMPERED" | tail -100)
    if [ -z "$TAMPERED" ]; then
        echo "  (hozircha fraud aniqlangan natija yo'q)"
    else
        echo "$TAMPERED" | python3 -c "
import sys, json
seen = set()
for line in sys.stdin:
    try:
        alert = json.loads(line.strip())
        agent = alert.get('agent', {}).get('name', 'N/A')
        agent_id = alert.get('agent', {}).get('id', 'N/A')
        
        # HW ma'lumotlarini qidirish (Direct JSON or EventChannel)
        hw = alert.get('data', {})
        if 'scan_type' not in hw:
            # Try EventChannel path
            hw_str = hw.get('win', {}).get('eventdata', {}).get('data', '')
            if 'hw_detector: ' in hw_str:
                hw = json.loads(hw_str.split('hw_detector: ')[1])
            elif hw_str.startswith('{'):
                hw = json.loads(hw_str)
        
        if hw.get('scan_type') != 'hw_fraud_detection': continue
        if agent in seen: continue
        seen.add(agent)
        
        label = hw.get('verdict', 'TAMPERED')
        cpu = hw.get('cpu', {})
        ram = hw.get('ram', {})
        
        print(f'  PC: {agent} (Agent: {agent_id})  |  Holat: {label}')
        if hw.get('tampered'):
            print(f'    CPU HAQIQIY:  {cpu.get(\"real\", \"N/A\")}')
            print(f'    CPU REPORTED: {cpu.get(\"reported_wmi\", \"N/A\")}')
        if hw.get('registry_tampered'):
            print(f'    REGISTRY:     SOXTALASHTIRISH ANIQLANDI!')
        print()
    except Exception as e:
        pass
" 2>/dev/null
    fi

    echo ""
    echo -e "${GREEN}${BOLD}========== TOZA PC LAR ==========${NC}"
    echo ""
    CLEAN=$(grep "hw_fraud_detection" "$ALERTS_FILE" | grep "CLEAN" | tail -100)
    if [ -z "$CLEAN" ]; then
        echo "  (hozircha clean natija yo'q)"
    else
        echo "$CLEAN" | python3 -c "
import sys, json
seen = set()
for line in sys.stdin:
    try:
        alert = json.loads(line.strip())
        agent = alert.get('agent', {}).get('name', 'N/A')
        
        hw = alert.get('data', {})
        if 'scan_type' not in hw:
            hw_str = hw.get('win', {}).get('eventdata', {}).get('data', '')
            if 'hw_detector: ' in hw_str:
                hw = json.loads(hw_str.split('hw_detector: ')[1])
            elif hw_str.startswith('{'):
                hw = json.loads(hw_str)

        if hw.get('scan_type') != 'hw_fraud_detection': continue
        if agent in seen: continue
        seen.add(agent)
        
        cpu = hw.get('cpu', {}).get('real', 'N/A')
        ram = hw.get('ram', {}).get('total_gb', 'N/A')
        print(f'  [OK] {agent}: CPU={cpu}, RAM={ram}GB')
    except Exception as e:
        pass
" 2>/dev/null
    fi

    echo ""

    # Hardware o'zgarishlar
    echo -e "${YELLOW}${BOLD}========== HARDWARE O'ZGARISHLAR ==========${NC}"
    echo ""
    CHANGES=$(grep "hw_change" "$ALERTS_FILE" 2>/dev/null | tail -20)
    if [ -z "$CHANGES" ]; then
        echo "  (hozircha hardware o'zgarishi topilmadi)"
    else
        echo "$CHANGES" | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        data = json.loads(line.strip())
        d = data.get('data', {})
        print(f'  [{d.get(\"component\",\"\")}] {d.get(\"hostname\",\"\")} — {d.get(\"change_type\",\"\")}')
        print(f'    Oldingi: {d.get(\"old_value\",\"\")}')
        print(f'    Hozirgi: {d.get(\"new_value\",\"\")}')
        print()
    except Exception as e:
        pass
" 2>/dev/null
    fi

    echo ""

    # Qisqa statistika
    TOTAL_TAMPERED=$(grep "hw_fraud_detection" "$ALERTS_FILE" 2>/dev/null | grep "TAMPERED" | python3 -c "
import sys, json
seen = set()
for line in sys.stdin:
    try: seen.add(json.loads(line).get('agent',{}).get('name',''))
    except: pass
print(len(seen))" 2>/dev/null)

    TOTAL_CLEAN=$(grep "hw_fraud_detection" "$ALERTS_FILE" 2>/dev/null | grep "CLEAN" | python3 -c "
import sys, json
seen = set()
for line in sys.stdin:
    try: seen.add(json.loads(line).get('agent',{}).get('name',''))
    except: pass
print(len(seen))" 2>/dev/null)

    echo -e "  Jami: ${RED}${TOTAL_TAMPERED:-0} ta SOXTALASHTIRILGAN${NC} / ${GREEN}${TOTAL_CLEAN:-0} ta TOZA${NC}"
    echo ""
    log_step "===== NATIJALAR TUGADI ====="
    echo ""
}

# -----------------------------------------------------------
# CLI Boshqaruvi
# -----------------------------------------------------------

case "$1" in
    deploy)
        # log_step "DEPLOY v2.0 BOSHLANDI"
        # ... (Bu qismlar sizda bor deb hisoblaymiz, hozir FAQAT show_results ni fix qilyapmiz)
        show_results
        ;;
    results)
        show_results
        ;;
    *)
        echo "Usage: $0 {deploy|results|db}"
        exit 1
        ;;
esac
