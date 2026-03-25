#!/bin/bash
# ============================================================
# HW-Detector Wazuh Deployment Script
# Wazuh Linux serverda ishga tushiring
# Bu skript HW-Detector ni barcha Windows agentlarga deploy qiladi
# va bir vaqtda skanerlashni boshlaydi
# ============================================================
#
# Ishlatish:
#   chmod +x deploy_hw_detector.sh
#   sudo ./deploy_hw_detector.sh
#
# Parametrlar:
#   deploy   - Skript va konfiguratsiyalarni o'rnatish
#   scan     - Barcha agentlarda hoziroq skanerlashni boshlash
#   results  - Natijalarni ko'rish
#   all      - Deploy + Scan + Results
#
# Misol: sudo ./deploy_hw_detector.sh all

set -e

WAZUH_DIR="/var/ossec"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[X]${NC} $1"; }
log_step()  { echo -e "${CYAN}[*]${NC} $1"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Bu skriptni root sifatida ishga tushiring: sudo $0"
        exit 1
    fi
}

check_wazuh() {
    if [ ! -d "$WAZUH_DIR" ]; then
        log_error "Wazuh Manager topilmadi: $WAZUH_DIR mavjud emas"
        exit 1
    fi
    if ! systemctl is-active --quiet wazuh-manager 2>/dev/null; then
        log_warn "wazuh-manager servisi ishlamayotgan bolishi mumkin"
    fi
}

# ============================================================
# 1-QADAM: Deploy - fayllarni joylashtirish
# ============================================================
deploy() {
    log_step "===== DEPLOY BOSHLANDI ====="
    echo ""

    # 1. Decoder ni joylashtirish
    log_info "Custom decoder joylashtirilmoqda..."
    cp "$SCRIPT_DIR/server/hw_detector_decoder.xml" "$WAZUH_DIR/etc/decoders/hw_detector_decoder.xml"
    chown wazuh:wazuh "$WAZUH_DIR/etc/decoders/hw_detector_decoder.xml"
    chmod 660 "$WAZUH_DIR/etc/decoders/hw_detector_decoder.xml"
    log_info "Decoder joylashtirildi: $WAZUH_DIR/etc/decoders/hw_detector_decoder.xml"

    # 2. Rules ni joylashtirish
    log_info "Custom rules joylashtirilmoqda..."
    cp "$SCRIPT_DIR/server/hw_detector_rules.xml" "$WAZUH_DIR/etc/rules/hw_detector_rules.xml"
    chown wazuh:wazuh "$WAZUH_DIR/etc/rules/hw_detector_rules.xml"
    chmod 660 "$WAZUH_DIR/etc/rules/hw_detector_rules.xml"
    log_info "Rules joylashtirildi: $WAZUH_DIR/etc/rules/hw_detector_rules.xml"

    # 3. Agent.conf ga wodle konfiguratsiyasini qoshish
    log_info "Agent konfiguratsiyasi tayyorlanmoqda..."

    # Default shared guruhga PS1 skriptni joylashtirish
    SHARED_DIR="$WAZUH_DIR/etc/shared/default"
    mkdir -p "$SHARED_DIR"

    # agent.conf ni yangilash (agar mavjud bolsa, hw_detector qismini qoshish)
    AGENT_CONF="$SHARED_DIR/agent.conf"
    if [ -f "$AGENT_CONF" ]; then
        if grep -q "hw_detector" "$AGENT_CONF"; then
            log_warn "agent.conf da hw_detector allaqachon mavjud, o'tkazib yuborildi"
        else
            log_info "Mavjud agent.conf ga hw_detector wodle qoshilmoqda..."
            # Oxirgi </agent_config> tagini topib, oldiga qoshish
            WODLE_BLOCK='  <!-- HW-Detector -->\n  <wodle name="command">\n    <disabled>no</disabled>\n    <tag>hw_detector</tag>\n    <command>Powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\\Program Files (x86)\\ossec-agent\\active-response\\bin\\HW-Detector-Wazuh.ps1"</command>\n    <interval>1h</interval>\n    <ignore_output>no</ignore_output>\n    <run_on_start>yes</run_on_start>\n    <timeout>120</timeout>\n  </wodle>'
            sed -i "/<\/agent_config>/i\\${WODLE_BLOCK}" "$AGENT_CONF"
        fi
    else
        log_info "Yangi agent.conf yaratilmoqda..."
        cp "$SCRIPT_DIR/server/agent.conf" "$AGENT_CONF"
    fi
    chown wazuh:wazuh "$AGENT_CONF"
    chmod 660 "$AGENT_CONF"

    # 4. PowerShell skriptini agentlarga tarqatish uchun tayyorlash
    log_info "PS1 skript agentlarga yuborish uchun tayyorlanmoqda..."
    log_warn "MUHIM: HW-Detector-Wazuh.ps1 ni har bir agentga quyidagi joyga joylashtiring:"
    echo ""
    echo "   C:\\Program Files (x86)\\ossec-agent\\active-response\\bin\\HW-Detector-Wazuh.ps1"
    echo ""
    echo "   Bu faylni tarqatish usullari:"
    echo "   a) GPO (Group Policy) orqali"
    echo "   b) SCCM/Intune orqali"
    echo "   c) Qolda har bir PC ga nusxalash"
    echo "   d) Quyidagi Wazuh API buyrugi bilan (pastda keltirilgan)"
    echo ""

    # 5. Wazuh Manager ni qayta yuklash
    log_info "Wazuh Manager qayta yuklanmoqda..."
    systemctl restart wazuh-manager 2>/dev/null || "$WAZUH_DIR/bin/wazuh-control" restart
    sleep 3
    log_info "Wazuh Manager qayta yuklandi"

    echo ""
    log_step "===== DEPLOY TUGADI ====="
    echo ""
}

# ============================================================
# 2-QADAM: Scan - barcha agentlarda hoziroq skanerlash
# ============================================================
scan_now() {
    log_step "===== SCAN BOSHLANDI ====="
    echo ""

    # Wazuh API token olish
    log_info "Wazuh API ga ulanilmoqda..."

    # API credentials
    API_USER="${WAZUH_API_USER:-wazuh-wui}"
    API_PASS="${WAZUH_API_PASS:-wazuh-wui}"
    API_HOST="${WAZUH_API_HOST:-localhost}"
    API_PORT="${WAZUH_API_PORT:-55000}"
    API_URL="https://${API_HOST}:${API_PORT}"

    # Token olish
    TOKEN=$(curl -s -k -u "${API_USER}:${API_PASS}" \
        -X POST "${API_URL}/security/user/authenticate" \
        2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])" 2>/dev/null)

    if [ -z "$TOKEN" ]; then
        log_error "API token olib bolmadi!"
        log_warn "API credentials ni tekshiring:"
        echo "   WAZUH_API_USER=$API_USER"
        echo "   WAZUH_API_PASS=***"
        echo "   WAZUH_API_HOST=$API_HOST"
        echo "   WAZUH_API_PORT=$API_PORT"
        echo ""
        log_warn "Credentials ni environment variable sifatida bering:"
        echo "   export WAZUH_API_USER=wazuh-wui"
        echo "   export WAZUH_API_PASS=your_password"
        echo "   sudo -E ./deploy_hw_detector.sh scan"
        echo ""

        # Alternativ: agent-control orqali
        log_info "Alternativ usul: agent.conf orqali run_on_start=yes ishlatilmoqda"
        log_info "Agentlarni restart qilish orqali skanerlash boshlanadi..."

        # Barcha agentlar royxatini olish
        AGENTS=$("$WAZUH_DIR/bin/agent_control" -l 2>/dev/null | grep -E "^   ID:" | awk '{print $2}' | tr -d ',')
        if [ -n "$AGENTS" ]; then
            for AGENT_ID in $AGENTS; do
                log_info "Agent $AGENT_ID ga restart signal yuborilmoqda..."
                "$WAZUH_DIR/bin/agent_control" -R "$AGENT_ID" 2>/dev/null || true
            done
            log_info "Barcha agentlarga restart signal yuborildi"
            log_info "Agentlar qayta ulanganda HW-Detector avtomatik ishga tushadi (run_on_start=yes)"
        else
            log_warn "Faol agentlar topilmadi"
        fi
        return
    fi

    log_info "API token muvaffaqiyatli olindi"

    # Barcha Windows agentlar royxati
    log_info "Windows agentlar royxati olinmoqda..."
    AGENTS_JSON=$(curl -s -k \
        -H "Authorization: Bearer $TOKEN" \
        -X GET "${API_URL}/agents?os.platform=windows&status=active&limit=500" 2>/dev/null)

    AGENT_IDS=$(echo "$AGENTS_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
items = data.get('data', {}).get('affected_items', [])
for a in items:
    print(a['id'])
" 2>/dev/null)

    if [ -z "$AGENT_IDS" ]; then
        log_warn "Faol Windows agentlar topilmadi"
        return
    fi

    AGENT_COUNT=$(echo "$AGENT_IDS" | wc -l)
    log_info "$AGENT_COUNT ta faol Windows agent topildi"
    echo ""

    # Har bir agentda wodle-command ni qayta ishga tushirish
    # Bu restart orqali run_on_start triggerlanadi
    for AID in $AGENT_IDS; do
        AGENT_NAME=$(echo "$AGENTS_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
items = data.get('data', {}).get('affected_items', [])
for a in items:
    if a['id'] == '$AID':
        print(a.get('name', 'Unknown'))
        break
" 2>/dev/null)
        log_info "Agent $AID ($AGENT_NAME) ga restart signal..."
        curl -s -k \
            -H "Authorization: Bearer $TOKEN" \
            -X PUT "${API_URL}/agents/${AID}/restart" >/dev/null 2>&1 || true
    done

    echo ""
    log_info "Barcha agentlarga restart signal yuborildi"
    log_info "Agentlar qayta ulanganda HW-Detector ishga tushadi (1-2 minut kutish)"
    log_step "===== SCAN TUGADI ====="
    echo ""
}

# ============================================================
# 3-QADAM: Results - natijalarni ko'rish
# ============================================================
show_results() {
    log_step "===== NATIJALAR ====="
    echo ""

    # alerts.json dan hw_detector yozuvlarini izlash
    ALERTS_FILE="$WAZUH_DIR/logs/alerts/alerts.json"
    if [ ! -f "$ALERTS_FILE" ]; then
        log_warn "Alerts fayl topilmadi: $ALERTS_FILE"
        log_info "Natijalar hali kelmagandir, bir necha daqiqa kutib qayta urinib koring"
        return
    fi

    log_info "Oxirgi HW-Detector natijalarni qidirish..."
    echo ""

    # TAMPERED natijalar
    echo -e "${RED}========== SOXTALASHTIRISH ANIQLANGAN PC LAR ==========${NC}"
    echo ""
    TAMPERED=$(grep "hw_detector" "$ALERTS_FILE" | grep "TAMPERED" | tail -50)
    if [ -z "$TAMPERED" ]; then
        echo "  (hozircha fraud aniqlangan natija yo'q)"
    else
        echo "$TAMPERED" | python3 -c "
import sys, json
seen = set()
for line in sys.stdin:
    try:
        data = json.loads(line.strip())
        agent = data.get('agent', {}).get('name', 'N/A')
        agent_id = data.get('agent', {}).get('id', 'N/A')
        hw_data = data.get('data', {})
        verdict = hw_data.get('verdict', 'N/A')
        if agent in seen:
            continue
        seen.add(agent)
        fraud_count = hw_data.get('fraud_count', 0)
        frauds = hw_data.get('frauds', [])
        cpu_real = hw_data.get('cpu', {}).get('real_cpuid', 'N/A')
        cpu_wmi = hw_data.get('cpu', {}).get('reported_wmi', 'N/A')
        ram_real = hw_data.get('ram', {}).get('real_kernel_gb', 'N/A')
        ram_wmi = hw_data.get('ram', {}).get('reported_wmi_gb', 'N/A')
        ts = hw_data.get('timestamp', 'N/A')
        print(f'  PC: {agent} (Agent ID: {agent_id})')
        print(f'  Sana: {ts}')
        print(f'  Fraud soni: {fraud_count}')
        if hw_data.get('cpu', {}).get('tampered'):
            print(f'    CPU HAQIQIY:  {cpu_real}')
            print(f'    CPU WMI:      {cpu_wmi}')
        if hw_data.get('ram', {}).get('tampered'):
            print(f'    RAM HAQIQIY:  {ram_real} GB')
            print(f'    RAM WMI:      {ram_wmi} GB')
        for f in frauds:
            print(f'    >> {f}')
        print()
    except:
        pass
" 2>/dev/null
    fi

    echo ""
    echo -e "${GREEN}========== TOZA PC LAR ==========${NC}"
    echo ""
    CLEAN=$(grep "hw_detector" "$ALERTS_FILE" | grep "CLEAN" | tail -50)
    if [ -z "$CLEAN" ]; then
        echo "  (hozircha clean natija yo'q)"
    else
        echo "$CLEAN" | python3 -c "
import sys, json
seen = set()
for line in sys.stdin:
    try:
        data = json.loads(line.strip())
        agent = data.get('agent', {}).get('name', 'N/A')
        hw_data = data.get('data', {})
        if agent in seen: continue
        seen.add(agent)
        cpu = hw_data.get('cpu', {}).get('real_cpuid', 'N/A')
        ram = hw_data.get('ram', {}).get('real_kernel_gb', 'N/A')
        bm = hw_data.get('benchmark', {}).get('score', 'N/A')
        print(f'  [OK] {agent}: CPU={cpu}, RAM={ram}GB, Benchmark={bm}')
    except:
        pass
" 2>/dev/null
    fi

    echo ""
    log_step "===== NATIJALAR TUGADI ====="
    echo ""

    # Qisqa statistika
    TOTAL_TAMPERED=$(grep "hw_detector" "$ALERTS_FILE" 2>/dev/null | grep "TAMPERED" | python3 -c "
import sys, json
seen = set()
for line in sys.stdin:
    try:
        data = json.loads(line)
        seen.add(data.get('agent',{}).get('name',''))
    except:
        pass
print(len(seen))
" 2>/dev/null)

    TOTAL_CLEAN=$(grep "hw_detector" "$ALERTS_FILE" 2>/dev/null | grep "CLEAN" | python3 -c "
import sys, json
seen = set()
for line in sys.stdin:
    try:
        data = json.loads(line)
        seen.add(data.get('agent',{}).get('name',''))
    except:
        pass
print(len(seen))
" 2>/dev/null)

    echo -e "  Jami: ${RED}${TOTAL_TAMPERED:-0} ta FRAUD${NC} / ${GREEN}${TOTAL_CLEAN:-0} ta TOZA${NC}"
    echo ""
}

# ============================================================
# MAIN
# ============================================================
check_root
check_wazuh

ACTION="${1:-all}"

case "$ACTION" in
    deploy)
        deploy
        ;;
    scan)
        scan_now
        ;;
    results)
        show_results
        ;;
    all)
        deploy
        echo ""
        echo "=================================================="
        echo "  PS1 skriptni agentlarga joylashtirgandan keyin"
        echo "  skanerlashni boshlash uchun qayta ishga tushiring:"
        echo "  sudo ./deploy_hw_detector.sh scan"
        echo ""
        echo "  Natijalarni ko'rish uchun:"
        echo "  sudo ./deploy_hw_detector.sh results"
        echo "=================================================="
        echo ""
        ;;
    *)
        echo "Ishlatish: $0 {deploy|scan|results|all}"
        echo ""
        echo "  deploy  - Decoder, rules, agent.conf ni o'rnatish"
        echo "  scan    - Barcha agentlarda skanerlashni boshlash"
        echo "  results - Natijalarni ko'rish"
        echo "  all     - Hammasini bajarish"
        exit 1
        ;;
esac
