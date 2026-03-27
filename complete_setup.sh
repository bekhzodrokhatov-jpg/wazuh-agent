#!/bin/bash
# Complete HW-Detector Wazuh Integration Setup
# Runs on Linux (Wazuh Manager)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAZUH_DIR="/var/ossec"
DEPLOY_DIR="$WAZUH_DIR/var/hw_monitor"

echo "======================================================================"
echo "  HW-DETECTOR: Complete Wazuh Integration Setup"
echo "======================================================================"
echo ""

# 1. Directories yaratish
echo "[1] Setting up directories..."
mkdir -p "$DEPLOY_DIR"
mkdir -p "$WAZUH_DIR/var/db"
mkdir -p "$WAZUH_DIR/etc/rules"
mkdir -p "$WAZUH_DIR/etc/decoders"
mkdir -p "$WAZUH_DIR/integrations"

# 2. Python scriptni deploy qilish
echo "[2] Deploying hw_change_detector.py..."
cp /tmp/hw_change_detector_updated.py "$DEPLOY_DIR/hw_change_detector.py"
chmod 750 "$DEPLOY_DIR/hw_change_detector.py"
chown root:wazuh "$DEPLOY_DIR/hw_change_detector.py"

# 3. Rules deploy qilish
echo "[3] Deploying rules and decoders..."
cp /tmp/hw_detector_rules.xml "$WAZUH_DIR/etc/rules/hw_detector_rules.xml"
cp /tmp/hw_change_rules.xml "$WAZUH_DIR/etc/rules/hw_change_rules.xml"
cp /tmp/hw_detector_decoder.xml "$WAZUH_DIR/etc/decoders/hw_detector_decoder.xml"
cp /tmp/hw_change_decoder.xml "$WAZUH_DIR/etc/decoders/hw_change_decoder.xml"

chown root:wazuh "$WAZUH_DIR/etc/rules/hw_*"
chown root:wazuh "$WAZUH_DIR/etc/decoders/hw_*"
chmod 660 "$WAZUH_DIR/etc/rules/hw_*"
chmod 660 "$WAZUH_DIR/etc/decoders/hw_*"

# 4. Cron job qo'yish (har 1 daqiqada)
echo "[4] Setting up cron job..."
CRON_ENTRY="* * * * * root python3 $DEPLOY_DIR/hw_change_detector.py --process 2>/dev/null"
if ! grep -q "hw_change_detector.py" /etc/cron.d/wazuh-hw-monitor 2>/dev/null; then
    echo "$CRON_ENTRY" > /etc/cron.d/wazuh-hw-monitor
    chmod 644 /etc/cron.d/wazuh-hw-monitor
    echo "    ✓ Cron job added"
else
    echo "    ✓ Cron job already exists"
fi

# 5. Wazuh Manager ni restart qilish
echo "[5] Restarting Wazuh Manager..."
systemctl restart wazuh-manager
sleep 10

# 6. Verify
echo ""
echo "[6] Verifying deployment..."
echo ""

if [ -f "$DEPLOY_DIR/hw_change_detector.py" ]; then
    echo "    ✓ hw_change_detector.py installed"
    echo "    ✓ Rules count: $(grep -c '<rule id=' $WAZUH_DIR/etc/rules/hw_*.xml 2>/dev/null || echo '0')"
    echo "    ✓ Database path: $WAZUH_DIR/var/db/hw_inventory.db"
fi

# Test mode
echo ""
echo "[7] Running test mode..."
python3 "$DEPLOY_DIR/hw_change_detector.py" --test

echo ""
echo "======================================================================"
echo "  SETUP COMPLETE!"
echo "======================================================================"
echo ""
echo "Usage:"
echo "  # Check database status"
echo "  python3 $DEPLOY_DIR/hw_change_detector.py --stats"
echo ""
echo "  # View all PCs hardware"
echo "  python3 $DEPLOY_DIR/hw_change_detector.py --dump"
echo ""
echo "  # View specific PC history (agent ID)"
echo "  python3 $DEPLOY_DIR/hw_change_detector.py --history 003"
echo ""
echo "  # View all hardware changes"
echo "  python3 $DEPLOY_DIR/hw_change_detector.py --changes"
echo ""
