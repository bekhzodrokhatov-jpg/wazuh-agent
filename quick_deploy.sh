#!/bin/bash
# Manual deployment script

WAZUH_DIR="/var/ossec"

echo "[1] Copying hw_change_detector.py..."
cp /tmp/hw_change_detector_updated.py "$WAZUH_DIR/var/hw_monitor/hw_change_detector.py"
chmod 750 "$WAZUH_DIR/var/hw_monitor/hw_change_detector.py"

echo "[2] Copying rules and decoders..."
cp /tmp/hw_change_rules.xml "$WAZUH_DIR/etc/rules/hw_change_rules.xml"
cp /tmp/hw_change_decoder.xml "$WAZUH_DIR/etc/decoders/hw_change_decoder.xml"
chown root:wazuh "$WAZUH_DIR/etc/rules/hw_change_rules.xml"
chown root:wazuh "$WAZUH_DIR/etc/decoders/hw_change_decoder.xml"
chmod 660 "$WAZUH_DIR/etc/rules/hw_change_rules.xml"
chmod 660 "$WAZUH_DIR/etc/decoders/hw_change_decoder.xml"

echo "[3] Setting up cron job..."
echo "* * * * * root python3 $WAZUH_DIR/var/hw_monitor/hw_change_detector.py --process 2>/dev/null" > /etc/cron.d/wazuh-hw-monitor
chmod 644 /etc/cron.d/wazuh-hw-monitor

echo "[4] Restarting Wazuh Manager..."
systemctl restart wazuh-manager
sleep 10

echo ""
echo "[5] Verifying..."
echo "    Rules deployed: $(grep -c '<rule id=' $WAZUH_DIR/etc/rules/hw_*.xml 2>/dev/null || echo '0')"
echo "    Decoders deployed: $(grep -c '<decoder' $WAZUH_DIR/etc/decoders/hw_*.xml 2>/dev/null || echo '0')"
echo "    Cron job: $(grep -c 'hw_change_detector' /etc/cron.d/wazuh-hw-monitor 2>/dev/null || echo '0')"
echo ""
echo "SETUP COMPLETE!"
