# Wazuh + HW-Detector: Markaziy Hardware Tekshiruv

## Arxitektura

```
Wazuh Server (Linux)              Windows Agent PCs
┌──────────────────┐          ┌─────────────────────┐
│  decoder.xml     │          │  HW-Detector-Wazuh  │
│  rules.xml       │◄─────── │  (wodle-command)     │
│  agent.conf      │──────►  │  JSON natija → log   │
│  alerts.json     │          └─────────────────────┘
│  deploy script   │          ┌─────────────────────┐
│                  │◄─────── │  HW-Detector-Wazuh  │
│  CPUID/SMBIOS vs │          │  ...x20 ta PC       │
│  WMI = FRAUD?    │          └─────────────────────┘
└──────────────────┘
```

## O'rnatish (3 qadam)

### 1-QADAM: Wazuh Server (Linux) da

```bash
# wazuh papkani serverga nusxalang (scp/rsync)
scp -r wazuh/ root@wazuh-server:/tmp/hw-detector/

# Serverda:
cd /tmp/hw-detector
chmod +x deploy_hw_detector.sh
sudo ./deploy_hw_detector.sh deploy
```

Bu quyidagilarni bajaradi:
- `hw_detector_decoder.xml` → `/var/ossec/etc/decoders/`
- `hw_detector_rules.xml` → `/var/ossec/etc/rules/`
- `agent.conf` → `/var/ossec/etc/shared/default/`
- Wazuh Manager restart

### 2-QADAM: Har bir Windows Agent PC da

`HW-Detector-Wazuh.ps1` ni quyidagi joyga nusxalang:

```
C:\Program Files (x86)\ossec-agent\active-response\bin\HW-Detector-Wazuh.ps1
```

**Tez tarqatish usullari:**

**a) PowerShell Remoting (eng tez):**
```powershell
# PC nomlari royxati
$PClar = @("LAB-PC-01","LAB-PC-02","LAB-PC-03") # ...

# Skriptni tarqatish
foreach ($pc in $PClar) {
    Copy-Item "HW-Detector-Wazuh.ps1" `
      -Destination "\\$pc\C$\Program Files (x86)\ossec-agent\active-response\bin\" `
      -Force
    Write-Host "$pc ga joylashtirildi" -ForegroundColor Green
}
```

**b) GPO orqali** - Computer Startup Script sifatida

**c) Qolda** - USB fleshka bilan

### 3-QADAM: Skanerlash boshlash

```bash
# Serverda:
sudo ./deploy_hw_detector.sh scan
```

Bu barcha agentlarni restart qiladi va `run_on_start=yes` tufayli HW-Detector avtomatik ishga tushadi.

## Natijalarni ko'rish

```bash
# Terminal da:
sudo ./deploy_hw_detector.sh results
```

Yoki **Wazuh Dashboard** da:
1. **Discover** bo'limiga kiring
2. Filter: `rule.groups: hw_fraud`
3. Barcha TAMPERED PC lar ro'yxati chiqadi

**Rule ID lari:**

| Rule ID | Level | Ma'nosi |
|---------|-------|---------|
| 100101 | 12 | Umumiy hardware soxtalashtirish |
| 100103 | 14 | CPU almashtirilgan |
| 100104 | 14 | RAM almashtirilgan |
| 100105 | 15 | CPU + RAM ikkalasi almashtirilgan |

## Fayl tuzilishi

```
wazuh/
├── HW-Detector-Wazuh.ps1          # Agent PC da ishlaydigan skript (JSON output)
├── deploy_hw_detector.sh           # Server deploy/scan/results skripti
└── server/
    ├── agent.conf                  # Wodle-command konfiguratsiyasi
    ├── hw_detector_decoder.xml     # JSON log parser
    └── hw_detector_rules.xml       # Ogohlantirish qoidalari
```

## Interval sozlash

`agent.conf` da `<interval>` qiymatini o'zgartiring:
- `1h` - har soatda (standart)
- `12h` - kuniga 2 marta
- `1d` - kuniga 1 marta
- Yoki `scan` buyrugi bilan istalgan vaqtda qo'lda ishga tushiring
