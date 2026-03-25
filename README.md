# HW-Detector: Hardware Fraud Detection Tool

## Nima qiladi?

Windows Registry va WMI soxtalashtirish (tampering) ni aniqlaydi. Bu vosita **Windows ichidan**, hech qanday Ubuntu yoki tashqi dastur talab qilmasdan, quyidagi usullar bilan **HAQIQIY** hardware malumotlarini aniqlaydi:

| Usul | Nimani tekshiradi | Nima uchun ishonchli |
|------|-------------------|---------------------|
| **CPUID** (shellcode) | CPU nomi, yadrolar, family/model | CPU chipidan bevosita oqiladi, soxtalashtirish **IMKONSIZ** |
| **SMBIOS** (firmware) | CPU, RAM, Anakart | BIOS/UEFI dan oqiladi, Windows reestrga boglanmagan |
| **Kernel API** | Jami fizik RAM | OS yadrosi darajasida, WMI chetlab otiladi |
| **PnP Hardware ID** | GPU vendor/device ID | PCI bus dan kernel tomonidan oqiladi |
| **CPU Benchmark** | Haqiqiy ishlash quvvati | Kuchsiz CPU o'zini kuchli deb ko'rsata olmaydi |

## Ishlatish

### 1-usul: BAT fayl orqali (eng oson)
`ISHGA_TUSHIR.bat` faylini ikki marta bosing. U avtomatik Admin huquqini so'raydi.

### 2-usul: PowerShell orqali
1. PowerShell ni **Administrator** sifatida oching
2. Quyidagini tering:
```powershell
.\HW-Detector.ps1
```

### Natijani faylga saqlash:
```powershell
.\HW-Detector.ps1 -OutputFile "C:\natija.txt"
```

## Natija
- Ekranda rangli hisobot chiqadi
- Desktop ga avtomatik `HW-Report_PCNOMI_sana.txt` faylini saqlaydi
- **YASHIL** = HAQIQIY (CPUID/SMBIOS/Kernel)
- **QIZIL** = SHUBHALI (WMI/Registry - soxtalashtirilgan bolishi mumkin)
- Nomuvofiqlik topilsa `[!!!]` belgisi bilan ogohlantiriladi

## 20 ta PC ni tekshirish
1. `HW-Detector` papkani USB fleshkaga nusxalang
2. Har bir PC da `ISHGA_TUSHIR.bat` ni ishga tushiring
3. Hisobot avtomatik Desktop ga saqlanadi
4. Hisobotlarni solishtirib, qaysilarida nomuvofiqlik borligini aniqlang
