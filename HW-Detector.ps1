# HW-DETECTOR v1.0 - Hardware Fraud Detection Tool
# Windows Registry va WMI soxtalashtirish (tampering) ni aniqlaydi.
# CPUID, SMBIOS firmware, PnP Hardware ID va benchmark orqali
# HAQIQIY hardware malumotlarini oqiydi.
#
# Ishlatish: PowerShell ni Administrator sifatida oching:
#   .\HW-Detector.ps1
#   .\HW-Detector.ps1 -OutputFile "C:\natija.txt"

param(
    [string]$OutputFile = ""
)

# Admin tekshiruvi
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host ""
    Write-Host "  [!] Bu skriptni ADMINISTRATOR sifatida ishga tushiring!" -ForegroundColor Red
    Write-Host "  PowerShell ni ong tugma -> Run as Administrator bilan oching." -ForegroundColor Yellow
    Write-Host ""
    pause
    exit 1
}

# ============================================================
# C# Helper Class - CPUID va SMBIOS uchun
# ============================================================
$csCode = @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;

public class HWDetect
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualFree(IntPtr a, uint s, uint t);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint GetSystemFirmwareTable(uint sig, uint id, IntPtr buf, uint sz);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate void CpuIdFunc(int leaf, IntPtr result);

    public static int[] DoCpuId(int leaf)
    {
        byte[] code;
        if (IntPtr.Size == 8)
        {
            code = new byte[] {
                0x53,0x57,0x48,0x89,0xD7,0x89,0xC8,0x0F,0xA2,
                0x89,0x07,0x89,0x5F,0x04,0x89,0x4F,0x08,0x89,0x57,0x0C,
                0x5F,0x5B,0xC3
            };
        }
        else
        {
            code = new byte[] {
                0x55,0x89,0xE5,0x53,0x57,
                0x8B,0x45,0x08,0x8B,0x7D,0x0C,0x0F,0xA2,
                0x89,0x07,0x89,0x5F,0x04,0x89,0x4F,0x08,0x89,0x57,0x0C,
                0x5F,0x5B,0x5D,0xC3
            };
        }
        IntPtr cp = VirtualAlloc(IntPtr.Zero, (uint)code.Length, 0x3000, 0x40);
        if (cp == IntPtr.Zero) return new int[4];
        Marshal.Copy(code, 0, cp, code.Length);
        IntPtr rp = Marshal.AllocHGlobal(16);
        try
        {
            var fn = (CpuIdFunc)Marshal.GetDelegateForFunctionPointer(cp, typeof(CpuIdFunc));
            fn(leaf, rp);
            int[] r = new int[4];
            Marshal.Copy(rp, r, 0, 4);
            return r;
        }
        finally
        {
            Marshal.FreeHGlobal(rp);
            VirtualFree(cp, 0, 0x8000);
        }
    }

    static string I2S(int v)
    {
        byte[] b = BitConverter.GetBytes(v);
        var sb = new StringBuilder();
        foreach (byte x in b) { if (x != 0) sb.Append((char)x); }
        return sb.ToString();
    }

    public static string CpuVendor()
    {
        try { int[] r = DoCpuId(0); return I2S(r[1]) + I2S(r[3]) + I2S(r[2]); }
        catch { return "N/A"; }
    }

    public static string CpuBrand()
    {
        try
        {
            int[] ext = DoCpuId(unchecked((int)0x80000000));
            if ((uint)ext[0] < 0x80000004) return "N/A";
            var sb = new StringBuilder();
            for (uint l = 0x80000002; l <= 0x80000004; l++)
            {
                int[] r = DoCpuId((int)l);
                sb.Append(I2S(r[0])); sb.Append(I2S(r[1]));
                sb.Append(I2S(r[2])); sb.Append(I2S(r[3]));
            }
            return sb.ToString().Trim();
        }
        catch { return "N/A"; }
    }

    public static int[] CpuFMS()
    {
        try
        {
            int[] r = DoCpuId(1);
            int fam = ((r[0]>>8)&0xF) + ((r[0]>>20)&0xFF);
            int mod = (((r[0]>>16)&0xF)<<4) + ((r[0]>>4)&0xF);
            int stp = r[0]&0xF;
            int lp = (r[1]>>16)&0xFF;
            return new int[] { fam, mod, stp, lp };
        }
        catch { return new int[] { 0,0,0,0 }; }
    }

    static byte[] GetSMBIOS()
    {
        uint sz = GetSystemFirmwareTable(0x52534D42, 0, IntPtr.Zero, 0);
        if (sz == 0) return null;
        IntPtr buf = Marshal.AllocHGlobal((int)sz);
        try
        {
            if (GetSystemFirmwareTable(0x52534D42, 0, buf, sz) == 0) return null;
            byte[] d = new byte[sz]; Marshal.Copy(buf, d, 0, (int)sz); return d;
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    static List<string> ExtractStrings(byte[] d, int start, int maxEnd)
    {
        var list = new List<string>();
        int p = start;
        while (p < maxEnd - 1)
        {
            if (d[p] == 0) break;
            int e = p; while (e < maxEnd && d[e] != 0) e++;
            list.Add(Encoding.ASCII.GetString(d, p, e - p));
            p = e + 1;
        }
        return list;
    }

    static string GetStr(List<string> s, int idx)
    { return (idx > 0 && idx <= s.Count) ? s[idx - 1] : ""; }

    public static string[] SmbiosCpu()
    {
        byte[] raw = GetSMBIOS();
        if (raw == null) return new string[] { "N/A","N/A","0","0","0","0","N/A" };
        int off = 8, len = raw.Length;
        while (off < len - 4)
        {
            byte tp = raw[off], tl = raw[off + 1];
            if (tl < 4) break;
            int ss = off + tl, se = ss;
            while (se < len - 1) { if (raw[se]==0 && raw[se+1]==0) { se+=2; break; } se++; }
            if (tp == 4 && tl >= 0x23)
            {
                var strs = ExtractStrings(raw, ss, se);
                string ver = GetStr(strs, raw[off+0x10]);
                string mfr = GetStr(strs, raw[off+0x07]);
                int maxS = BitConverter.ToUInt16(raw, off+0x14);
                int curS = BitConverter.ToUInt16(raw, off+0x16);
                int cores = (tl >= 0x24) ? raw[off+0x23] : 0;
                int thrds = (tl >= 0x26) ? raw[off+0x25] : 0;
                string sock = GetStr(strs, raw[off+0x04]);
                return new string[] { ver, mfr, maxS.ToString(), curS.ToString(),
                    cores.ToString(), thrds.ToString(), sock };
            }
            off = se;
        }
        return new string[] { "N/A","N/A","0","0","0","0","N/A" };
    }

    public static List<string[]> SmbiosRam()
    {
        var result = new List<string[]>();
        byte[] raw = GetSMBIOS();
        if (raw == null) return result;
        int off = 8, len = raw.Length;
        while (off < len - 4)
        {
            byte tp = raw[off], tl = raw[off + 1];
            if (tl < 4) break;
            int ss = off + tl, se = ss;
            while (se < len - 1) { if (raw[se]==0 && raw[se+1]==0) { se+=2; break; } se++; }
            if (tp == 17 && tl >= 0x15)
            {
                var strs = ExtractStrings(raw, ss, se);
                int rawSz = BitConverter.ToUInt16(raw, off+0x0C);
                int sizeMB = 0;
                if (rawSz == 0x7FFF && tl >= 0x20)
                    sizeMB = (int)BitConverter.ToUInt32(raw, off+0x1C);
                else if (rawSz != 0 && rawSz != 0xFFFF)
                    sizeMB = ((rawSz & 0x8000)!=0) ? (rawSz & 0x7FFF)/1024 : rawSz;
                string devLoc = GetStr(strs, raw[off+0x10]);
                int speed = BitConverter.ToUInt16(raw, off+0x15);
                int cfgSpd = (tl >= 0x22) ? BitConverter.ToUInt16(raw, off+0x20) : 0;
                string memTp = MemType(raw[off+0x12]);
                string mfr = (tl >= 0x18) ? GetStr(strs, raw[off+0x17]) : "";
                string pn = (tl >= 0x1B) ? GetStr(strs, raw[off+0x1A]) : "";
                string sn = (tl >= 0x19) ? GetStr(strs, raw[off+0x18]) : "";
                if (sizeMB > 0)
                    result.Add(new string[] { devLoc,sizeMB.ToString(),speed.ToString(),
                        cfgSpd.ToString(),memTp,mfr,pn,sn });
            }
            off = se;
        }
        return result;
    }

    static string MemType(int t)
    {
        switch(t){
            case 18: return "DDR"; case 19: return "DDR2"; case 20: return "DDR2";
            case 24: return "DDR3"; case 26: return "DDR4"; case 30: return "LPDDR4";
            case 34: return "DDR5"; case 35: return "LPDDR5"; default: return "Type"+t;
        }
    }

    public static string[] SmbiosSystem()
    {
        byte[] raw = GetSMBIOS();
        if (raw == null) return new string[] { "N/A","N/A","N/A" };
        int off = 8, len = raw.Length;
        while (off < len - 4)
        {
            byte tp = raw[off], tl = raw[off + 1];
            if (tl < 4) break;
            int ss = off + tl, se = ss;
            while (se < len - 1) { if (raw[se]==0 && raw[se+1]==0) { se+=2; break; } se++; }
            if (tp == 1 && tl >= 0x08)
            {
                var strs = ExtractStrings(raw, ss, se);
                return new string[] { GetStr(strs, raw[off+0x04]),
                    GetStr(strs, raw[off+0x05]), GetStr(strs, raw[off+0x07]) };
            }
            off = se;
        }
        return new string[] { "N/A","N/A","N/A" };
    }

    public static string[] SmbiosBoard()
    {
        byte[] raw = GetSMBIOS();
        if (raw == null) return new string[] { "N/A","N/A","N/A" };
        int off = 8, len = raw.Length;
        while (off < len - 4)
        {
            byte tp = raw[off], tl = raw[off + 1];
            if (tl < 4) break;
            int ss = off + tl, se = ss;
            while (se < len - 1) { if (raw[se]==0 && raw[se+1]==0) { se+=2; break; } se++; }
            if (tp == 2 && tl >= 0x08)
            {
                var strs = ExtractStrings(raw, ss, se);
                return new string[] { GetStr(strs, raw[off+0x04]),
                    GetStr(strs, raw[off+0x05]), GetStr(strs, raw[off+0x07]) };
            }
            off = se;
        }
        return new string[] { "N/A","N/A","N/A" };
    }

    [StructLayout(LayoutKind.Sequential)]
    struct MEMSTATEX { public uint len; public uint load; public ulong totalPhys;
        public ulong availPhys; public ulong totalPage; public ulong availPage;
        public ulong totalVirt; public ulong availVirt; public ulong extMem; }

    [DllImport("kernel32.dll")][return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GlobalMemoryStatusEx(ref MEMSTATEX m);

    public static long ActualRamBytes()
    {
        MEMSTATEX m = new MEMSTATEX(); m.len = (uint)Marshal.SizeOf(typeof(MEMSTATEX));
        if (GlobalMemoryStatusEx(ref m)) return (long)m.totalPhys;
        return 0;
    }
}
"@

try { Add-Type -TypeDefinition $csCode -Language CSharp -ErrorAction Stop }
catch {
    if ($_.Exception.Message -notlike "*already exists*") {
        Write-Host "  [!] C# compile xatosi: $($_.Exception.Message)" -ForegroundColor Red
        pause; exit 1
    }
}

# ============================================================
# Output helpers
# ============================================================
$script:logLines = [System.Collections.ArrayList]@()

function WL {
    param([string]$text = "", [string]$color = "White")
    Write-Host $text -ForegroundColor $color
    [void]$script:logLines.Add($text)
}

function PrintRow {
    param([string]$label, [string]$value, [string]$lc = "Cyan", [string]$vc = "White")
    $line = "  {0,-28} {1}" -f $label, $value
    Write-Host ("  {0,-28}" -f $label) -ForegroundColor $lc -NoNewline
    Write-Host (" {0}" -f $value) -ForegroundColor $vc
    [void]$script:logLines.Add($line)
}

# ============================================================
# BANNER
# ============================================================
Clear-Host
WL ""
WL "  ============================================================" "DarkCyan"
WL "       HW-DETECTOR v1.0 - Hardware Fraud Detection Tool" "Cyan"
WL "      Registry/WMI Bypass - Haqiqiy Hardware Aniqlagich" "Cyan"
WL "  ============================================================" "DarkCyan"
WL ""
WL ("  PC:    " + $env:COMPUTERNAME) "Gray"
WL ("  Sana:  " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) "Gray"
WL ("  User:  " + $env:USERNAME) "Gray"
WL ""

$fraudFound = $false

# ============================================================
# 1. CPU ANALYSIS
# ============================================================
WL "  ------------------------------------------------------------" "DarkYellow"
WL "  [CPU] PROTSESSOR TAHLILI" "Yellow"
WL "  ------------------------------------------------------------" "DarkYellow"
WL ""

$cpuidBrand = [HWDetect]::CpuBrand()
$cpuidVendor = [HWDetect]::CpuVendor()
$cpuFMS = [HWDetect]::CpuFMS()

$smbCpu = [HWDetect]::SmbiosCpu()

$wmiCpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
$wmiCpuName = if ($wmiCpu) { $wmiCpu.Name } else { "N/A" }
$wmiCpuCores = if ($wmiCpu) { $wmiCpu.NumberOfCores } else { 0 }
$wmiCpuThreads = if ($wmiCpu) { $wmiCpu.NumberOfLogicalProcessors } else { 0 }

$regCpuName = (Get-ItemProperty "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -ErrorAction SilentlyContinue).ProcessorNameString
if (-not $regCpuName) { $regCpuName = "N/A" }

PrintRow "CPUID (HAQIQIY):" $cpuidBrand "Green" "White"
PrintRow "SMBIOS/BIOS (HAQIQIY):" $smbCpu[0] "Green" "White"
PrintRow "WMI (SHUBHALI):" $wmiCpuName "Red" "White"
PrintRow "Registry (SHUBHALI):" $regCpuName "Red" "White"
WL ""

$realCpu = if ($cpuidBrand -and $cpuidBrand -ne "N/A") { $cpuidBrand } else { $smbCpu[0] }
$reportedCpu = $wmiCpuName

$realCpuClean = ($realCpu -replace '\s+', ' ').Trim()
$reportedCpuClean = ($reportedCpu -replace '\s+', ' ').Trim()

if ($realCpuClean -ne $reportedCpuClean -and $realCpu -ne "N/A" -and $reportedCpu -ne "N/A") {
    WL "  [!!!] CPU NOMUVOFIQLIK ANIQLANDI!" "Red"
    WL ("       Haqiqiy:      " + $realCpu) "Green"
    WL ("       Korsatilgan:  " + $reportedCpu) "Red"
    $fraudFound = $true
} else {
    WL "  [OK] CPU malumotlari mos kelmoqda." "Green"
}

WL ""
PrintRow "CPUID Vendor:" $cpuidVendor
PrintRow "Family/Model/Step:" ("{0} / {1} / {2}" -f $cpuFMS[0], $cpuFMS[1], $cpuFMS[2])
PrintRow "CPUID Logical CPUs:" $cpuFMS[3]
PrintRow "SMBIOS Cores/Threads:" ("{0} / {1}" -f $smbCpu[4], $smbCpu[5])
PrintRow "SMBIOS Max/Cur MHz:" ("{0} / {1}" -f $smbCpu[2], $smbCpu[3])
PrintRow "WMI Cores/Threads:" ("{0} / {1}" -f $wmiCpuCores, $wmiCpuThreads)

$realCores = [int]$smbCpu[4]
$wmiCoresInt = [int]$wmiCpuCores
if ($realCores -gt 0 -and $wmiCoresInt -gt 0 -and $realCores -ne $wmiCoresInt) {
    WL ""
    WL ("  [!!!] Yadrolar soni farq qiladi! SMBIOS: {0}, WMI: {1}" -f $realCores, $wmiCoresInt) "Red"
    $fraudFound = $true
}
WL ""

# ============================================================
# 2. RAM ANALYSIS
# ============================================================
WL "  ------------------------------------------------------------" "DarkYellow"
WL "  [RAM] XOTIRA TAHLILI" "Yellow"
WL "  ------------------------------------------------------------" "DarkYellow"
WL ""

$actualRamBytes = [HWDetect]::ActualRamBytes()
$actualRamGB = [math]::Round($actualRamBytes / 1GB, 2)

$smbRam = [HWDetect]::SmbiosRam()
$smbTotalMB = 0
foreach ($stick in $smbRam) { $smbTotalMB += [int]$stick[1] }
$smbTotalGB = [math]::Round($smbTotalMB / 1024, 2)

$wmiRam = Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue
$wmiTotalBytes = ($wmiRam | Measure-Object -Property Capacity -Sum).Sum
$wmiTotalGB = if ($wmiTotalBytes) { [math]::Round($wmiTotalBytes / 1GB, 2) } else { 0 }

PrintRow "Kernel API (HAQIQIY):" ("{0} GB" -f $actualRamGB) "Green" "White"
PrintRow "SMBIOS/BIOS (HAQIQIY):" ("{0} GB" -f $smbTotalGB) "Green" "White"
PrintRow "WMI (SHUBHALI):" ("{0} GB" -f $wmiTotalGB) "Red" "White"
WL ""

if ([math]::Abs($actualRamGB - $wmiTotalGB) -gt 1) {
    WL ("  [!!!] RAM HAJMI NOMUVOFIQ! Kernel: {0}GB vs WMI: {1}GB" -f $actualRamGB, $wmiTotalGB) "Red"
    $fraudFound = $true
} else {
    WL "  [OK] RAM hajmi mos kelmoqda." "Green"
}
WL ""

WL "  RAM platalari (SMBIOS - BIOS darajasidagi haqiqiy malumot):" "Cyan"
WL ""
$slotNum = 1
foreach ($stick in $smbRam) {
    WL ("   Slot {0} [{1}]:" -f $slotNum, $stick[0]) "Yellow"
    PrintRow "    Hajmi:" ("{0} MB" -f $stick[1]) "Gray"
    PrintRow "    Tezlik:" ("{0} MHz (Configured: {1} MHz)" -f $stick[2], $stick[3]) "Gray"
    PrintRow "    Turi:" $stick[4] "Gray"
    PrintRow "    Ishlab chiqaruvchi:" $stick[5] "Gray"
    PrintRow "    Part Number:" $stick[6] "Gray"
    PrintRow "    Serial Number:" $stick[7] "Gray"
    WL ""

    if ($wmiRam) {
        $wmiStick = $wmiRam | Where-Object { $_.DeviceLocator -eq $stick[0] } | Select-Object -First 1
        if ($wmiStick) {
            $wmiStickMB = [math]::Round($wmiStick.Capacity / 1MB)
            $smbStickMB = [int]$stick[1]
            if ([math]::Abs($smbStickMB - $wmiStickMB) -gt 100) {
                WL ("   [!!!] Bu slot: SMBIOS={0}MB vs WMI={1}MB - farq bor!" -f $smbStickMB, $wmiStickMB) "Red"
                $fraudFound = $true
            }
        }
    }
    $slotNum++
}

# ============================================================
# 3. GPU ANALYSIS
# ============================================================
WL "  ------------------------------------------------------------" "DarkYellow"
WL "  [GPU] VIDEOKARTA TAHLILI" "Yellow"
WL "  ------------------------------------------------------------" "DarkYellow"
WL ""

$gpuDevices = Get-PnpDevice -Class Display -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' }
$wmiGpu = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue

$venRegex = 'VEN_([0-9a-fA-F]{4})'
$devRegex = 'DEV_([0-9a-fA-F]{4})'

if ($gpuDevices) {
    $gpuIdx = 1
    foreach ($gpu in $gpuDevices) {
        $hwIds = (Get-PnpDeviceProperty -InstanceId $gpu.InstanceId -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction SilentlyContinue).Data
        $pnpDesc = $gpu.FriendlyName

        WL ("   GPU #{0}:" -f $gpuIdx) "Yellow"
        PrintRow "    PnP Nomi (HAQIQIY):" $pnpDesc "Green"

        if ($hwIds) {
            foreach ($hwId in $hwIds) {
                PrintRow "    Hardware ID:" $hwId "Green"
                if ($hwId -match $venRegex) {
                    $venId = $matches[1]
                    $vendor = switch ($venId.ToUpper()) {
                        "10DE" { "NVIDIA" }
                        "1002" { "AMD/ATI" }
                        "8086" { "Intel" }
                        default { "Vendor $venId" }
                    }
                    PrintRow "    Haqiqiy Vendor:" ("{0} ({1})" -f $vendor, $venId) "Green"
                }
                if ($hwId -match $devRegex) {
                    PrintRow "    Device ID:" $matches[1] "Green"
                }
            }
        }

        $wmiMatch = $wmiGpu | Where-Object { $_.PNPDeviceID -eq $gpu.InstanceId } | Select-Object -First 1
        $wmiGpuName = if ($wmiMatch) { $wmiMatch.Name } else { ($wmiGpu | Select-Object -First 1).Name }
        PrintRow "    WMI Nomi (SHUBHALI):" $wmiGpuName "Red"

        if ($pnpDesc -and $wmiGpuName -and $pnpDesc -ne $wmiGpuName) {
            WL "   [!!!] GPU nomlari farq qilmoqda!" "Red"
            $fraudFound = $true
        }
        WL ""
        $gpuIdx++
    }
} else {
    WL "  GPU qurilmalari topilmadi." "Gray"
}

# ============================================================
# 4. CPU BENCHMARK
# ============================================================
WL "  ------------------------------------------------------------" "DarkYellow"
WL "  [BENCHMARK] CPU Ishlash Quvvatini Sinash" "Yellow"
WL "  ------------------------------------------------------------" "DarkYellow"
WL ""
WL "  Hisoblash testi (~5 soniya)..." "Gray"

$bmStart = [System.Diagnostics.Stopwatch]::StartNew()
$iterations = 0
$testDuration = 5000
$pi = 0.0
$sign = 1.0
$k = 0
while ($bmStart.ElapsedMilliseconds -lt $testDuration) {
    for ($i = 0; $i -lt 10000; $i++) {
        $pi += $sign / (2 * $k + 1)
        $sign = -$sign
        $k++
    }
    $iterations += 10000
}
$bmStart.Stop()
$bmScore = [math]::Round($iterations / ($bmStart.ElapsedMilliseconds / 1000))

WL ""
PrintRow "Benchmark natijasi:" ("{0:N0} iter/sek" -f $bmScore) "Cyan"
PrintRow "Test davomiyligi:" ("{0:N1} sekund" -f ($bmStart.ElapsedMilliseconds/1000)) "Cyan"
WL ""

$estimatedClass = if ($bmScore -lt 50000) { "Juda past (Atom/Celeron darajasi)" }
    elseif ($bmScore -lt 100000) { "Past (Pentium/eski i3 darajasi)" }
    elseif ($bmScore -lt 200000) { "Ortacha (i3/i5 darajasi)" }
    elseif ($bmScore -lt 350000) { "Yaxshi (i5/i7 darajasi)" }
    else { "Yuqori (i7/i9/Ryzen 7+ darajasi)" }

PrintRow "Taxminiy CPU darajasi:" $estimatedClass "Yellow"
WL ""

# ============================================================
# 5. SYSTEM INFO
# ============================================================
WL "  ------------------------------------------------------------" "DarkYellow"
WL "  [SYSTEM] TIZIM MALUMOTLARI (SMBIOS)" "Yellow"
WL "  ------------------------------------------------------------" "DarkYellow"
WL ""

$sysInfo = [HWDetect]::SmbiosSystem()
$boardInfo = [HWDetect]::SmbiosBoard()

PrintRow "Tizim ishlab chiqaruvchi:" $sysInfo[0]
PrintRow "Tizim modeli:" $sysInfo[1]
PrintRow "Tizim Serial:" $sysInfo[2]
WL ""
PrintRow "Anakart ishlab chiqaruvchi:" $boardInfo[0]
PrintRow "Anakart modeli:" $boardInfo[1]
PrintRow "Anakart Serial:" $boardInfo[2]
WL ""

# ============================================================
# 6. YAKUNIY XULOSA
# ============================================================
WL ""
WL "  ============================================================" "DarkCyan"
WL "                       YAKUNIY XULOSA" "Cyan"
WL "  ============================================================" "DarkCyan"
WL ""

if ($fraudFound) {
    WL "  [!!!] OGOHLANTIRISH: Nomuvofiqliklar aniqlandi!" "Red"
    WL "  Bu kompyuterda hardware malumotlari" "Red"
    WL "  soxtalashtirilgan bolishi mumkin!" "Red"
    WL ""
    WL "  HAQIQIY malumotlar uchun CPUID va SMBIOS" "Yellow"
    WL "  natijalariga qarang (YASHIL rangdagi qiymatlar)." "Yellow"
} else {
    WL "  [OK] Aniq nomuvofiqlik topilmadi." "Green"
    WL "  Lekin benchmark natijasini ham tekshiring -" "Yellow"
    WL "  agar CPU modeli yuqori bolsa-yu benchmark past" "Yellow"
    WL "  bolsa, bu ham shubhali hisoblanadi." "Yellow"
}

WL ""
WL "  MUHIM: SMBIOS va CPUID malumotlari togidan-togri" "DarkGray"
WL "  BIOS/CPU dan oqiladi. Bu malumotlarni Windows ichidan" "DarkGray"
WL "  ozgartirish deyarli IMKONSIZ." "DarkGray"
WL ""

# Faylga saqlash
if ($OutputFile) {
    $script:logLines | Out-File -FilePath $OutputFile -Encoding UTF8
    WL ("  Natijalar saqlandi: " + $OutputFile) "Green"
    WL ""
}

$reportDir = $env:USERPROFILE + "\Desktop"
$reportFile = $reportDir + "\HW-Report_" + $env:COMPUTERNAME + "_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".txt"
$script:logLines | Out-File -FilePath $reportFile -Encoding UTF8
WL "  Hisobot avtomatik saqlandi:" "Gray"
WL ("  " + $reportFile) "Cyan"
WL ""

Write-Host "  Davom etish uchun istalgan tugmani bosing..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
