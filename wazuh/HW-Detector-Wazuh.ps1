# HW-DETECTOR v1.0 - Wazuh Agent versiyasi
# Wazuh wodle-command orqali ishga tushiriladi
# Natijani JSON formatda stdout ga chiqaradi
# Wazuh agent bu natijani log sifatida serverga yuboradi

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
        Write-Output ('hw_detector: {{"error":"C# compile failed: {0}"}}' -f ($_.Exception.Message -replace '"',''))
        exit 1
    }
}

# ============================================================
# Malumotlarni yigish
# ============================================================

# CPU - CPUID (HAQIQIY)
$cpuidBrand = [HWDetect]::CpuBrand()
$cpuidVendor = [HWDetect]::CpuVendor()
$cpuFMS = [HWDetect]::CpuFMS()

# CPU - SMBIOS (HAQIQIY)
$smbCpu = [HWDetect]::SmbiosCpu()

# CPU - WMI (SHUBHALI)
$wmiCpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
$wmiCpuName = if ($wmiCpu) { $wmiCpu.Name } else { "N/A" }
$wmiCpuCores = if ($wmiCpu) { [int]$wmiCpu.NumberOfCores } else { 0 }
$wmiCpuThreads = if ($wmiCpu) { [int]$wmiCpu.NumberOfLogicalProcessors } else { 0 }

# CPU - Registry
$regCpuName = (Get-ItemProperty "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" -ErrorAction SilentlyContinue).ProcessorNameString
if (-not $regCpuName) { $regCpuName = "N/A" }

# RAM - Kernel API (HAQIQIY)
$actualRamBytes = [HWDetect]::ActualRamBytes()
$actualRamGB = [math]::Round($actualRamBytes / 1GB, 2)

# RAM - SMBIOS (HAQIQIY)
$smbRam = [HWDetect]::SmbiosRam()
$smbTotalMB = 0
foreach ($stick in $smbRam) { $smbTotalMB += [int]$stick[1] }
$smbTotalGB = [math]::Round($smbTotalMB / 1024, 2)

# RAM - WMI (SHUBHALI)
$wmiRam = Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue
$wmiTotalBytes = ($wmiRam | Measure-Object -Property Capacity -Sum).Sum
$wmiTotalGB = if ($wmiTotalBytes) { [math]::Round($wmiTotalBytes / 1GB, 2) } else { 0 }

# GPU - PnP (HAQIQIY)
$gpuDevices = Get-PnpDevice -Class Display -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' }
$wmiGpu = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue

# System
$sysInfo = [HWDetect]::SmbiosSystem()
$boardInfo = [HWDetect]::SmbiosBoard()

# ============================================================
# Taqqoslash va fraud aniqlash
# ============================================================
$fraudList = [System.Collections.ArrayList]@()

# CPU taqqoslash
$realCpuClean = ($cpuidBrand -replace '\s+', ' ').Trim()
$wmiCpuClean = ($wmiCpuName -replace '\s+', ' ').Trim()
$cpuTampered = ($realCpuClean -ne $wmiCpuClean) -and ($cpuidBrand -ne "N/A") -and ($wmiCpuName -ne "N/A")
if ($cpuTampered) {
    [void]$fraudList.Add("CPU: Real=[$cpuidBrand] vs WMI=[$wmiCpuName]")
}

# CPU cores taqqoslash
$smbCores = [int]$smbCpu[4]
if ($smbCores -gt 0 -and $wmiCpuCores -gt 0 -and $smbCores -ne $wmiCpuCores) {
    [void]$fraudList.Add(("CPU_CORES: SMBIOS={0} vs WMI={1}" -f $smbCores, $wmiCpuCores))
}

# RAM taqqoslash
$ramTampered = [math]::Abs($actualRamGB - $wmiTotalGB) -gt 1
if ($ramTampered) {
    [void]$fraudList.Add(("RAM: Kernel={0}GB vs WMI={1}GB" -f $actualRamGB, $wmiTotalGB))
}

# GPU taqqoslash
$gpuInfoList = [System.Collections.ArrayList]@()
if ($gpuDevices) {
    foreach ($gpu in $gpuDevices) {
        $pnpName = $gpu.FriendlyName
        $wmiMatch = $wmiGpu | Where-Object { $_.PNPDeviceID -eq $gpu.InstanceId } | Select-Object -First 1
        $wmiName = if ($wmiMatch) { $wmiMatch.Name } else { "N/A" }
        $hwIds = (Get-PnpDeviceProperty -InstanceId $gpu.InstanceId -KeyName 'DEVPKEY_Device_HardwareIds' -ErrorAction SilentlyContinue).Data
        $hwIdStr = if ($hwIds) { $hwIds[0] } else { "N/A" }

        $gpuObj = @{
            pnp_name = $pnpName
            wmi_name = $wmiName
            hardware_id = $hwIdStr
        }
        [void]$gpuInfoList.Add($gpuObj)

        if ($pnpName -and $wmiName -and $pnpName -ne $wmiName -and $wmiName -ne "N/A") {
            [void]$fraudList.Add(("GPU: PnP=[$pnpName] vs WMI=[$wmiName]"))
        }
    }
}

# RAM sticks info
$ramSticks = [System.Collections.ArrayList]@()
foreach ($stick in $smbRam) {
    [void]$ramSticks.Add(@{
        slot = $stick[0]
        size_mb = [int]$stick[1]
        speed_mhz = [int]$stick[2]
        type = $stick[4]
        manufacturer = $stick[5]
        part_number = $stick[6]
        serial = $stick[7]
    })
}

# ============================================================
# Benchmark (qisqa - 3 sekund)
# ============================================================
$bmStart = [System.Diagnostics.Stopwatch]::StartNew()
$iterations = 0
$pi = 0.0; $sign = 1.0; $k = 0
while ($bmStart.ElapsedMilliseconds -lt 3000) {
    for ($i = 0; $i -lt 10000; $i++) {
        $pi += $sign / (2 * $k + 1); $sign = -$sign; $k++
    }
    $iterations += 10000
}
$bmStart.Stop()
$bmScore = [math]::Round($iterations / ($bmStart.ElapsedMilliseconds / 1000))

# ============================================================
# JSON natija chiqarish (Wazuh uchun)
# ============================================================
$overallVerdict = if ($fraudList.Count -gt 0) { "TAMPERED" } else { "CLEAN" }

$result = @{
    scan_type = "hw_fraud_detection"
    timestamp = (Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz')
    hostname = $env:COMPUTERNAME
    verdict = $overallVerdict
    fraud_count = $fraudList.Count
    frauds = $fraudList.ToArray()
    cpu = @{
        real_cpuid = $cpuidBrand
        real_smbios = $smbCpu[0]
        real_vendor = $cpuidVendor
        real_cores = [int]$smbCpu[4]
        real_threads = [int]$smbCpu[5]
        real_max_mhz = [int]$smbCpu[2]
        reported_wmi = $wmiCpuName
        reported_registry = $regCpuName
        reported_wmi_cores = $wmiCpuCores
        reported_wmi_threads = $wmiCpuThreads
        family = $cpuFMS[0]
        model = $cpuFMS[1]
        stepping = $cpuFMS[2]
        tampered = $cpuTampered
    }
    ram = @{
        real_kernel_gb = $actualRamGB
        real_smbios_gb = $smbTotalGB
        reported_wmi_gb = $wmiTotalGB
        tampered = $ramTampered
        sticks = $ramSticks.ToArray()
    }
    gpu = $gpuInfoList.ToArray()
    benchmark = @{
        score = $bmScore
        duration_sec = [math]::Round($bmStart.ElapsedMilliseconds / 1000, 1)
    }
    system = @{
        manufacturer = $sysInfo[0]
        product = $sysInfo[1]
        serial = $sysInfo[2]
        board_manufacturer = $boardInfo[0]
        board_product = $boardInfo[1]
        board_serial = $boardInfo[2]
    }
}

$jsonOutput = $result | ConvertTo-Json -Depth 5 -Compress
Write-Output ("hw_detector: " + $jsonOutput)
