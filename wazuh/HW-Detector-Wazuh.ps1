# HW-DETECTOR v2.0 - Wazuh Agent versiyasi
# Yangi v2.0: Registry tampering, hardware fingerprint, RAM/GPU details.

$csCode = @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

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
}
"@

Add-Type -TypeDefinition $csCode -ErrorAction SilentlyContinue

# CPU INFO
$real_cpu = [HWDetect]::CpuBrand()
$wmi_cpu = (Get-WmiObject Win32_Processor).Name
$reg_cpu = (Get-ItemProperty "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0").ProcessorNameString -replace '\s+', ' '

$cpu_tampered = ($real_cpu -ne $wmi_cpu)
$reg_tampered = ($wmi_cpu -ne $reg_cpu)

# RAM INFO
$wmi_ram = Get-WmiObject Win32_PhysicalMemory
$total_wmi_gb = [math]::Round(($wmi_ram | Measure-Object Capacity -Sum).Sum / 1GB, 0)
$ram_count = ($wmi_ram | Measure-Object).Count

# GPU INFO
$gpu = Get-WmiObject Win32_VideoController | Select-Object -First 1
$gpu_name = $gpu.Name

# VERDICT
$verdict = "CLEAN"
if ($cpu_tampered -or $reg_tampered) { $verdict = "TAMPERED" }

$result = @{
    scan_type = "hw_fraud_detection"
    verdict = $verdict
    tampered = $cpu_tampered
    registry_tampered = $reg_tampered
    cpu = @{
        real = $real_cpu
        reported_wmi = $wmi_cpu
        reported_registry = $reg_cpu
    }
    ram = @{
        total_gb = $total_wmi_gb
        stick_count = $ram_count
    }
    gpu = @{
        name = $gpu_name
    }
    agent = @{
        name = $env:COMPUTERNAME
    }
}

$jsonOutput = $result | ConvertTo-Json -Depth 5 -Compress
Write-Output ("hw_detector: " + $jsonOutput)

# WRITE TO FILE FOR WAZUH
$logPath = "C:\Program Files (x86)\ossec-agent\hw_detector.json"
Out-File -FilePath $logPath -InputObject $jsonOutput -Encoding ASCII
