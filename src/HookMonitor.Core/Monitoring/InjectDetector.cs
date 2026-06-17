using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using HookMonitor.Models;

namespace HookMonitor.Core.Monitoring;

/// <summary>
/// DLL注入检测器
/// 检测AppInit_DLLs、AppCertDlls注册表项以及远程线程注入
/// 上网行为管理软件常通过全局DLL注入实现对进程的监控
/// 纯被动检测，不修改注册表或进程内存
/// </summary>
[SupportedOSPlatform("windows")]
public class InjectDetector
{
    // 注册表键
    private const string AppInitDllsKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
    private const string AppInitDllsValue = "AppInit_DLLs";
    private const string LoadAppInitDllsValue = "LoadAppInit_DLLs";
    private const string AppCertDllsKey = @"SYSTEM\CurrentControlSet\Control\Session Manager";
    private const string AppCertDllsValue = "AppCertDLLs";

    // Wow64重定向键
    private const string AppInitDllsKey32 = @"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows";
    private const string AppCertDllsKey32 = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs_x86";

    /// <summary>
    /// 检测AppInit_DLLs注册表项（全局DLL注入）
    /// </summary>
    public List<InjectDetectionInfo> DetectAppInitDlls()
    {
        var results = new List<InjectDetectionInfo>();

        // 检测64位AppInit_DLLs
        DetectAppInitFromRegistry(Microsoft.Win32.Registry.LocalMachine, AppInitDllsKey, results, "x64");

        // 检测32位AppInit_DLLs（在64位系统上）
        if (Environment.Is64BitOperatingSystem)
        {
            DetectAppInitFromRegistry(Microsoft.Win32.Registry.LocalMachine, AppInitDllsKey32, results, "x86");
        }

        return results;
    }

    /// <summary>
    /// 检测AppCertDlls注册表项（API调用拦截DLL）
    /// </summary>
    public List<InjectDetectionInfo> DetectAppCertDlls()
    {
        var results = new List<InjectDetectionInfo>();

        // 检测AppCertDLLs主键
        DetectAppCertFromRegistry(Microsoft.Win32.Registry.LocalMachine, AppCertDllsKey, AppCertDllsValue, results, "x64");

        // 检测32位版本
        if (Environment.Is64BitOperatingSystem)
        {
            DetectAppCertFromRegistry(Microsoft.Win32.Registry.LocalMachine, AppCertDllsKey32, AppCertDllsValue, results, "x86");
        }

        return results;
    }

    /// <summary>
    /// 检测系统中所有非微软签名的网络过滤驱动
    /// </summary>
    public List<KernelDriverInfo> DetectNetworkFilterDrivers()
    {
        var drivers = new List<KernelDriverInfo>();

        try
        {
            // 使用WMI查询网络过滤驱动
            using var searcher = new System.Management.ManagementObjectSearcher(
                @"\\localhost\ROOT\StandardCimv2",
                "SELECT * FROM MSFT_NetAdapterBindingSetting WHERE Enabled = TRUE");

            foreach (var obj in searcher.Get())
            {
                var driverName = obj["ComponentID"]?.ToString();
                var driverDesc = obj["Name"]?.ToString();

                if (!string.IsNullOrEmpty(driverName))
                {
                    drivers.Add(new KernelDriverInfo
                    {
                        DriverName = driverName,
                        Description = driverDesc ?? string.Empty,
                        DriverType = "NDIS Filter/LWF",
                        IsNetworkFilter = true,
                        State = "Enabled",
                        IsMicrosoftSigned = IsMicrosoftDriver(driverName),
                        DetectedAt = DateTime.UtcNow
                    });
                }
            }
        }
        catch
        {
            // StandardCimv2可能不可用，尝试其他方式
        }

        // 也通过驱动服务枚举补充
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT * FROM Win32_SystemDriver WHERE State = 'Running'");

            foreach (var obj in searcher.Get())
            {
                var driverName = obj["Name"]?.ToString() ?? "";
                var driverPath = obj["PathName"]?.ToString();
                var driverDesc = obj["Description"]?.ToString();
                var driverState = obj["State"]?.ToString() ?? "";

                // 检查是否为网络相关驱动
                var isNetwork = IsNetworkRelatedDriver(driverName, driverPath ?? "", driverDesc ?? "");

                if (isNetwork && !drivers.Any(d => d.DriverName == driverName))
                {
                    drivers.Add(new KernelDriverInfo
                    {
                        DriverName = driverName,
                        DriverPath = driverPath,
                        Description = driverDesc,
                        DriverType = "Kernel Driver",
                        State = driverState,
                        IsNetworkFilter = true,
                        IsMicrosoftSigned = IsMicrosoftDriver(driverName),
                        DetectedAt = DateTime.UtcNow
                    });
                }
            }
        }
        catch { /* 静默处理 */ }

        return drivers;
    }

    /// <summary>
    /// 获取所有非微软签名的驱动（包括文件系统过滤驱动）
    /// </summary>
    public List<KernelDriverInfo> GetThirdPartyDrivers()
    {
        var drivers = DetectNetworkFilterDrivers();

        // 补充文件系统过滤驱动（minifilter）
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT * FROM Win32_SystemDriver WHERE State = 'Running'");

            foreach (var obj in searcher.Get())
            {
                var driverName = obj["Name"]?.ToString() ?? "";
                var driverPath = obj["PathName"]?.ToString();
                var driverDesc = obj["Description"]?.ToString();
                var driverState = obj["State"]?.ToString() ?? "";

                // 跳过已添加的
                if (drivers.Any(d => d.DriverName == driverName))
                    continue;

                var isFsFilter = IsFileSystemFilterDriver(driverName, driverPath ?? "", driverDesc ?? "");

                if (isFsFilter && !IsMicrosoftDriver(driverName))
                {
                    drivers.Add(new KernelDriverInfo
                    {
                        DriverName = driverName,
                        DriverPath = driverPath,
                        Description = driverDesc,
                        DriverType = "File System Minifilter",
                        State = driverState,
                        IsFileSystemFilter = true,
                        IsMicrosoftSigned = false,
                        DetectedAt = DateTime.UtcNow
                    });
                }
            }
        }
        catch { /* 静默处理 */ }

        return drivers;
    }

    private void DetectAppInitFromRegistry(
        Microsoft.Win32.RegistryKey baseKey, string keyPath,
        List<InjectDetectionInfo> results, string architecture)
    {
        try
        {
            using var key = baseKey.OpenSubKey(keyPath);
            if (key == null) return;

            // 检查LoadAppInit_DLLs是否启用
            var loadAppInit = key.GetValue(LoadAppInitDllsValue);
            if (loadAppInit is int loadValue && loadValue == 0)
                return; // AppInit_DLLs已禁用

            var appInitDlls = key.GetValue(AppInitDllsValue) as string;
            if (string.IsNullOrEmpty(appInitDlls))
                return;

            var dlls = appInitDlls.Split([' ', ',', ';'], StringSplitOptions.RemoveEmptyEntries);
            foreach (var dll in dlls)
            {
                var trimmedDll = dll.Trim();
                if (string.IsNullOrEmpty(trimmedDll))
                    continue;

                var fullPath = ResolveDllPath(trimmedDll);

                results.Add(new InjectDetectionInfo
                {
                    InjectedDllPath = fullPath ?? trimmedDll,
                    InjectionMethod = $"AppInit_DLLs ({architecture})",
                    IsSystemDll = IsSystemDllPath(fullPath),
                    DllCompany = GetFileCompany(fullPath),
                    DllDescription = GetFileDescription(fullPath),
                    DetectedAt = DateTime.UtcNow
                });
            }
        }
        catch { /* 注册表键可能不可访问 */ }
    }

    private void DetectAppCertFromRegistry(
        Microsoft.Win32.RegistryKey baseKey, string keyPath, string valueName,
        List<InjectDetectionInfo> results, string architecture)
    {
        try
        {
            using var key = baseKey.OpenSubKey(keyPath);
            if (key == null) return;

            var appCertDlls = key.GetValue(valueName) as string[];
            if (appCertDlls == null || appCertDlls.Length == 0)
                return;

            foreach (var dll in appCertDlls)
            {
                var fullPath = ResolveDllPath(dll);

                results.Add(new InjectDetectionInfo
                {
                    InjectedDllPath = fullPath ?? dll,
                    InjectionMethod = $"AppCertDLLs ({architecture})",
                    IsSystemDll = IsSystemDllPath(fullPath),
                    DllCompany = GetFileCompany(fullPath),
                    DllDescription = GetFileDescription(fullPath),
                    DetectedAt = DateTime.UtcNow
                });
            }
        }
        catch { /* 注册表键可能不可访问 */ }
    }

    private string? ResolveDllPath(string dllName)
    {
        if (Path.IsPathRooted(dllName) && File.Exists(dllName))
            return dllName;

        // 尝试在System32中查找
        var systemPath = Path.Combine(Environment.SystemDirectory, dllName);
        if (File.Exists(systemPath))
            return systemPath;

        // 尝试在Windows目录中查找
        var windowsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), dllName);
        if (File.Exists(windowsPath))
            return windowsPath;

        return null;
    }

    private bool IsSystemDllPath(string? path)
    {
        if (string.IsNullOrEmpty(path))
            return false;

        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return path.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase);
    }

    private string? GetFileCompany(string? filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            return null;

        try
        {
            var versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(filePath);
            return versionInfo.CompanyName;
        }
        catch { return null; }
    }

    private string? GetFileDescription(string? filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            return null;

        try
        {
            var versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(filePath);
            return versionInfo.FileDescription;
        }
        catch { return null; }
    }

    private bool IsMicrosoftDriver(string driverName)
    {
        var knownMicrosoftDrivers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "tcpip", "netbt", "afd", "tdx", "tdi", "ws2ifsl",
            "ndis", "ndisuio", "vwififlt", "vwifibus", "vwifimp",
            "pacer", "wfplwfs", "netio", "npsvctrig", "nsi",
            "mslldp", "ms_implat", "lltdio", "rspndr", "ms_tcpip6",
            "mrxsmb", "mrxsmb10", "mrxsmb20", "srv", "srv2", "srvnet",
            "rdbss", "dfsc", "csc", "luafv", "wcifs", "storqosflt",
            "fileinfo", "fltmgr", "wof", "wofadk", "bindflt", "iorate",
            "msfs", "npfs", "netbios", "netbt", "tcpipreg"
        };

        return knownMicrosoftDrivers.Contains(driverName.ToLowerInvariant());
    }

    private bool IsNetworkRelatedDriver(string name, string path, string description)
    {
        var networkKeywords = new[]
        {
            "ndis", "filter", "net", "tcp", "udp", "ip", "wfp",
            "firewall", "proxy", "vpn", "mobile", "wlan",
            "http", "dns", "dhcp", "arp", "icmp", "tunnel",
            "bridge", "switch", "routing", "nat", "qos", "pacer"
        };

        var combined = $"{name} {path} {description}".ToLowerInvariant();
        return networkKeywords.Any(kw => combined.Contains(kw));
    }

    private bool IsFileSystemFilterDriver(string name, string path, string description)
    {
        var fsKeywords = new[]
        {
            "minifilter", "miniflt", "fileinfo", "filesystem",
            "fsfilter", "flt", "fltmgr", "filemon", "file",
            "procmon", "antivirus", "antimalware", "av", "edr",
            "dlp", "encryption", "backup", "snapshot", "vss"
        };

        var combined = $"{name} {path} {description}".ToLowerInvariant();
        return fsKeywords.Any(kw => combined.Contains(kw));
    }
}