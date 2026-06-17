using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using HookMonitor.Core.NativeInterop;
using HookMonitor.Models;

namespace HookMonitor.Core.Monitoring;

/// <summary>
/// 进程扫描器，使用底层NT API枚举系统进程并收集详细信息
/// </summary>
[SupportedOSPlatform("windows")]
public class ProcessScanner
{
    /// <summary>
    /// 枚举所有系统进程（使用NtQuerySystemInformation）
    /// </summary>
    public List<ProcessBasicInfo> EnumerateProcesses()
    {
        var processes = new List<ProcessBasicInfo>();
        var buffer = IntPtr.Zero;
        try
        {
            var status = NtApi.NtQuerySystemInformation(
                NtStructures.SYSTEM_INFORMATION_CLASS.SystemProcessInformation,
                IntPtr.Zero, 0, out var requiredSize);

            if (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH)
                return processes;

            var bufferSize = requiredSize + 65536;
            buffer = Marshal.AllocHGlobal(bufferSize);

            status = NtApi.NtQuerySystemInformation(
                NtStructures.SYSTEM_INFORMATION_CLASS.SystemProcessInformation,
                buffer, bufferSize, out _);

            if (!NtStatus.IsSuccess(status))
                return processes;

            var offset = 0;
            while (true)
            {
                var currentPtr = IntPtr.Add(buffer, offset);
                var spi = Marshal.PtrToStructure<NtStructures.SYSTEM_PROCESS_INFORMATION>(currentPtr);

                var processName = NtApi.ReadLocalUnicodeString(spi.ImageName) ?? $"PID:{spi.UniqueProcessId}";
                var pid = spi.UniqueProcessId.ToInt32();
                var parentPid = spi.InheritedFromUniqueProcessId.ToInt32();

                processes.Add(new ProcessBasicInfo
                {
                    ProcessId = pid,
                    ProcessName = processName,
                    ParentProcessId = parentPid,
                    HandleCount = (int)spi.HandleCount,
                    SessionId = (int)spi.SessionId,
                    WorkingSetSize = spi.WorkingSetSize,
                    PeakWorkingSetSize = spi.PeakWorkingSetSize,
                    VirtualSize = spi.VirtualSize,
                    PagefileUsage = spi.PagefileUsage,
                    KernelTime = spi.KernelTime,
                    UserTime = spi.UserTime,
                    CreateTime = spi.CreateTime
                });

                if (spi.NextEntryOffset == 0)
                    break;

                offset += (int)spi.NextEntryOffset;
            }
        }
        catch (Exception)
        {
            // 静默处理，返回已收集的数据
        }
        finally
        {
            if (buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(buffer);
        }

        return processes;
    }

    /// <summary>
    /// 获取进程详细信息（路径、命令行等）
    /// </summary>
    public ProcessDetailInfo? GetProcessDetail(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            var result = new ProcessDetailInfo
            {
                ProcessId = processId,
                ProcessName = process.ProcessName,
                StartTime = process.StartTime,
                SessionId = process.SessionId,
                HandleCount = process.HandleCount,
                WorkingSetSize = process.WorkingSet64,
                IsProtected = IsProcessProtected(processId)
            };

            // 获取文件路径
            try
            {
                result.FilePath = process.MainModule?.FileName;
            }
            catch { /* 32/64位跨架构访问可能失败 */ }

            // 获取命令行
            result.CommandLine = GetProcessCommandLine(processId);

            // 获取父进程
            result.ParentProcessId = GetParentProcessId(processId);
            if (result.ParentProcessId > 0)
            {
                try
                {
                    using var parent = Process.GetProcessById(result.ParentProcessId);
                    result.ParentProcessName = parent.ProcessName;
                }
                catch { /* 父进程可能已退出 */ }
            }

            // 获取文件版本信息
            if (!string.IsNullOrEmpty(result.FilePath))
            {
                try
                {
                    var versionInfo = FileVersionInfo.GetVersionInfo(result.FilePath);
                    result.Company = versionInfo.CompanyName;
                    result.Description = versionInfo.FileDescription;
                    result.FileVersion = versionInfo.FileVersion;
                }
                catch { /* 文件可能不可访问 */ }
            }

            // 检查是否为服务
            result.IsService = CheckIfService(result.FilePath, process.ProcessName);
            result.ServiceName = result.IsService ? process.ProcessName : null;

            // 检测架构
            result.Architecture = GetProcessArchitecture(processId);

            return result;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 获取进程命令行参数（通过读取PEB）
    /// </summary>
    private string? GetProcessCommandLine(int processId)
    {
        // 优先使用WMI获取命令行
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}");
            foreach (var obj in searcher.Get())
            {
                return obj["CommandLine"]?.ToString();
            }
        }
        catch { /* WMI查询可能失败 */ }

        return null;
    }

    /// <summary>
    /// 获取父进程ID
    /// </summary>
    private int GetParentProcessId(int processId)
    {
        var handle = IntPtr.Zero;
        try
        {
            handle = NtApi.OpenProcess(NtApi.PROCESS_QUERY_INFORMATION, false, processId);
            if (handle == IntPtr.Zero)
                handle = NtApi.OpenProcess(NtApi.PROCESS_QUERY_LIMITED_INFORMATION, false, processId);

            if (handle == IntPtr.Zero)
                return 0;

            var pbiPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NtStructures.PROCESS_BASIC_INFORMATION>());
            try
            {
                var status = NtApi.NtQueryInformationProcess(
                    handle,
                    NtStructures.PROCESS_INFORMATION_CLASS.ProcessBasicInformation,
                    pbiPtr,
                    Marshal.SizeOf<NtStructures.PROCESS_BASIC_INFORMATION>(),
                    out _);

                if (NtStatus.IsSuccess(status))
                {
                    var pbi = Marshal.PtrToStructure<NtStructures.PROCESS_BASIC_INFORMATION>(pbiPtr);
                    return pbi.InheritedFromUniqueProcessId.ToInt32();
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pbiPtr);
            }
        }
        catch { /* 静默处理 */ }
        finally
        {
            if (handle != IntPtr.Zero)
                NtApi.CloseHandle(handle);
        }

        return 0;
    }

    /// <summary>
    /// 检查进程是否为受保护进程（PPL）
    /// </summary>
    private bool IsProcessProtected(int processId)
    {
        var handle = IntPtr.Zero;
        try
        {
            handle = NtApi.OpenProcess(NtApi.PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
            if (handle == IntPtr.Zero)
                return true; // 无法打开可能意味着是受保护进程

            // 查询进程保护级别
            var buffer = Marshal.AllocHGlobal(4);
            try
            {
                var status = NtApi.NtQueryInformationProcess(
                    handle,
                    (NtStructures.PROCESS_INFORMATION_CLASS)50, // ProcessProtectionInformation
                    buffer, 4, out _);

                if (NtStatus.IsSuccess(status))
                {
                    var protectionLevel = Marshal.ReadInt32(buffer);
                    return protectionLevel != 0; // 0 = 无保护
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch { /* 静默处理 */ }
        finally
        {
            if (handle != IntPtr.Zero)
                NtApi.CloseHandle(handle);
        }

        return false;
    }

    /// <summary>
    /// 检查进程是否为Windows服务
    /// </summary>
    private bool CheckIfService(string? filePath, string processName)
    {
        if (string.IsNullOrEmpty(filePath))
            return false;

        var lowerPath = filePath.ToLowerInvariant();
        // 服务通常运行在System32或SysWOW64下，且由svchost托管
        if (lowerPath.Contains("svchost.exe"))
            return true;

        // 检查是否在服务路径下
        if (lowerPath.Contains("\\windows\\system32\\") ||
            lowerPath.Contains("\\windows\\syswow64\\"))
        {
            // 排除普通应用程序
            var serviceProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "svchost", "services", "lsass", "wininit", "dwm",
                "csrss", "smss", "winlogon", "taskhostw", "sihost",
                "ctfmon", "dllhost", "searchindexer", "spoolsv"
            };
            return serviceProcessNames.Contains(processName);
        }

        return false;
    }

    /// <summary>
    /// 获取进程架构
    /// </summary>
    private string? GetProcessArchitecture(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            // .NET 10 中可通过 ProcessThread 获取架构信息
            return Environment.Is64BitProcess ? "x64" : "x86";
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>
/// 进程基本信息（从NtQuerySystemInformation获取）
/// </summary>
public class ProcessBasicInfo
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public int ParentProcessId { get; set; }
    public int HandleCount { get; set; }
    public int SessionId { get; set; }
    public long WorkingSetSize { get; set; }
    public long PeakWorkingSetSize { get; set; }
    public long VirtualSize { get; set; }
    public long PagefileUsage { get; set; }
    public long KernelTime { get; set; }
    public long UserTime { get; set; }
    public long CreateTime { get; set; }
}

/// <summary>
/// 进程详细信息
/// </summary>
public class ProcessDetailInfo
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string? FilePath { get; set; }
    public string? CommandLine { get; set; }
    public string? Company { get; set; }
    public string? Description { get; set; }
    public string? FileVersion { get; set; }
    public int ParentProcessId { get; set; }
    public string? ParentProcessName { get; set; }
    public DateTime StartTime { get; set; }
    public int SessionId { get; set; }
    public int HandleCount { get; set; }
    public long WorkingSetSize { get; set; }
    public bool IsProtected { get; set; }
    public bool IsService { get; set; }
    public string? ServiceName { get; set; }
    public string? Architecture { get; set; }
}
