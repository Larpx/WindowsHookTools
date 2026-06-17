using System.Runtime.InteropServices;
using HookMonitor.Core.NativeInterop;

namespace HookMonitor.Core.Hooking;

/// <summary>
/// DLL注入器，将监控DLL注入到目标进程中
/// 包含安全检查，避免注入系统关键进程和受保护进程
/// </summary>
public class DllInjector
{
    /// <summary>
    /// 系统关键进程名单，禁止注入
    /// </summary>
    private static readonly HashSet<string> CriticalProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss", "smss", "wininit", "services", "lsass",
        "svchost", "dwm", "winlogon", "taskhostw", "sihost",
        "ctfmon", "dllhost", "conhost", "fontdrvhost",
        "WUDFHost", "MsMpEng", "MpCmdRun", "NisSrv",
        "SecurityHealthService", "SecurityHealthSystray",
        "MpDefender", "MsSense", "SenseIR",
        "SearchIndexer", "SearchHost", "RuntimeBroker",
        "System", "Registry", "Memory Compression",
        "SystemSettings", "ShellExperienceHost",
        "StartMenuExperienceHost", "SearchUI"
    };

    /// <summary>
    /// 安全软件进程名单，禁止注入
    /// </summary>
    private static readonly HashSet<string> SecurityProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "MsMpEng", "MsSense", "NisSrv", "MpCmdRun",
        "SecurityHealthService", "SecurityHealthSystray",
        "MpDefender", "SenseIR", "SenseCncProxy",
        "SenseSampleUploader", "Mrt", "Mrt.exe",
        "360", "360sd", "360tray", "ZhuDongFangYu",
        "360safe", "360leakfixer", "360rp",
        "Huorong", "hipstray", "hipstray.exe",
        "wsctrl", "usysdiag", "KWatch",
        "kxescore", "kxetray", "KSWebShield",
        "QQPCTray", "QQPCRTP", "QQPCMgr"
    };

    /// <summary>
    /// 检查进程是否可以安全注入
    /// </summary>
    public InjectionSafetyCheckResult CheckInjectionSafety(string processName, int processId, bool isProtected)
    {
        // 检查是否为当前进程
        if (processId == Kernel32Api.GetCurrentProcessId())
            return InjectionSafetyCheckResult.Unsafe("不能注入自身进程");

        // 检查是否为受保护进程（PPL）
        if (isProtected)
            return InjectionSafetyCheckResult.Unsafe("受保护进程（PPL），注入可能触发安全机制");

        // 检查是否为系统关键进程
        if (CriticalProcesses.Contains(processName))
            return InjectionSafetyCheckResult.Unsafe("系统关键进程，注入可能导致蓝屏");

        // 检查是否为安全软件进程
        if (SecurityProcesses.Contains(processName))
            return InjectionSafetyCheckResult.Unsafe("安全软件进程，注入可能触发报警");

        // 检查是否为PID 4（System进程）
        if (processId <= 4)
            return InjectionSafetyCheckResult.Unsafe("系统内核进程，禁止注入");

        return InjectionSafetyCheckResult.Safe();
    }

    /// <summary>
    /// 使用CreateRemoteThread方式注入DLL
    /// 注意：此方法可能被安全软件标记，仅在用户明确授权时使用
    /// </summary>
    public bool InjectDll(int processId, string dllPath)
    {
        IntPtr hProcess = IntPtr.Zero;
        IntPtr remoteMemory = IntPtr.Zero;

        try
        {
            // 打开目标进程
            hProcess = NtApi.OpenProcess(
                NtApi.PROCESS_VM_WRITE | NtApi.PROCESS_VM_OPERATION |
                NtApi.PROCESS_QUERY_INFORMATION | 0x0001 /* PROCESS_CREATE_THREAD */,
                false, processId);

            if (hProcess == IntPtr.Zero)
                return false;

            // 在目标进程中分配内存
            var dllPathBytes = System.Text.Encoding.Unicode.GetBytes(dllPath + "\0");
            remoteMemory = Kernel32Api.VirtualAllocEx(
                hProcess, IntPtr.Zero, dllPathBytes.Length,
                Kernel32Api.MEM_COMMIT | Kernel32Api.MEM_RESERVE,
                Kernel32Api.PAGE_READWRITE);

            if (remoteMemory == IntPtr.Zero)
                return false;

            // 写入DLL路径
            if (!Kernel32Api.WriteProcessMemory(
                hProcess, remoteMemory, dllPathBytes,
                dllPathBytes.Length, out _))
                return false;

            // 获取LoadLibraryW地址
            var kernel32Handle = Kernel32Api.GetModuleHandle("kernel32.dll");
            var loadLibraryAddr = Kernel32Api.GetProcAddress(kernel32Handle, "LoadLibraryW");

            if (loadLibraryAddr == IntPtr.Zero)
                return false;

            // 创建远程线程调用LoadLibraryW
            var remoteThread = Kernel32Api.CreateRemoteThread(
                hProcess, IntPtr.Zero, 0,
                loadLibraryAddr, remoteMemory, 0, out _);

            if (remoteThread == IntPtr.Zero)
                return false;

            NtApi.CloseHandle(remoteThread);
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (remoteMemory != IntPtr.Zero && hProcess != IntPtr.Zero)
                Kernel32Api.VirtualFreeEx(hProcess, remoteMemory, 0, Kernel32Api.MEM_RELEASE);

            if (hProcess != IntPtr.Zero)
                NtApi.CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// 卸载已注入的DLL
    /// </summary>
    public bool EjectDll(int processId, string dllPath)
    {
        IntPtr hProcess = IntPtr.Zero;
        try
        {
            hProcess = NtApi.OpenProcess(
                NtApi.PROCESS_VM_WRITE | NtApi.PROCESS_VM_OPERATION |
                NtApi.PROCESS_QUERY_INFORMATION | 0x0001,
                false, processId);

            if (hProcess == IntPtr.Zero)
                return false;

            var kernel32Handle = Kernel32Api.GetModuleHandle("kernel32.dll");
            var freeLibraryAddr = Kernel32Api.GetProcAddress(kernel32Handle, "FreeLibrary");

            if (freeLibraryAddr == IntPtr.Zero)
                return false;

            // 注意：FreeLibrary需要模块句柄，不是路径
            // 这里简化处理，实际需要先枚举目标进程的模块找到DLL基址
            return false; // 暂不实现，需要更复杂的逻辑
        }
        catch
        {
            return false;
        }
        finally
        {
            if (hProcess != IntPtr.Zero)
                NtApi.CloseHandle(hProcess);
        }
    }
}

/// <summary>
/// 注入安全检查结果
/// </summary>
public class InjectionSafetyCheckResult
{
    public bool IsSafe { get; private set; }
    public string? Reason { get; private set; }

    public static InjectionSafetyCheckResult Safe() => new() { IsSafe = true };
    public static InjectionSafetyCheckResult Unsafe(string reason) => new() { IsSafe = false, Reason = reason };
}
