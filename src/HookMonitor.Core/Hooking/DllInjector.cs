using System.Diagnostics;
using System.Runtime.InteropServices;
using Larpx.PersonalTools.HookMonitor.Core.NativeInterop;

namespace Larpx.PersonalTools.HookMonitor.Core.Hooking;

/// <summary>
/// DLL注入器，将监控DLL注入到目标进程中
/// 包含安全检查，避免注入系统关键进程和受保护进程
/// 优先使用QueueUserAPC注入（更隐蔽），回退到NtCreateThreadEx
/// </summary>
public class DllInjector
{
    /// <summary>
    /// 注入方法枚举
    /// </summary>
    public enum InjectionMethod
    {
        /// <summary>QueueUserAPC注入（推荐，最隐蔽）</summary>
        QueueUserAPC,
        /// <summary>NtCreateThreadEx注入（回退方案）</summary>
        NtCreateThreadEx,
        /// <summary>CreateRemoteThread注入（经典方式，易被检测）</summary>
        CreateRemoteThread
    }

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

    #region P/Invoke声明

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint QueueUserAPC(
        IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

    [DllImport("ntdll.dll", SetLastError = false)]
    private static extern uint NtCreateThreadEx(
        out IntPtr threadHandle,
        uint desiredAccess,
        IntPtr objectAttributes,
        IntPtr processHandle,
        IntPtr startAddress,
        IntPtr argument,
        uint createFlags,
        uint zeroBits,
        uint stackSize,
        uint maximumStackSize,
        IntPtr attributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern uint EnumProcessModulesEx(
        IntPtr hProcess,
        IntPtr[] lphModule,
        uint cb,
        out uint lpcbNeeded,
        uint dwFilterFlag);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetModuleFileNameExW(
        IntPtr hProcess,
        IntPtr hModule,
        System.Text.StringBuilder lpFilename,
        uint nSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct THREADENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ThreadID;
        public uint th32OwnerProcessID;
        public uint tpBasePri;
        public uint tpDeltaPri;
        public uint dwFlags;
    }

    private const uint TH32CS_SNAPTHREAD = 0x00000004;
    private const uint THREAD_SET_CONTEXT = 0x0010;
    private const uint THREAD_QUERY_INFORMATION = 0x0040;
    private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    private const uint LIST_MODULES_ALL = 0x03;

    #endregion

    /// <summary>
    /// 检查进程是否可以安全注入
    /// </summary>
    public InjectionSafetyCheckResult CheckInjectionSafety(string processName, int processId, bool isProtected)
    {
        if (processId == Kernel32Api.GetCurrentProcessId())
            return InjectionSafetyCheckResult.Unsafe("不能注入自身进程");

        if (isProtected)
            return InjectionSafetyCheckResult.Unsafe("受保护进程（PPL），注入可能触发安全机制");

        if (CriticalProcesses.Contains(processName))
            return InjectionSafetyCheckResult.Unsafe("系统关键进程，注入可能导致蓝屏");

        if (SecurityProcesses.Contains(processName))
            return InjectionSafetyCheckResult.Unsafe("安全软件进程，注入可能触发报警");

        if (processId <= 4)
            return InjectionSafetyCheckResult.Unsafe("系统内核进程，禁止注入");

        return InjectionSafetyCheckResult.Safe();
    }

    /// <summary>
    /// 注入DLL到目标进程
    /// 优先使用QueueUserAPC，回退到NtCreateThreadEx
    /// </summary>
    public bool InjectDll(int processId, string dllPath)
    {
        return InjectDll(processId, dllPath, InjectionMethod.QueueUserAPC);
    }

    /// <summary>
    /// 使用指定方式注入DLL到目标进程
    /// </summary>
    public bool InjectDll(int processId, string dllPath, InjectionMethod method)
    {
        IntPtr hProcess = IntPtr.Zero;
        IntPtr remoteMemory = IntPtr.Zero;

        try
        {
            hProcess = NtApi.OpenProcess(
                NtApi.PROCESS_VM_WRITE | NtApi.PROCESS_VM_OPERATION |
                NtApi.PROCESS_QUERY_INFORMATION | 0x0001 /* PROCESS_CREATE_THREAD */,
                false, processId);

            if (hProcess == IntPtr.Zero)
                return false;

            // 在目标进程中分配内存并写入DLL路径
            var dllPathBytes = System.Text.Encoding.Unicode.GetBytes(dllPath + "\0");
            remoteMemory = Kernel32Api.VirtualAllocEx(
                hProcess, IntPtr.Zero, dllPathBytes.Length,
                Kernel32Api.MEM_COMMIT | Kernel32Api.MEM_RESERVE,
                Kernel32Api.PAGE_READWRITE);

            if (remoteMemory == IntPtr.Zero)
                return false;

            if (!Kernel32Api.WriteProcessMemory(
                hProcess, remoteMemory, dllPathBytes,
                dllPathBytes.Length, out _))
                return false;

            // 获取LoadLibraryW地址
            var kernel32Handle = Kernel32Api.GetModuleHandle("kernel32.dll");
            var loadLibraryAddr = Kernel32Api.GetProcAddress(kernel32Handle, "LoadLibraryW");

            if (loadLibraryAddr == IntPtr.Zero)
                return false;

            // 按指定方法注入
            bool result = method switch
            {
                InjectionMethod.QueueUserAPC => InjectViaQueueUserAPC(hProcess, processId, loadLibraryAddr, remoteMemory),
                InjectionMethod.NtCreateThreadEx => InjectViaNtCreateThreadEx(hProcess, loadLibraryAddr, remoteMemory),
                InjectionMethod.CreateRemoteThread => InjectViaCreateRemoteThread(hProcess, loadLibraryAddr, remoteMemory),
                _ => false
            };

            // QueueUserAPC失败时自动回退
            if (!result && method == InjectionMethod.QueueUserAPC)
            {
                result = InjectViaNtCreateThreadEx(hProcess, loadLibraryAddr, remoteMemory);
            }

            return result;
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
    /// QueueUserAPC注入：向目标进程的所有线程队列APC
    /// 不创建新线程，复用已有线程执行LoadLibraryW，更隐蔽
    /// </summary>
    private bool InjectViaQueueUserAPC(IntPtr hProcess, int processId, IntPtr loadLibraryAddr, IntPtr remoteMemory)
    {
        var threadIds = GetProcessThreadIds((uint)processId);
        if (threadIds.Count == 0)
            return false;

        uint successCount = 0;
        foreach (var threadId in threadIds)
        {
            // 打开线程需要THREAD_SET_CONTEXT权限
            var hThread = NtApi.OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, false, (int)threadId);
            if (hThread == IntPtr.Zero)
                continue;

            try
            {
                var result = QueueUserAPC(loadLibraryAddr, hThread, remoteMemory);
                if (result != 0)
                    successCount++;
            }
            finally
            {
                NtApi.CloseHandle(hThread);
            }
        }

        return successCount > 0;
    }

    /// <summary>
    /// NtCreateThreadEx注入：使用ntdll底层API创建远程线程
    /// 比CreateRemoteThread更底层，部分安全软件不监控此API
    /// </summary>
    private bool InjectViaNtCreateThreadEx(IntPtr hProcess, IntPtr loadLibraryAddr, IntPtr remoteMemory)
    {
        var status = NtCreateThreadEx(
            out var threadHandle,
            0x1FFFFF, // THREAD_ALL_ACCESS
            IntPtr.Zero,
            hProcess,
            loadLibraryAddr,
            remoteMemory,
            0, // 创建后不立即挂起
            0, 0, 0,
            IntPtr.Zero);

        if (!NtStatus.IsSuccess(status) || threadHandle == IntPtr.Zero)
            return false;

        // 等待线程完成加载
        NtApi.WaitForSingleObject(threadHandle, 10000);
        NtApi.CloseHandle(threadHandle);
        return true;
    }

    /// <summary>
    /// CreateRemoteThread注入（经典方式，易被安全软件检测，仅作最后回退）
    /// </summary>
    private bool InjectViaCreateRemoteThread(IntPtr hProcess, IntPtr loadLibraryAddr, IntPtr remoteMemory)
    {
        var remoteThread = Kernel32Api.CreateRemoteThread(
            hProcess, IntPtr.Zero, 0,
            loadLibraryAddr, remoteMemory, 0, out _);

        if (remoteThread == IntPtr.Zero)
            return false;

        NtApi.CloseHandle(remoteThread);
        return true;
    }

    /// <summary>
    /// 卸载已注入的DLL
    /// 通过枚举目标进程模块找到DLL基址，然后远程调用FreeLibrary
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

            // 枚举目标进程的模块，查找已注入的DLL
            var moduleBase = FindRemoteModule(hProcess, dllPath);
            if (moduleBase == IntPtr.Zero)
                return false;

            // 获取FreeLibrary地址
            var kernel32Handle = Kernel32Api.GetModuleHandle("kernel32.dll");
            var freeLibraryAddr = Kernel32Api.GetProcAddress(kernel32Handle, "FreeLibrary");

            if (freeLibraryAddr == IntPtr.Zero)
                return false;

            // 优先使用NtCreateThreadEx远程调用FreeLibrary
            var status = NtCreateThreadEx(
                out var threadHandle,
                0x1FFFFF,
                IntPtr.Zero,
                hProcess,
                freeLibraryAddr,
                moduleBase,
                0, 0, 0, 0,
                IntPtr.Zero);

            if (!NtStatus.IsSuccess(status) || threadHandle == IntPtr.Zero)
            {
                // 回退到CreateRemoteThread
                threadHandle = Kernel32Api.CreateRemoteThread(
                    hProcess, IntPtr.Zero, 0,
                    freeLibraryAddr, moduleBase, 0, out _);

                if (threadHandle == IntPtr.Zero)
                    return false;
            }

            // 等待FreeLibrary完成
            NtApi.WaitForSingleObject(threadHandle, 10000);
            NtApi.CloseHandle(threadHandle);
            return true;
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

    /// <summary>
    /// 在目标进程中查找指定DLL的模块基址
    /// </summary>
    private static IntPtr FindRemoteModule(IntPtr hProcess, string dllPath)
    {
        var dllFileName = Path.GetFileName(dllPath);

        // 先尝试使用EnumProcessModulesEx
        var modules = new IntPtr[1024];
        var result = EnumProcessModulesEx(
            hProcess, modules, (uint)(modules.Length * IntPtr.Size),
            out var needed, LIST_MODULES_ALL);

        if (result != 0 && needed > 0)
        {
            var moduleCount = (int)(needed / IntPtr.Size);
            var nameBuilder = new System.Text.StringBuilder(260);

            for (var i = 0; i < moduleCount; i++)
            {
                nameBuilder.Clear();
                GetModuleFileNameExW(hProcess, modules[i], nameBuilder, 260);

                var moduleName = nameBuilder.ToString();
                if (string.IsNullOrEmpty(moduleName))
                    continue;

                // 比较文件名（不比较完整路径，因为远程进程中路径可能不同）
                if (string.Equals(Path.GetFileName(moduleName), dllFileName, StringComparison.OrdinalIgnoreCase))
                {
                    return modules[i];
                }
            }
        }

        // 回退：使用Process.GetProcessById枚举模块
        try
        {
            var processId = GetProcessId(hProcess);
            if (processId > 0)
            {
                using var process = Process.GetProcessById((int)processId);
                foreach (ProcessModule module in process.Modules)
                {
                    if (string.Equals(Path.GetFileName(module.FileName), dllFileName, StringComparison.OrdinalIgnoreCase))
                    {
                        return module.BaseAddress;
                    }
                }
            }
        }
        catch
        {
            // 跨架构访问可能失败
        }

        return IntPtr.Zero;
    }

    /// <summary>
    /// 获取进程ID（从进程句柄）
    /// </summary>
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetProcessId(IntPtr hProcess);

    /// <summary>
    /// 获取指定进程的所有线程ID
    /// </summary>
    private static List<uint> GetProcessThreadIds(uint processId)
    {
        var threadIds = new List<uint>();
        var snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1))
            return threadIds;

        try
        {
            var entry = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<THREADENTRY32>() };

            if (Thread32First(snapshot, ref entry))
            {
                do
                {
                    if (entry.th32OwnerProcessID == processId)
                    {
                        threadIds.Add(entry.th32ThreadID);
                    }
                }
                while (Thread32Next(snapshot, ref entry));
            }
        }
        finally
        {
            NtApi.CloseHandle(snapshot);
        }

        return threadIds;
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
