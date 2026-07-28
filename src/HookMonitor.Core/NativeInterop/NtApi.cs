using System.Runtime.InteropServices;
using System.Text;

namespace Larpx.PersonalTools.HookMonitor.Core.NativeInterop;

/// <summary>
/// NT底层API P/Invoke声明，优先使用ntdll.dll而非高级Win32 API
/// 防止恶意进程通过Hook高级API来规避检测
/// </summary>
public static class NtApi
{
    private const string NTDLL = "ntdll.dll";
    private const string KERNEL32 = "kernel32.dll";

    #region NtQuerySystemInformation

    /// <summary>
    /// 查询系统信息（底层API，用于枚举进程和句柄）
    /// </summary>
    [DllImport(NTDLL, SetLastError = false)]
    public static extern uint NtQuerySystemInformation(
        NtStructures.SYSTEM_INFORMATION_CLASS SystemInformationClass,
        IntPtr SystemInformation,
        int SystemInformationLength,
        out int ReturnLength);

    #endregion

    #region NtQueryInformationProcess

    /// <summary>
    /// 查询进程信息
    /// </summary>
    [DllImport(NTDLL, SetLastError = false)]
    public static extern uint NtQueryInformationProcess(
        IntPtr ProcessHandle,
        NtStructures.PROCESS_INFORMATION_CLASS ProcessInformationClass,
        IntPtr ProcessInformation,
        int ProcessInformationLength,
        out int ReturnLength);

    #endregion

    #region NtQueryObject

    /// <summary>
    /// 查询对象信息
    /// </summary>
    [DllImport(NTDLL, SetLastError = false)]
    public static extern uint NtQueryObject(
        IntPtr Handle,
        int ObjectTypeInformation,
        IntPtr ObjectInformation,
        int ObjectInformationLength,
        out int ReturnLength);

    /// <summary>
    /// 对象类型信息类别
    /// </summary>
    public const int ObjectTypeInformation = 2;
    public const int ObjectNameInformation = 1;

    #endregion

    #region 进程操作

    /// <summary>
    /// 打开进程（底层方式）
    /// </summary>
    [DllImport(KERNEL32, SetLastError = true)]
    public static extern IntPtr OpenProcess(
        uint processAccess,
        bool bInheritHandle,
        int processId);

    /// <summary>
    /// 关闭句柄
    /// </summary>
    [DllImport(KERNEL32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    /// <summary>
    /// 读取进程内存
    /// </summary>
    [DllImport(KERNEL32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int dwSize,
        out int lpNumberOfBytesRead);

    #endregion

    #region 进程访问权限常量

    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint PROCESS_VM_WRITE = 0x0020;
    public const uint PROCESS_VM_OPERATION = 0x0008;
    public const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    public const uint SYNCHRONIZE = 0x100000;

    #endregion

    #region 线程操作

    /// <summary>
    /// 打开线程
    /// </summary>
    [DllImport(KERNEL32, SetLastError = true)]
    public static extern IntPtr OpenThread(
        uint dwDesiredAccess,
        bool bInheritHandle,
        int dwThreadId);

    /// <summary>
    /// 等待对象信号
    /// </summary>
    [DllImport(KERNEL32, SetLastError = true)]
    public static extern uint WaitForSingleObject(
        IntPtr hHandle,
        uint dwMilliseconds);

    #endregion

    #region 辅助方法

    /// <summary>
    /// 从UNICODE_STRING读取字符串
    /// </summary>
    public static string? ReadUnicodeString(IntPtr processHandle, NtStructures.UNICODE_STRING us)
    {
        if (us.Length == 0 || us.Buffer == IntPtr.Zero)
            return null;

        try
        {
            var buffer = new byte[us.Length];
            if (ReadProcessMemory(processHandle, us.Buffer, buffer, us.Length, out _))
            {
                return Encoding.Unicode.GetString(buffer);
            }

            // 如果无法跨进程读取，尝试直接读取（同一进程内）
            return Marshal.PtrToStringUni(us.Buffer, us.Length / 2);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 从本地UNICODE_STRING读取字符串（当前进程内）
    /// </summary>
    public static string? ReadLocalUnicodeString(NtStructures.UNICODE_STRING us)
    {
        if (us.Length == 0 || us.Buffer == IntPtr.Zero)
            return null;

        try
        {
            return Marshal.PtrToStringUni(us.Buffer, us.Length / 2);
        }
        catch
        {
            return null;
        }
    }

    #endregion
}
