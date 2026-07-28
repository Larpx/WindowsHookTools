using System.Runtime.InteropServices;
using System.Text;

namespace Larpx.PersonalTools.HookMonitor.Core.NativeInterop;

/// <summary>
/// Kernel32 API P/Invoke声明
/// </summary>
public static class Kernel32Api
{
    private const string KERNEL32 = "kernel32.dll";

    /// <summary>
    /// 打开进程
    /// </summary>
    [DllImport(KERNEL32, SetLastError = true)]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        int dwProcessId);

    /// <summary>
    /// 关闭句柄
    /// </summary>
    [DllImport(KERNEL32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    /// <summary>
    /// 获取模块文件名
    /// </summary>
    [DllImport(KERNEL32, SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint GetModuleFileNameEx(
        IntPtr hProcess,
        IntPtr hModule,
        StringBuilder lpFilename,
        uint nSize);

    /// <summary>
    /// 获取进程命令行（通过查询进程PEB）
    /// </summary>
    [DllImport(KERNEL32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int dwSize,
        out int lpNumberOfBytesRead);

    /// <summary>
    /// 在指定进程中分配内存
    /// </summary>
    [DllImport(KERNEL32, SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        int dwSize,
        uint flAllocationType,
        uint flProtect);

    /// <summary>
    /// 释放指定进程中的内存
    /// </summary>
    [DllImport(KERNEL32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool VirtualFreeEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        int dwSize,
        uint dwFreeType);

    /// <summary>
    /// 向指定进程写入数据
    /// </summary>
    [DllImport(KERNEL32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        out int lpNumberOfBytesWritten);

    /// <summary>
    /// 在指定进程中创建远程线程
    /// </summary>
    [DllImport(KERNEL32, SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out IntPtr lpThreadId);

    /// <summary>
    /// 获取LoadLibraryW函数地址
    /// </summary>
    [DllImport(KERNEL32, SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr GetProcAddress(
        IntPtr hModule,
        string lpProcName);

    /// <summary>
    /// 获取模块句柄
    /// </summary>
    [DllImport(KERNEL32, SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr GetModuleHandle(
        string lpModuleName);

    /// <summary>
    /// 获取当前进程ID
    /// </summary>
    [DllImport(KERNEL32, SetLastError = false)]
    public static extern int GetCurrentProcessId();

    // 内存分配常量
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint MEM_RELEASE = 0x8000;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_EXECUTE_READ = 0x20;
}
