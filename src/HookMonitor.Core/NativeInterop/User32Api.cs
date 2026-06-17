using System.Runtime.InteropServices;
using System.Text;

namespace HookMonitor.Core.NativeInterop;

/// <summary>
/// User32 API P/Invoke声明，用于窗口和截屏相关检测
/// </summary>
public static class User32Api
{
    private const string USER32 = "user32.dll";

    /// <summary>
    /// 打印窗口（截屏API之一）
    /// </summary>
    [DllImport(USER32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool PrintWindow(
        IntPtr hwnd,
        IntPtr hdcBlt,
        uint nFlags);

    /// <summary>
    /// 获取窗口DC
    /// </summary>
    [DllImport(USER32, SetLastError = true)]
    public static extern IntPtr GetWindowDC(IntPtr hWnd);

    /// <summary>
    /// 枚举窗口
    /// </summary>
    [DllImport(USER32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EnumWindows(
        EnumWindowsProc lpEnumFunc,
        IntPtr lParam);

    /// <summary>
    /// 获取窗口所属进程ID
    /// </summary>
    [DllImport(USER32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern GetWindowThreadProcessIdResult GetWindowThreadProcessId(
        IntPtr hWnd,
        out int lpdwProcessId);

    /// <summary>
    /// 获取前台窗口
    /// </summary>
    [DllImport(USER32, SetLastError = false)]
    public static extern IntPtr GetForegroundWindow();

    /// <summary>
    /// 获取窗口文本
    /// </summary>
    [DllImport(USER32, SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int GetWindowText(
        IntPtr hWnd,
        StringBuilder lpString,
        int nMaxCount);

    /// <summary>
    /// 设置Windows钩子
    /// </summary>
    [DllImport(USER32, SetLastError = true)]
    public static extern IntPtr SetWindowsHookEx(
        int idHook,
        IntPtr lpfn,
        IntPtr hMod,
        uint dwThreadId);

    /// <summary>
    /// 卸载Windows钩子
    /// </summary>
    [DllImport(USER32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool UnhookWindowsHookEx(IntPtr hhk);

    /// <summary>
    /// 枚举窗口回调
    /// </summary>
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    /// <summary>
    /// GetWindowThreadProcessId 返回值类型
    /// </summary>
    public struct GetWindowThreadProcessIdResult
    {
        private uint _value;
        public static implicit operator uint(GetWindowThreadProcessIdResult r) => r._value;
        public static implicit operator GetWindowThreadProcessIdResult(uint v) => new() { _value = v };
    }
}
