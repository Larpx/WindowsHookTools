using System.Runtime.InteropServices;

namespace HookMonitor.Core.NativeInterop;

/// <summary>
/// GDI相关API P/Invoke声明，用于截屏检测
/// </summary>
public static class GdiApi
{
    private const string GDI32 = "gdi32.dll";
    private const string USER32 = "user32.dll";

    /// <summary>
    /// 获取设备上下文
    /// </summary>
    [DllImport(USER32, SetLastError = true)]
    public static extern IntPtr GetDC(IntPtr hWnd);

    /// <summary>
    /// 释放设备上下文
    /// </summary>
    [DllImport(USER32, SetLastError = true)]
    public static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

    /// <summary>
    /// 创建兼容内存DC
    /// </summary>
    [DllImport(GDI32, SetLastError = true)]
    public static extern IntPtr CreateCompatibleDC(IntPtr hdc);

    /// <summary>
    /// 创建兼容位图
    /// </summary>
    [DllImport(GDI32, SetLastError = true)]
    public static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);

    /// <summary>
    /// 位块传输（截屏核心API）
    /// </summary>
    [DllImport(GDI32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool BitBlt(
        IntPtr hdc, int x, int y, int cx, int cy,
        IntPtr hdcSrc, int x1, int y1, uint rop);

    /// <summary>
    /// 获取设备上下文中的位图信息
    /// </summary>
    [DllImport(GDI32, SetLastError = true)]
    public static extern int GetDeviceCaps(IntPtr hdc, int nIndex);

    /// <summary>
    /// 获取GDI对象数量
    /// </summary>
    [DllImport(GDI32, SetLastError = false)]
    public static extern uint GetGuiResources(IntPtr hProcess, uint uiFlags);

    /// <summary>
    /// 枚举GDI对象句柄
    /// </summary>
    [DllImport(USER32, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool EnumObjects(
        IntPtr hdc, int nObjectType,
        IntPtr lpFunc, IntPtr lParam);

    // GetDeviceCaps 索引常量
    public const int HORZRES = 8;
    public const int VERTRES = 10;
    public const int BITSPIXEL = 12;
    public const int PLANES = 14;

    // GetGuiResources 标志
    public const uint GR_GDIOBJECTS = 0;
    public const uint GR_USEROBJECTS = 1;

    // BitBlt 光栅操作码
    public const uint SRCCOPY = 0x00CC0020;
    public const uint CAPTUREBLT = 0x40000000;
}
