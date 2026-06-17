namespace HookMonitor.Models;

/// <summary>
/// 被监控的API类别
/// </summary>
public enum ApiCategory
{
    /// <summary>进程枚举（NtQuerySystemInformation等）</summary>
    ProcessEnumeration = 0,
    /// <summary>屏幕截取（BitBlt、PrintWindow等）</summary>
    ScreenCapture = 1,
    /// <summary>窗口监控（GetWindow、EnumWindows等）</summary>
    WindowMonitoring = 2,
    /// <summary>剪贴板访问</summary>
    ClipboardAccess = 3,
    /// <summary>键盘输入监控</summary>
    KeyLogging = 4
}
