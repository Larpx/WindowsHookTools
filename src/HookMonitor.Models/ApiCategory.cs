namespace Larpx.PersonalTools.HookMonitor.Models;

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
    KeyLogging = 4,
    /// <summary>网络过滤（WFP callout、NDIS filter等）</summary>
    NetworkFiltering = 5,
    /// <summary>DNS查询拦截</summary>
    DnsInterception = 6,
    /// <summary>TCP/UDP连接监控</summary>
    NetworkConnection = 7,
    /// <summary>DLL注入（SetWindowsHookEx、远程线程等）</summary>
    DllInjection = 8,
    /// <summary>代理配置</summary>
    ProxyConfiguration = 9,
    /// <summary>Winsock LSP（分层服务提供者）</summary>
    WinsockLsp = 10
}
