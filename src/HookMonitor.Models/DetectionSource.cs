namespace Larpx.PersonalTools.HookMonitor.Models;

/// <summary>
/// 检测来源
/// </summary>
public enum DetectionSource
{
    /// <summary>ETW事件追踪</summary>
    Etw = 0,
    /// <summary>系统句柄扫描</summary>
    HandleScan = 1,
    /// <summary>IAT Hook拦截</summary>
    IatHook = 2,
    /// <summary>行为模式分析</summary>
    BehaviorAnalysis = 3,
    /// <summary>WFP网络过滤器检测</summary>
    WfpDetection = 4,
    /// <summary>DNS查询监控</summary>
    DnsMonitor = 5,
    /// <summary>网络连接监控</summary>
    NetworkMonitor = 6,
    /// <summary>Winsock LSP检测</summary>
    LspDetection = 7,
    /// <summary>DLL注入检测</summary>
    InjectDetection = 8,
    /// <summary>代理配置检测</summary>
    ProxyDetection = 9,
    /// <summary>内核驱动检测</summary>
    DriverDetection = 10
}
