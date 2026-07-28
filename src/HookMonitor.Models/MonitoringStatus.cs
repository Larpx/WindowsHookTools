namespace Larpx.PersonalTools.HookMonitor.Models;

/// <summary>
/// 监控运行状态
/// </summary>
public class MonitoringStatus
{
    /// <summary>是否正在监控</summary>
    public bool IsRunning { get; set; }

    /// <summary>监控开始时间</summary>
    public DateTime StartTime { get; set; }

    /// <summary>已扫描的总进程数</summary>
    public int TotalProcessesScanned { get; set; }

    /// <summary>已发现的可疑进程数</summary>
    public int SuspiciousProcessCount { get; set; }

    /// <summary>已捕获的API调用总数</summary>
    public long TotalApiCallsCaptured { get; set; }

    /// <summary>ETW会话是否活跃</summary>
    public bool IsEtwActive { get; set; }

    /// <summary>句柄扫描是否活跃</summary>
    public bool IsHandleScanActive { get; set; }

    /// <summary>IAT Hook是否活跃</summary>
    public bool IsIatHookActive { get; set; }

    // ---- 内核视角检测状态 ----

    /// <summary>WFP网络过滤器检测是否活跃</summary>
    public bool IsWfpDetectionActive { get; set; }

    /// <summary>DNS监控是否活跃</summary>
    public bool IsDnsMonitorActive { get; set; }

    /// <summary>网络连接监控是否活跃</summary>
    public bool IsNetworkMonitorActive { get; set; }

    /// <summary>LSP检测是否活跃</summary>
    public bool IsLspDetectionActive { get; set; }

    /// <summary>DLL注入检测是否活跃</summary>
    public bool IsInjectDetectionActive { get; set; }

    /// <summary>代理检测是否活跃</summary>
    public bool IsProxyDetectionActive { get; set; }

    /// <summary>内核驱动检测是否活跃</summary>
    public bool IsDriverDetectionActive { get; set; }

    // ---- 统计数据 ----

    /// <summary>检测到的第三方WFP Provider数量</summary>
    public int DetectedWfpProviders { get; set; }

    /// <summary>检测到的第三方LSP数量</summary>
    public int DetectedLsps { get; set; }

    /// <summary>检测到的注入DLL数量</summary>
    public int DetectedInjectedDlls { get; set; }

    /// <summary>检测到的第三方网络驱动数量</summary>
    public int DetectedNetworkDrivers { get; set; }

    /// <summary>上次扫描时间</summary>
    public DateTime LastScanTime { get; set; }

    /// <summary>错误信息</summary>
    public string? ErrorMessage { get; set; }
}
