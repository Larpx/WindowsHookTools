namespace HookMonitor.Models;

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

    /// <summary>上次扫描时间</summary>
    public DateTime LastScanTime { get; set; }

    /// <summary>错误信息</summary>
    public string? ErrorMessage { get; set; }
}
