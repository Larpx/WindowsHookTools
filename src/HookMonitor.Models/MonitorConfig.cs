namespace HookMonitor.Models;

/// <summary>
/// 监控配置
/// </summary>
public class MonitorConfig
{
    /// <summary>扫描间隔（秒）</summary>
    public int ScanIntervalSeconds { get; set; } = 10;

    /// <summary>威胁评分阈值</summary>
    public int ThreatThreshold { get; set; } = 30;

    /// <summary>是否启用ETW监控</summary>
    public bool EnableEtw { get; set; } = true;

    /// <summary>是否启用句柄扫描</summary>
    public bool EnableHandleScan { get; set; } = true;

    /// <summary>是否启用IAT Hook（高级功能）</summary>
    public bool EnableIatHook { get; set; } = false;

    /// <summary>是否启行为分析</summary>
    public bool EnableBehaviorAnalysis { get; set; } = true;

    /// <summary>白名单进程名列表（不监控）</summary>
    public List<string> WhitelistedProcesses { get; set; } = [];

    /// <summary>黑名单进程名列表（重点监控）</summary>
    public List<string> BlacklistedProcesses { get; set; } = [];

    /// <summary>最大API调用记录数</summary>
    public int MaxApiCallRecords { get; set; } = 10000;

    /// <summary>进程枚举频率阈值（每分钟调用次数超过此值视为可疑）</summary>
    public int ProcessEnumFrequencyThreshold { get; set; } = 6;

    /// <summary>截屏API频率阈值（每分钟调用次数超过此值视为可疑）</summary>
    public int ScreenCaptureFrequencyThreshold { get; set; } = 3;
}
