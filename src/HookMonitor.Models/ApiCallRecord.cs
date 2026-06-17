namespace HookMonitor.Models;

/// <summary>
/// API调用记录，记录一次被监控API的调用
/// </summary>
public class ApiCallRecord
{
    /// <summary>调用进程ID</summary>
    public int ProcessId { get; set; }

    /// <summary>调用进程名称</summary>
    public string ProcessName { get; set; } = string.Empty;

    /// <summary>API类别</summary>
    public ApiCategory Category { get; set; }

    /// <summary>被调用的API名称</summary>
    public string ApiName { get; set; } = string.Empty;

    /// <summary>调用时间戳</summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>检测来源</summary>
    public DetectionSource Source { get; set; }

    /// <summary>调用详情</summary>
    public string? Detail { get; set; }
}
