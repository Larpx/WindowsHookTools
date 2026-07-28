namespace Larpx.PersonalTools.HookMonitor.Models;

/// <summary>
/// 可疑进程信息，包含进程详细参数和威胁评估
/// </summary>
public class SuspiciousProcessInfo
{
    /// <summary>进程ID</summary>
    public int ProcessId { get; set; }

    /// <summary>进程名称</summary>
    public string ProcessName { get; set; } = string.Empty;

    /// <summary>可执行文件完整路径</summary>
    public string? FilePath { get; set; }

    /// <summary>命令行参数</summary>
    public string? CommandLine { get; set; }

    /// <summary>公司/发行者</summary>
    public string? Company { get; set; }

    /// <summary>文件描述</summary>
    public string? Description { get; set; }

    /// <summary>文件版本</summary>
    public string? FileVersion { get; set; }

    /// <summary>威胁等级</summary>
    public ThreatLevel ThreatLevel { get; set; }

    /// <summary>威胁评分（0-100）</summary>
    public int ThreatScore { get; set; }

    /// <summary>被捕获的API调用记录</summary>
    public List<ApiCallRecord> ApiCalls { get; set; } = [];

    /// <summary>检测原因列表</summary>
    public List<string> DetectionReasons { get; set; } = [];

    /// <summary>首次检测时间</summary>
    public DateTime FirstDetected { get; set; } = DateTime.UtcNow;

    /// <summary>最近检测时间</summary>
    public DateTime LastDetected { get; set; } = DateTime.UtcNow;

    /// <summary>每分钟API调用频率</summary>
    public double CallFrequency { get; set; }

    /// <summary>是否为Windows服务</summary>
    public bool IsService { get; set; }

    /// <summary>服务名称（如果是服务）</summary>
    public string? ServiceName { get; set; }

    /// <summary>父进程ID</summary>
    public int ParentProcessId { get; set; }

    /// <summary>父进程名称</summary>
    public string? ParentProcessName { get; set; }

    /// <summary>进程启动时间</summary>
    public DateTime StartTime { get; set; }

    /// <summary>是否为受保护进程（PPL）</summary>
    public bool IsProtected { get; set; }

    /// <summary>是否为系统关键进程</summary>
    public bool IsSystemCritical { get; set; }

    /// <summary>进程会话ID</summary>
    public int SessionId { get; set; }

    /// <summary>进程架构（x86/x64/ARM64）</summary>
    public string? Architecture { get; set; }

    /// <summary>进程打开的句柄数</summary>
    public int HandleCount { get; set; }

    /// <summary>进程工作集大小（字节）</summary>
    public long WorkingSetSize { get; set; }

    /// <summary>
    /// 主要检测原因（用于列表显示）
    /// </summary>
    public string PrimaryDetectionReason => DetectionReasons.Count > 0
        ? DetectionReasons[0]
        : "未知";
}
