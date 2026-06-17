namespace HookMonitor.Models;

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
    BehaviorAnalysis = 3
}
