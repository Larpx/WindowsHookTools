namespace Larpx.PersonalTools.HookMonitor.Models;

/// <summary>
/// 威胁等级
/// </summary>
public enum ThreatLevel
{
    /// <summary>无威胁</summary>
    None = 0,
    /// <summary>低威胁</summary>
    Low = 1,
    /// <summary>中等威胁</summary>
    Medium = 2,
    /// <summary>高威胁</summary>
    High = 3,
    /// <summary>严重威胁</summary>
    Critical = 4
}
