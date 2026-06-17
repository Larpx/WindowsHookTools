namespace HookMonitor.Models;

/// <summary>
/// WFP网络过滤器信息，描述Windows Filtering Platform中的过滤驱动/Provider
/// 上网行为管理软件通常通过WFP callout驱动实现网络流量过滤
/// </summary>
public class NetworkFilterInfo
{
    /// <summary>WFP Provider Key（GUID）</summary>
    public Guid ProviderKey { get; set; }

    /// <summary>Provider名称</summary>
    public string ProviderName { get; set; } = string.Empty;

    /// <summary>Provider描述</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>关联的服务名称</summary>
    public string? ServiceName { get; set; }

    /// <summary>Provider Flags</summary>
    public uint Flags { get; set; }

    /// <summary>关联的Callout数量</summary>
    public int CalloutCount { get; set; }

    /// <summary>关联的Filter数量</summary>
    public int FilterCount { get; set; }

    /// <summary>关联的Sublayer数量</summary>
    public int SublayerCount { get; set; }

    /// <summary>是否为持久化Provider（重启后仍存在）</summary>
    public bool IsPersistent { get; set; }

    /// <summary>是否为系统内置Provider</summary>
    public bool IsSystemProvider { get; set; }

    /// <summary>检测时间</summary>
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// WFP Callout信息，描述具体的过滤回调点
/// </summary>
public class WfpCalloutInfo
{
    /// <summary>Callout Key（GUID）</summary>
    public Guid CalloutKey { get; set; }

    /// <summary>Callout名称</summary>
    public string CalloutName { get; set; } = string.Empty;

    /// <summary>所属Provider Key</summary>
    public Guid ProviderKey { get; set; }

    /// <summary>所属Provider名称</summary>
    public string ProviderName { get; set; } = string.Empty;

    /// <summary>Callout Flags</summary>
    public uint Flags { get; set; }

    /// <summary>关联的Filter数量</summary>
    public int FilterCount { get; set; }

    /// <summary>过滤层GUID</summary>
    public Guid ApplicableLayer { get; set; }

    /// <summary>过滤层名称</summary>
    public string ApplicableLayerName { get; set; } = string.Empty;
}

/// <summary>
/// WFP Filter信息，描述具体的过滤规则
/// </summary>
public class WfpFilterInfo
{
    /// <summary>Filter Key（GUID）</summary>
    public Guid FilterKey { get; set; }

    /// <summary>Filter名称</summary>
    public string FilterName { get; set; } = string.Empty;

    /// <summary>Filter描述</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>所属Provider Key</summary>
    public Guid ProviderKey { get; set; }

    /// <summary>所属Sublayer Key</summary>
    public Guid SubLayerKey { get; set; }

    /// <summary>Filter权重</summary>
    public ulong Weight { get; set; }

    /// <summary>Filter Flags</summary>
    public uint Flags { get; set; }

    /// <summary>过滤层Key</summary>
    public Guid LayerKey { get; set; }

    /// <summary>是否为阻止规则</summary>
    public bool IsBlock { get; set; }

    /// <summary>是否为允许规则</summary>
    public bool IsPermit { get; set; }

    /// <summary>是否为Callout规则</summary>
    public bool IsCallout { get; set; }
}