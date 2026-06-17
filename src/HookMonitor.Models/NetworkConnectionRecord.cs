namespace HookMonitor.Models;

/// <summary>
/// 网络连接记录，记录TCP/UDP连接事件
/// 用于检测上网行为管理软件的代理转发和流量劫持行为
/// </summary>
public class NetworkConnectionRecord
{
    /// <summary>发起连接的进程ID</summary>
    public int ProcessId { get; set; }

    /// <summary>发起连接的进程名称</summary>
    public string ProcessName { get; set; } = string.Empty;

    /// <summary>连接协议（TCP/UDP）</summary>
    public string Protocol { get; set; } = string.Empty;

    /// <summary>本地地址</summary>
    public string LocalAddress { get; set; } = string.Empty;

    /// <summary>本地端口</summary>
    public int LocalPort { get; set; }

    /// <summary>远程地址</summary>
    public string RemoteAddress { get; set; } = string.Empty;

    /// <summary>远程端口</summary>
    public int RemotePort { get; set; }

    /// <summary>连接状态</summary>
    public string ConnectionState { get; set; } = string.Empty;

    /// <summary>事件时间戳</summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>是否为代理连接（目标端口为常见代理端口）</summary>
    public bool IsSuspiciousProxy { get; set; }

    /// <summary>可疑原因</summary>
    public string? SuspicionReason { get; set; }
}

/// <summary>
/// DNS查询记录
/// </summary>
public class DnsQueryRecord
{
    /// <summary>发起查询的进程ID</summary>
    public int ProcessId { get; set; }

    /// <summary>发起查询的进程名称</summary>
    public string ProcessName { get; set; } = string.Empty;

    /// <summary>查询的域名</summary>
    public string QueryName { get; set; } = string.Empty;

    /// <summary>查询类型（A、AAAA、MX等）</summary>
    public string QueryType { get; set; } = string.Empty;

    /// <summary>查询结果</summary>
    public string? QueryResult { get; set; }

    /// <summary>DNS服务器地址</summary>
    public string? DnsServer { get; set; }

    /// <summary>查询状态</summary>
    public uint Status { get; set; }

    /// <summary>事件时间戳</summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>是否为可疑DNS查询（被重定向或拦截）</summary>
    public bool IsSuspicious { get; set; }

    /// <summary>可疑原因</summary>
    public string? SuspicionReason { get; set; }
}

/// <summary>
/// DLL注入检测信息
/// </summary>
public class InjectDetectionInfo
{
    /// <summary>被注入的进程ID</summary>
    public int TargetProcessId { get; set; }

    /// <summary>被注入的进程名称</summary>
    public string TargetProcessName { get; set; } = string.Empty;

    /// <summary>注入的DLL路径</summary>
    public string InjectedDllPath { get; set; } = string.Empty;

    /// <summary>注入来源进程ID（如果可追溯）</summary>
    public int? SourceProcessId { get; set; }

    /// <summary>注入来源进程名称</summary>
    public string? SourceProcessName { get; set; }

    /// <summary>注入方式</summary>
    public string InjectionMethod { get; set; } = string.Empty;

    /// <summary>检测时间</summary>
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;

    /// <summary>是否为系统合法DLL</summary>
    public bool IsSystemDll { get; set; }

    /// <summary>DLL签名信息</summary>
    public string? DllCompany { get; set; }

    /// <summary>DLL描述</summary>
    public string? DllDescription { get; set; }
}

/// <summary>
/// 内核驱动信息
/// </summary>
public class KernelDriverInfo
{
    /// <summary>驱动名称</summary>
    public string DriverName { get; set; } = string.Empty;

    /// <summary>驱动路径</summary>
    public string? DriverPath { get; set; }

    /// <summary>驱动类型</summary>
    public string? DriverType { get; set; }

    /// <summary>驱动描述</summary>
    public string? Description { get; set; }

    /// <summary>驱动状态</summary>
    public string State { get; set; } = string.Empty;

    /// <summary>是否为网络过滤驱动</summary>
    public bool IsNetworkFilter { get; set; }

    /// <summary>是否为文件系统过滤驱动</summary>
    public bool IsFileSystemFilter { get; set; }

    /// <summary>数字签名发行者</summary>
    public string? Company { get; set; }

    /// <summary>是否为微软签名</summary>
    public bool IsMicrosoftSigned { get; set; }

    /// <summary>检测时间</summary>
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}