namespace HookMonitor.Models;

/// <summary>
/// 进程句柄信息，用于句柄扫描分析
/// </summary>
public class ProcessHandleInfo
{
    /// <summary>拥有句柄的进程ID</summary>
    public int ProcessId { get; set; }

    /// <summary>进程名称</summary>
    public string ProcessName { get; set; } = string.Empty;

    /// <summary>句柄值</summary>
    public IntPtr HandleValue { get; set; }

    /// <summary>对象类型名称</summary>
    public string ObjectType { get; set; } = string.Empty;

    /// <summary>对象名称</summary>
    public string? ObjectName { get; set; }

    /// <summary>授予的访问权限</summary>
    public uint GrantedAccess { get; set; }

    /// <summary>是否为进程句柄（用于检测进程枚举）</summary>
    public bool IsProcessHandle => ObjectType.Equals("Process", StringComparison.OrdinalIgnoreCase);

    /// <summary>是否为GDI位图句柄（用于检测截屏）</summary>
    public bool IsBitmapHandle => ObjectType.Equals("Bitmap", StringComparison.OrdinalIgnoreCase)
        || ObjectType.Equals("DIBSection", StringComparison.OrdinalIgnoreCase);
}
