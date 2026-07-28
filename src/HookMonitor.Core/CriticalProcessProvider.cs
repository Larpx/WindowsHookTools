namespace Larpx.PersonalTools.HookMonitor.Core;

/// <summary>
/// 系统关键进程名单提供者，用于安全过滤
/// 避免对关键进程进行注入操作，防止蓝屏和安全软件报警
/// </summary>
public static class CriticalProcessProvider
{
    /// <summary>
    /// Windows系统关键进程名单（禁止注入）
    /// </summary>
    public static readonly HashSet<string> SystemCriticalProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Windows核心子系统
        "csrss",       // 客户端/服务器运行时子系统
        "smss",        // 会话管理器子系统
        "wininit",     // Windows启动应用
        "services",    // 服务控制管理器
        "lsass",       // 本地安全认证子系统
        "winlogon",    // Windows登录应用
        "dwm",         // 桌面窗口管理器

        // 服务宿主
        "svchost",     // 服务宿主进程

        // Windows Shell
        "explorer",    // Windows资源管理器（注入可能导致桌面不稳定）

        // 运行时进程
        "taskhostw",   // 任务宿主
        "sihost",      // Shell输入宿主
        "ctfmon",      // 文本输入框架
        "dllhost",     // COM Surrogate
        "conhost",     // 控制台宿主
        "fontdrvhost", // 字体驱动宿主

        // 安全相关
        "MsMpEng",     // Windows Defender
        "NisSrv",      // 网络检测服务
        "SecurityHealthService",

        // 搜索和Cortana
        "SearchIndexer", "SearchHost", "SearchUI",

        // UWP运行时
        "RuntimeBroker",
        "ApplicationFrameHost",

        // 系统进程
        "System",
        "Registry",
        "Memory Compression"
    };

    /// <summary>
    /// 安全软件进程名单（禁止注入）
    /// </summary>
    public static readonly HashSet<string> SecuritySoftwareProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Windows Defender
        "MsMpEng", "MsSense", "NisSrv", "MpCmdRun",
        "SecurityHealthService", "SecurityHealthSystray",
        "MpDefender", "SenseIR", "SenseCncProxy",

        // 第三方安全软件
        "360safe", "360sd", "360tray", "ZhuDongFangYu",
        "Huorong", "hipstray", "wsctrl", "usysdiag",
        "KWatch", "kxescore", "kxetray",
        "QQPCTray", "QQPCRTP", "QQPCMgr",
        "avp", " kavfs", "kavfswp",
        "TmCCSF", "PccNT", "NTRtScan",
        "McAfee", "MfeAVSvc", "mfemms"
    };

    /// <summary>
    /// 已知合法的截屏/进程枚举进程（白名单，降低误报）
    /// </summary>
    public static readonly HashSet<string> KnownLegitimateProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // Windows系统工具
        "Taskmgr",         // 任务管理器
        "procexp",         // Process Explorer
        "procmon",         // Process Monitor
        "perfmon",         // 性能监视器
        "ResourceMonitor", // 资源监视器

        // 截屏工具
        "SnippingTool",    // Windows截图工具
        "ScreenClippingHost", // OneNote截图
        "ms-screenclip",   // Windows截图
        "ShareX",          // ShareX截图
        "Snipaste",        // Snipaste截图
        "Lightshot",       // Lightshot截图

        // 远程桌面
        "mstsc",           // 远程桌面连接
        "RDCMan",          // 远程桌面管理器

        // 开发工具
        "devenv",          // Visual Studio
        "code",            // VS Code
        "dotnet",          // .NET CLI

        // 游戏相关（Xbox Game Bar截屏）
        "GameBar",         // Xbox Game Bar
        "GameBarFT",       // Xbox Game Bar

        // Windows Shell
        "ShellExperienceHost",
        "StartMenuExperienceHost"
    };

    /// <summary>
    /// 检查进程是否为系统关键进程
    /// </summary>
    public static bool IsCriticalProcess(string processName)
    {
        return SystemCriticalProcesses.Contains(processName) ||
               SecuritySoftwareProcesses.Contains(processName);
    }

    /// <summary>
    /// 检查进程是否为已知合法进程
    /// </summary>
    public static bool IsKnownLegitimate(string processName)
    {
        return KnownLegitimateProcesses.Contains(processName);
    }
}
