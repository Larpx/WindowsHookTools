using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using HookMonitor.Models;

namespace HookMonitor.Core.Monitoring;

/// <summary>
/// Winsock LSP (Layered Service Provider) 检测器
/// 检测系统中安装的Winsock分层服务提供者
/// 部分上网行为管理软件通过LSP拦截网络流量
/// 纯被动检测，不修改Winsock目录
/// </summary>
[SupportedOSPlatform("windows")]
public class LspDetector
{
    /// <summary>
    /// 枚举所有Winsock协议提供者
    /// </summary>
    public List<WinsockLspInfo> EnumerateLspProtocols()
    {
        var lspList = new List<WinsockLspInfo>();

        try
        {
            // 获取所需缓冲区大小
            var result = WSCEnumProtocols(
                null, IntPtr.Zero, out var bufferSize, out var errorCode);

            if (bufferSize <= 0)
                return lspList;

            var buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                result = WSCEnumProtocolsRef(
                    null, buffer, ref bufferSize, out errorCode);

                if (result != 0)
                    return lspList;

                // 解析WSAPROTOCOL_INFOW数组
                var entrySize = Marshal.SizeOf<NativeLsp.WSAPROTOCOL_INFOW>();
                var count = bufferSize / entrySize;

                for (int i = 0; i < count; i++)
                {
                    var entryPtr = IntPtr.Add(buffer, i * entrySize);
                    var protocol = Marshal.PtrToStructure<NativeLsp.WSAPROTOCOL_INFOW>(entryPtr);

                    var lspInfo = new WinsockLspInfo
                    {
                        ProtocolName = protocol.szProtocol,
                        CatalogEntryId = protocol.dwCatalogEntryId,
                        ProviderId = protocol.ProviderId,
                        SocketType = protocol.iSocketType,
                        Protocol = protocol.iProtocol,
                        AddressFamily = protocol.iAddressFamily,
                        ChainLength = protocol.ProtocolChain.ChainLen,
                        IsLayeredProvider = protocol.ProtocolChain.ChainLen > 1,
                        IsBaseProvider = protocol.ProtocolChain.ChainLen == 0,
                        ProviderPath = GetProviderPath(protocol.dwCatalogEntryId),
                        DetectedAt = DateTime.UtcNow
                    };

                    lspInfo.IsSystemProvider = IsSystemLsp(lspInfo.ProviderPath);
                    lspInfo.IsKnownBehaviorManagement = IsKnownBehaviorManagementLsp(lspInfo);

                    lspList.Add(lspInfo);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch
        {
            // LSP枚举可能因权限不足而失败
        }

        return lspList;
    }

    /// <summary>
    /// 获取非系统LSP（重点关注第三方LSP）
    /// </summary>
    public List<WinsockLspInfo> GetSuspiciousLsps()
    {
        return EnumerateLspProtocols()
            .Where(l => !l.IsSystemProvider)
            .OrderBy(l => l.ProtocolName)
            .ToList();
    }

    /// <summary>
    /// 获取LSP提供者的DLL路径
    /// </summary>
    private string? GetProviderPath(uint catalogEntryId)
    {
        try
        {
            var pathBuilder = new System.Text.StringBuilder(512);
            var pathLength = pathBuilder.Capacity;
            var result = WSCGetProviderPath(
                ref NativeLsp.gGuid, // 使用ProviderId对应的GUID
                pathBuilder,
                ref pathLength,
                out _);

            if (result == 0)
                return pathBuilder.ToString();
        }
        catch { /* 静默处理 */ }

        return null;
    }

    /// <summary>
    /// 判断是否为系统自带LSP
    /// </summary>
    private bool IsSystemLsp(string? providerPath)
    {
        if (string.IsNullOrEmpty(providerPath))
            return true;

        return providerPath.Contains("\\System32\\", StringComparison.OrdinalIgnoreCase) ||
               providerPath.Contains("\\SysWOW64\\", StringComparison.OrdinalIgnoreCase) ||
               providerPath.Contains("mswsock.dll", StringComparison.OrdinalIgnoreCase) ||
               providerPath.Contains("wshtcpip.dll", StringComparison.OrdinalIgnoreCase) ||
               providerPath.Contains("rnr20.dll", StringComparison.OrdinalIgnoreCase) ||
               providerPath.Contains("winrnr.dll", StringComparison.OrdinalIgnoreCase) ||
               providerPath.Contains("nlaapi.dll", StringComparison.OrdinalIgnoreCase) ||
               providerPath.Contains("pnrpnsp.dll", StringComparison.OrdinalIgnoreCase) ||
               providerPath.Contains("napinsp.dll", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 判断是否为已知上网行为管理软件LSP
    /// </summary>
    private bool IsKnownBehaviorManagementLsp(WinsockLspInfo lsp)
    {
        if (lsp.IsSystemProvider)
            return false;

        var knownPatterns = new[]
        {
            "Filter", "Hook", "Monitor", "Capture", "Proxy",
            "Tunnel", "Inspect", "Audit", "Control", "Guard",
            "Sangfor", "Hillstone", "NSFOCUS", "Venustech",
            "Topsec", "H3C", "Ruijie", "NetentSec", "Leadsec",
            "Websense", "Forcepoint", "BlueCoat", "Zscaler",
            "F-Secure", "Comodo", "Trend", "Symantec", "McAfee",
            "Kaspersky", "Sophos", "ESET", "Avast", "AVG",
            "360", "Tencent", "Alibaba", "Baidu", "QiAnXin",
        };

        var path = lsp.ProviderPath ?? "";

        return knownPatterns.Any(pattern =>
            lsp.ProtocolName.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
            path.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }

    #region Ws2_32.dll P/Invoke

    private static class NativeLsp
    {
        public static Guid gGuid = Guid.Empty;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WSAPROTOCOL_INFOW
        {
            public uint dwServiceFlags1;
            public uint dwServiceFlags2;
            public uint dwServiceFlags3;
            public uint dwServiceFlags4;
            public uint dwProviderFlags;
            public Guid ProviderId;
            public uint dwCatalogEntryId;
            public WSAPROTOCOLCHAIN ProtocolChain;
            public int iVersion;
            public int iAddressFamily;
            public int iMaxSockAddr;
            public int iMinSockAddr;
            public int iSocketType;
            public int iProtocol;
            public int iProtocolMaxOffset;
            public int iNetworkByteOrder;
            public int iSecurityScheme;
            public uint dwMessageSize;
            public uint dwProviderReserved;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string szProtocol;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WSAPROTOCOLCHAIN
        {
            public int ChainLen;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
            public uint[] ChainEntries;
        }
    }

    [DllImport("Ws2_32.dll", EntryPoint = "WSCEnumProtocols")]
    private static extern int WSCEnumProtocols(
        int[]? lpiProtocols,
        IntPtr lpProtocolBuffer,
        out int lpdwBufferLength,
        out int lpErrno);

    [DllImport("Ws2_32.dll", EntryPoint = "WSCEnumProtocols")]
    private static extern int WSCEnumProtocolsRef(
        int[]? lpiProtocols,
        IntPtr lpProtocolBuffer,
        ref int lpdwBufferLength,
        out int lpErrno);

    [DllImport("Ws2_32.dll", CharSet = CharSet.Unicode)]
    private static extern int WSCGetProviderPath(
        ref Guid providerId,
        [MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder lpszProviderDllPath,
        ref int lpProviderDllPathLen,
        out int lpErrno);

    #endregion
}

/// <summary>
/// Winsock LSP信息
/// </summary>
public class WinsockLspInfo
{
    /// <summary>协议名称</summary>
    public string ProtocolName { get; set; } = string.Empty;

    /// <summary>目录条目ID</summary>
    public uint CatalogEntryId { get; set; }

    /// <summary>Provider GUID</summary>
    public Guid ProviderId { get; set; }

    /// <summary>Socket类型</summary>
    public int SocketType { get; set; }

    /// <summary>协议号</summary>
    public int Protocol { get; set; }

    /// <summary>地址族</summary>
    public int AddressFamily { get; set; }

    /// <summary>协议链长度</summary>
    public int ChainLength { get; set; }

    /// <summary>是否为分层服务提供者</summary>
    public bool IsLayeredProvider { get; set; }

    /// <summary>是否为基础服务提供者</summary>
    public bool IsBaseProvider { get; set; }

    /// <summary>Provider DLL路径</summary>
    public string? ProviderPath { get; set; }

    /// <summary>是否为系统自带LSP</summary>
    public bool IsSystemProvider { get; set; }

    /// <summary>是否为已知上网行为管理软件</summary>
    public bool IsKnownBehaviorManagement { get; set; }

    /// <summary>检测时间</summary>
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}