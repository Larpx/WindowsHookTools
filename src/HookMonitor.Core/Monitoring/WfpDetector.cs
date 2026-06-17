using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using HookMonitor.Models;

namespace HookMonitor.Core.Monitoring;

/// <summary>
/// WFP (Windows Filtering Platform) 检测器
/// 枚举系统中注册的网络过滤Provider、Callout和Filter
/// 上网行为管理软件通常通过WFP注册callout驱动来实现HTTP/HTTPS流量过滤
/// 纯被动检测，不修改任何配置，不会对目标软件产生影响
/// </summary>
[SupportedOSPlatform("windows")]
public class WfpDetector
{
    // WFP API 常量
    private const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;

    /// <summary>
    /// 检测系统中所有非微软的WFP Provider
    /// </summary>
    public List<NetworkFilterInfo> DetectWfpProviders()
    {
        var providers = new List<NetworkFilterInfo>();

        try
        {
            // 打开WFP引擎（只读，不修改任何配置）
            var status = FwpmEngineOpen0(
                null,
                NativeWfp.RPC_C_AUTHN_WINNT,
                IntPtr.Zero,
                IntPtr.Zero,
                out var engineHandle);

            if (status != 0 || engineHandle == IntPtr.Zero)
                return providers;

            try
            {
                // 枚举所有Provider
                status = FwpmProviderEnum0(
                    engineHandle,
                    IntPtr.Zero,
                    out var providerArray);

                if (status == 0 && providerArray != IntPtr.Zero)
                {
                    var count = Marshal.ReadInt32(providerArray);
                    var entrySize = Marshal.SizeOf<NativeWfp.FWPM_PROVIDER0>();
                    var entryPtr = IntPtr.Add(providerArray, IntPtr.Size);

                    for (int i = 0; i < count; i++)
                    {
                        var currentPtr = IntPtr.Add(entryPtr, i * entrySize);
                        var provider = Marshal.PtrToStructure<NativeWfp.FWPM_PROVIDER0>(currentPtr);

                        // 跳过微软内置Provider
                        var providerName = Marshal.PtrToStringUni(provider.displayData.name);
                        if (string.IsNullOrEmpty(providerName))
                            providerName = provider.providerKey.ToString();

                        var isSystem = providerName.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                                       providerName.StartsWith("MS", StringComparison.OrdinalIgnoreCase) &&
                                       providerName.Contains("Windows", StringComparison.OrdinalIgnoreCase);

                        var serviceName = provider.serviceName != IntPtr.Zero
                            ? Marshal.PtrToStringUni(provider.serviceName)
                            : null;

                        var description = provider.displayData.description != IntPtr.Zero
                            ? Marshal.PtrToStringUni(provider.displayData.description)
                            : string.Empty;

                        var filterInfo = new NetworkFilterInfo
                        {
                            ProviderKey = provider.providerKey,
                            ProviderName = providerName,
                            Description = description ?? string.Empty,
                            ServiceName = serviceName,
                            Flags = provider.flags,
                            IsPersistent = (provider.flags & 0x00000001) != 0, // FWPM_PROVIDER_FLAG_PERSISTENT
                            IsSystemProvider = isSystem,
                            DetectedAt = DateTime.UtcNow
                        };

                        // 统计关联的Callout数量
                        filterInfo.CalloutCount = CountCalloutsForProvider(engineHandle, provider.providerKey);

                        // 统计关联的Filter数量
                        filterInfo.FilterCount = CountFiltersForProvider(engineHandle, provider.providerKey);

                        providers.Add(filterInfo);
                    }

                    FwpmFreeMemory0(ref providerArray);
                }
            }
            finally
            {
                FwpmEngineClose0(engineHandle);
            }
        }
        catch
        {
            // WFP API可能因权限不足而失败，静默处理
        }

        return providers;
    }

    /// <summary>
    /// 获取非微软的第三方WFP Provider（重点关注）
    /// </summary>
    public List<NetworkFilterInfo> GetThirdPartyProviders()
    {
        return DetectWfpProviders()
            .Where(p => !p.IsSystemProvider)
            .OrderByDescending(p => p.FilterCount)
            .ToList();
    }

    /// <summary>
    /// 统计指定Provider的Callout数量
    /// </summary>
    private int CountCalloutsForProvider(IntPtr engineHandle, Guid providerKey)
    {
        try
        {
            var enumTemplate = new NativeWfp.FWPM_CALLOUT_ENUM_TEMPLATE0
            {
                providerKey = providerKey
            };

            var templatePtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeWfp.FWPM_CALLOUT_ENUM_TEMPLATE0>());
            try
            {
                Marshal.StructureToPtr(enumTemplate, templatePtr, false);
                var status = FwpmCalloutEnum0(engineHandle, templatePtr, out var calloutArray);
                if (status == 0 && calloutArray != IntPtr.Zero)
                {
                    var count = Marshal.ReadInt32(calloutArray);
                    FwpmFreeMemory0(ref calloutArray);
                    return count;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(templatePtr);
            }
        }
        catch { /* 静默处理 */ }

        return 0;
    }

    /// <summary>
    /// 统计指定Provider的Filter数量
    /// </summary>
    private int CountFiltersForProvider(IntPtr engineHandle, Guid providerKey)
    {
        try
        {
            var enumTemplate = new NativeWfp.FWPM_FILTER_ENUM_TEMPLATE0
            {
                providerKey = providerKey
            };

            var templatePtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeWfp.FWPM_FILTER_ENUM_TEMPLATE0>());
            try
            {
                Marshal.StructureToPtr(enumTemplate, templatePtr, false);
                var status = FwpmFilterEnum0(engineHandle, templatePtr, out var filterArray);
                if (status == 0 && filterArray != IntPtr.Zero)
                {
                    var count = Marshal.ReadInt32(filterArray);
                    FwpmFreeMemory0(ref filterArray);
                    return count;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(templatePtr);
            }
        }
        catch { /* 静默处理 */ }

        return 0;
    }

    /// <summary>
    /// 检测已知的上网行为管理软件特征
    /// </summary>
    public bool IsKnownBehaviorManagementSoftware(NetworkFilterInfo provider)
    {
        // 常见上网行为管理软件的Provider名称特征
        var knownPatterns = new[]
        {
            "Sangfor",     // 深信服
            "Hillstone",   // 山石网科
            "NSFOCUS",     // 绿盟
            "Venustech",   // 启明星辰
            "Topsec",      // 天融信
            "H3C",         // 新华三
            "Ruijie",      // 锐捷
            "NetentSec",   // 网康
            "Leadsec",     // 网御
            "DBAPPSec",    // 安恒
            "QiAnXin",     // 奇安信
            "360",         // 360
            "TrendMicro",  // 趋势科技
            "Symantec",    // 赛门铁克
            "McAfee",      // 迈克菲
            "Kaspersky",   // 卡巴斯基
            "Websense",    // Websense
            "Forcepoint",  // Forcepoint
            "BlueCoat",    // Blue Coat
            "Zscaler",     // Zscaler
            "Palo Alto",   // Palo Alto Networks
            "CheckPoint",  // Check Point
            "Fortinet",    // Fortinet
            "Cisco",       // Cisco Umbrella
            "Barracuda",   // Barracuda
            "Sophos",      // Sophos
            "ESET",        // ESET
            "Bitdefender", // Bitdefender
            "Comodo",      // Comodo
            "F-Secure",    // F-Secure
            "Avast",       // Avast
            "AVG",         // AVG
            "Tencent",     // 腾讯iOA
            "Alibaba",     // 阿里云盾
            "Baidu",       // 百度
            "ByteDance",   // 字节跳动
            "NetEase",     // 网易
            "Kingsoft",    // 金山
            "Jiangmin",    // 江民
            "Rising",      // 瑞星
            "Micropoint",  // 微点
            "Malware",     // 恶意软件通用
            "Filter",      // 通用过滤器
            "NetFilter",   // 网络过滤器
            "Firewall",    // 防火墙
            "Proxy",       // 代理
            "Monitor",     // 监控
            "Capture",     // 抓包
            "Inspect",     // 检测
            "Audit",       // 审计
        };

        var name = provider.ProviderName;
        var desc = provider.Description;
        var svc = provider.ServiceName ?? "";

        return knownPatterns.Any(pattern =>
            name.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
            desc.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
            svc.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }

    #region Fwpmu.dll P/Invoke

    private static class NativeWfp
    {
        public const uint RPC_C_AUTHN_WINNT = 10;

        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_PROVIDER0
        {
            public Guid providerKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public IntPtr providerData; // FWP_BYTE_BLOB*
            public IntPtr serviceName;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct FWPM_DISPLAY_DATA0
        {
            public IntPtr name;
            public IntPtr description;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_CALLOUT_ENUM_TEMPLATE0
        {
            public Guid providerKey;
            public Guid layerKey;
            public uint flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_FILTER_ENUM_TEMPLATE0
        {
            public Guid providerKey;
            public Guid layerKey;
            public uint flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_CALLOUT0
        {
            public Guid calloutKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public Guid providerKey;
            public IntPtr providerData;
            public Guid applicableLayer;
            public uint calloutId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_FILTER0
        {
            public Guid filterKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public Guid providerKey;
            public IntPtr providerData;
            public Guid layerKey;
            public Guid subLayerKey;
            public FWPM_FILTER_CONDITION0 filterCondition;
            public uint actionType;
            public uint filterId;
            public ulong weight;
            public IntPtr rawContext;
            public Guid reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_FILTER_CONDITION0
        {
            public uint fieldKey;
            public uint matchType;
            public uint conditionValueType;
            public IntPtr conditionValue;
        }
    }

    [DllImport("Fwpuclnt.dll", EntryPoint = "FwpmEngineOpen0")]
    private static extern uint FwpmEngineOpen0(
        [MarshalAs(UnmanagedType.LPWStr)] string? serverName,
        uint authnService,
        IntPtr authIdentity,
        IntPtr session,
        out IntPtr engineHandle);

    [DllImport("Fwpuclnt.dll", EntryPoint = "FwpmEngineClose0")]
    private static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("Fwpuclnt.dll", EntryPoint = "FwpmProviderEnum0")]
    private static extern uint FwpmProviderEnum0(
        IntPtr engineHandle,
        IntPtr enumTemplate,
        out IntPtr entries);

    [DllImport("Fwpuclnt.dll", EntryPoint = "FwpmCalloutEnum0")]
    private static extern uint FwpmCalloutEnum0(
        IntPtr engineHandle,
        IntPtr enumTemplate,
        out IntPtr entries);

    [DllImport("Fwpuclnt.dll", EntryPoint = "FwpmFilterEnum0")]
    private static extern uint FwpmFilterEnum0(
        IntPtr engineHandle,
        IntPtr enumTemplate,
        out IntPtr entries);

    [DllImport("Fwpuclnt.dll", EntryPoint = "FwpmFreeMemory0")]
    private static extern void FwpmFreeMemory0(ref IntPtr p);

    #endregion
}