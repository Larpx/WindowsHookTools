using System.Runtime.Versioning;
using Microsoft.Win32;
using Larpx.PersonalTools.HookMonitor.Models;

namespace Larpx.PersonalTools.HookMonitor.Core.Monitoring;

/// <summary>
/// 系统代理配置检测器
/// 检测系统级代理设置，上网行为管理软件通常会修改代理配置
/// 纯被动检测，不修改任何代理设置
/// </summary>
[SupportedOSPlatform("windows")]
public class ProxyDetector
{
    private const string InternetSettingsKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string ProxyEnableValue = "ProxyEnable";
    private const string ProxyServerValue = "ProxyServer";
    private const string ProxyOverrideValue = "ProxyOverride";
    private const string AutoConfigURLValue = "AutoConfigURL";

    /// <summary>
    /// 检测系统代理配置
    /// </summary>
    public ProxyDetectionResult DetectProxyConfiguration()
    {
        var result = new ProxyDetectionResult
        {
            DetectedAt = DateTime.UtcNow
        };

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey);
            if (key == null)
                return result;

            // 检查是否启用了代理
            var proxyEnable = key.GetValue(ProxyEnableValue);
            if (proxyEnable is int enableValue && enableValue == 1)
            {
                result.IsProxyEnabled = true;
            }

            // 获取代理服务器地址
            result.ProxyServer = key.GetValue(ProxyServerValue) as string;
            result.ProxyOverride = key.GetValue(ProxyOverrideValue) as string;

            // 检查PAC自动配置
            result.AutoConfigUrl = key.GetValue(AutoConfigURLValue) as string;

            // 分析是否为上网行为管理软件配置的代理
            if (result.IsProxyEnabled)
            {
                result.IsBehaviorManagementProxy = IsBehaviorManagementProxy(result);
                if (result.IsBehaviorManagementProxy)
                {
                    result.DetectionReason = $"检测到上网行为管理代理配置: {result.ProxyServer}";
                }
            }

            if (!string.IsNullOrEmpty(result.AutoConfigUrl))
            {
                result.IsPacEnabled = true;
                if (IsBehaviorManagementPacUrl(result.AutoConfigUrl))
                {
                    result.IsBehaviorManagementProxy = true;
                    result.DetectionReason = $"检测到上网行为管理PAC脚本: {result.AutoConfigUrl}";
                }
            }
        }
        catch
        {
            // 注册表键可能不可访问
        }

        return result;
    }

    /// <summary>
    /// 判断代理配置是否来自上网行为管理软件
    /// </summary>
    private bool IsBehaviorManagementProxy(ProxyDetectionResult result)
    {
        var proxyServer = result.ProxyServer ?? "";
        var autoConfigUrl = result.AutoConfigUrl ?? "";

        // 检查常见上网行为管理软件代理特征
        var knownPatterns = new[]
        {
            // 深信服
            "sangfor", "sinfor", "深信服",
            // 山石网科
            "hillstone", "stoneos",
            // 网康
            "netentsec", "网康",
            // 网御
            "leadsec", "网御",
            // 绿盟
            "nsfocus", "绿盟",
            // 启明星辰
            "venustech", "启明",
            // 天融信
            "topsec", "天融信",
            // H3C
            "h3c",
            // 华为
            "huawei", "secoway",
            // 锐捷
            "ruijie",
            // 360
            "360safe", "360ent",
            // 腾讯iOA
            "tencent", "ioa",
            // 阿里云盾
            "alibaba", "aliyun",
            // 奇安信
            "qianxin",
            // 通用PAC
            "proxy.pac", "wpad.dat", "autoproxy",
            // 各厂商
            "websense", "forcepoint", "bluecoat", "zscaler",
            "cisco", "umbrella", "barracuda",
            "sophos", "trendmicro", "symantec", "mcafee",
            "kaspersky", "eset", "comodo", "f-secure",
            "fortinet", "paloalto", "checkpoint",
        };

        var combined = $"{proxyServer} {autoConfigUrl}".ToLowerInvariant();
        return knownPatterns.Any(pattern => combined.Contains(pattern));
    }

    /// <summary>
    /// 判断PAC URL是否来自上网行为管理软件
    /// </summary>
    private bool IsBehaviorManagementPacUrl(string pacUrl)
    {
        var knownPacPatterns = new[]
        {
            "proxy.pac", "wpad.dat", "autoproxy",
            "sangfor", "hillstone", "nsfocus", "venustech",
            "topsec", "h3c", "ruijie", "netentsec", "leadsec",
            "websense", "forcepoint", "bluecoat", "zscaler",
            "cisco", "barracuda", "sophos", "trendmicro",
            "symantec", "mcafee", "fortinet", "paloalto",
            "checkpoint", "qianxin", "tencent", "alibaba",
        };

        var lowerUrl = pacUrl.ToLowerInvariant();
        return knownPacPatterns.Any(pattern => lowerUrl.Contains(pattern));
    }
}

/// <summary>
/// 代理检测结果
/// </summary>
public class ProxyDetectionResult
{
    /// <summary>是否启用了代理</summary>
    public bool IsProxyEnabled { get; set; }

    /// <summary>代理服务器地址</summary>
    public string? ProxyServer { get; set; }

    /// <summary>代理例外列表</summary>
    public string? ProxyOverride { get; set; }

    /// <summary>是否启用了PAC自动配置</summary>
    public bool IsPacEnabled { get; set; }

    /// <summary>PAC自动配置URL</summary>
    public string? AutoConfigUrl { get; set; }

    /// <summary>是否为上网行为管理软件配置的代理</summary>
    public bool IsBehaviorManagementProxy { get; set; }

    /// <summary>检测原因</summary>
    public string? DetectionReason { get; set; }

    /// <summary>检测时间</summary>
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}