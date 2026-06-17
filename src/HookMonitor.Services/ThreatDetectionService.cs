using System.Collections.Concurrent;
using HookMonitor.Core;
using HookMonitor.Core.Monitoring;
using HookMonitor.Models;
using Microsoft.Extensions.Logging;

namespace HookMonitor.Services;

/// <summary>
/// 威胁检测服务，分析进程行为并识别可疑活动
/// </summary>
public class ThreatDetectionService
{
    private readonly ILogger<ThreatDetectionService> _logger;
    private readonly MonitorConfig _config;

    /// <summary>
    /// 进程API调用频率跟踪（进程ID -> API类别 -> 调用记录列表）
    /// </summary>
    private readonly ConcurrentDictionary<int, ConcurrentDictionary<ApiCategory, List<DateTime>>> _callFrequency = [];

    /// <summary>
    /// 已识别的可疑进程缓存
    /// </summary>
    private readonly ConcurrentDictionary<int, SuspiciousProcessInfo> _suspiciousProcesses = [];

    /// <summary>
    /// 初始化威胁检测服务
    /// </summary>
    public ThreatDetectionService(ILogger<ThreatDetectionService> logger, MonitorConfig? config = null)
    {
        _logger = logger;
        _config = config ?? new MonitorConfig();
    }

    /// <summary>
    /// 获取当前所有可疑进程
    /// </summary>
    public List<SuspiciousProcessInfo> GetSuspiciousProcesses()
    {
        return _suspiciousProcesses.Values
            .OrderByDescending(p => p.ThreatScore)
            .ToList();
    }

    /// <summary>
    /// 分析API调用记录，更新威胁评估
    /// </summary>
    public void AnalyzeApiCalls(List<ApiCallRecord> calls)
    {
        var cutoffTime = DateTime.UtcNow.AddMinutes(-1);

        foreach (var call in calls)
        {
            // 更新调用频率跟踪
            var processCalls = _callFrequency.GetOrAdd(call.ProcessId, _ => []);
            var categoryCalls = processCalls.GetOrAdd(call.Category, _ => []);
            lock (categoryCalls)
            {
                categoryCalls.Add(call.Timestamp);
                // 只保留最近1分钟的记录
                categoryCalls.RemoveAll(t => t < cutoffTime);
            }
        }
    }

    /// <summary>
    /// 分析句柄扫描结果，检测可疑行为
    /// </summary>
    public void AnalyzeHandleResults(Dictionary<int, HandleAnalysisResult> handleResults)
    {
        foreach (var (processId, result) in handleResults)
        {
            if (!result.IsSuspiciousProcessEnum && !result.IsSuspiciousScreenCapture)
                continue;

            var existing = _suspiciousProcesses.GetValueOrDefault(processId);
            if (existing != null)
            {
                // 更新现有记录
                foreach (var reason in result.SuspicionReasons)
                {
                    if (!existing.DetectionReasons.Contains(reason))
                        existing.DetectionReasons.Add(reason);
                }
                existing.LastDetected = DateTime.UtcNow;
                UpdateThreatScore(existing);
            }
        }
    }

    /// <summary>
    /// 计算进程的威胁评分和等级
    /// </summary>
    public void UpdateThreatScore(SuspiciousProcessInfo process)
    {
        var score = 0;

        // 基于API调用频率评分
        if (_callFrequency.TryGetValue(process.ProcessId, out var categoryCalls))
        {
            foreach (var (category, calls) in categoryCalls)
            {
                var frequency = calls.Count; // 每分钟调用次数
                switch (category)
                {
                    case ApiCategory.ProcessEnumeration:
                        if (frequency > _config.ProcessEnumFrequencyThreshold)
                            score += Math.Min(40, frequency * 3);
                        else if (frequency > _config.ProcessEnumFrequencyThreshold / 2)
                            score += 15;
                        break;

                    case ApiCategory.ScreenCapture:
                        if (frequency > _config.ScreenCaptureFrequencyThreshold)
                            score += Math.Min(50, frequency * 5);
                        else if (frequency > _config.ScreenCaptureFrequencyThreshold / 2)
                            score += 20;
                        break;

                    case ApiCategory.KeyLogging:
                        score += 60; // 键盘记录直接高分
                        break;

                    case ApiCategory.ClipboardAccess:
                        if (frequency > 10)
                            score += 25;
                        break;
                }
            }
        }

        // 基于检测原因评分
        foreach (var reason in process.DetectionReasons)
        {
            if (reason.Contains("进程句柄"))
                score += 10;
            if (reason.Contains("位图句柄"))
                score += 15;
            if (reason.Contains("查询+读取权限"))
                score += 10;
        }

        // 基于进程特征评分
        if (process.IsService && !process.IsSystemCritical)
            score += 5; // 非系统服务做这些事更可疑
        if (string.IsNullOrEmpty(process.FilePath))
            score += 10; // 无法获取路径更可疑
        if (string.IsNullOrEmpty(process.Company))
            score += 5; // 无数字签名信息

        // 已知合法进程降低评分
        if (CriticalProcessProvider.IsKnownLegitimate(process.ProcessName))
            score = Math.Max(0, score - 30);

        // 限制评分范围
        process.ThreatScore = Math.Clamp(score, 0, 100);
        process.ThreatLevel = process.ThreatScore switch
        {
            >= 80 => ThreatLevel.Critical,
            >= 60 => ThreatLevel.High,
            >= 40 => ThreatLevel.Medium,
            >= 20 => ThreatLevel.Low,
            _ => ThreatLevel.None
        };

        // 更新调用频率
        if (_callFrequency.TryGetValue(process.ProcessId, out var frequencyMap))
        {
            var totalCalls = frequencyMap.Values.Sum(c => c.Count);
            process.CallFrequency = totalCalls;
        }
    }

    /// <summary>
    /// 添加或更新可疑进程
    /// </summary>
    public void AddOrUpdateSuspiciousProcess(SuspiciousProcessInfo process)
    {
        _suspiciousProcesses.AddOrUpdate(
            process.ProcessId,
            process,
            (_, existing) =>
            {
                existing.LastDetected = DateTime.UtcNow;
                existing.ThreatScore = Math.Max(existing.ThreatScore, process.ThreatScore);
                existing.ThreatLevel = (ThreatLevel)Math.Max((int)existing.ThreatLevel, (int)process.ThreatLevel);
                foreach (var reason in process.DetectionReasons)
                {
                    if (!existing.DetectionReasons.Contains(reason))
                        existing.DetectionReasons.Add(reason);
                }
                foreach (var call in process.ApiCalls)
                {
                    existing.ApiCalls.Add(call);
                }
                return existing;
            });
    }

    /// <summary>
    /// 分析DNS查询记录，检测DNS劫持/重定向
    /// </summary>
    public void AnalyzeDnsQueries(List<DnsQueryRecord> records)
    {
        var suspiciousRecords = records
            .Where(r => r.IsSuspicious)
            .ToList();

        if (suspiciousRecords.Count == 0)
            return;

        // 按进程分组统计
        var processGroups = suspiciousRecords
            .GroupBy(r => r.ProcessId)
            .Where(g => g.Key > 0);

        foreach (var group in processGroups)
        {
            var processId = group.Key;
            var dnsQueries = group.ToList();
            var processName = dnsQueries.First().ProcessName;

            // 获取或创建可疑进程记录
            var suspicious = _suspiciousProcesses.GetOrAdd(processId, _ =>
            {
                var info = new SuspiciousProcessInfo
                {
                    ProcessId = processId,
                    ProcessName = processName,
                    FirstDetected = DateTime.UtcNow
                };
                return info;
            });

            suspicious.LastDetected = DateTime.UtcNow;

            // 添加DNS相关的API调用记录
            foreach (var query in dnsQueries)
            {
                suspicious.ApiCalls.Add(new ApiCallRecord
                {
                    ProcessId = processId,
                    ProcessName = processName,
                    Category = ApiCategory.DnsInterception,
                    ApiName = "DNS Query",
                    Timestamp = query.Timestamp,
                    Source = DetectionSource.DnsMonitor,
                    Detail = $"域名: {query.QueryName} → DNS服务器: {query.DnsServer} ({query.SuspicionReason})"
                });
            }

            // 添加检测原因
            var reason = $"DNS查询异常: {dnsQueries.Count}次查询被重定向到非标准DNS服务器";
            if (!suspicious.DetectionReasons.Contains(reason))
                suspicious.DetectionReasons.Add(reason);

            // 提高威胁评分
            suspicious.ThreatScore = Math.Min(suspicious.ThreatScore + dnsQueries.Count * 2, 100);
            suspicious.ThreatLevel = suspicious.ThreatScore switch
            {
                >= 80 => ThreatLevel.Critical,
                >= 60 => ThreatLevel.High,
                >= 40 => ThreatLevel.Medium,
                >= 20 => ThreatLevel.Low,
                _ => ThreatLevel.None
            };

            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning("DNS劫持检测: PID={ProcessId} 进程={ProcessName} 异常查询数={Count}",
                    processId, processName, dnsQueries.Count);
            }
        }

        // 限制API调用记录数
        foreach (var (pid, process) in _suspiciousProcesses)
        {
            if (process.ApiCalls.Count > _config.MaxApiCallRecords)
            {
                process.ApiCalls = process.ApiCalls
                    .OrderByDescending(c => c.Timestamp)
                    .Take(_config.MaxApiCallRecords / 2)
                    .ToList();
            }
        }
    }

    /// <summary>
    /// 分析网络连接记录，检测代理转发和流量劫持
    /// </summary>
    public void AnalyzeNetworkConnections(List<NetworkConnectionRecord> records)
    {
        var suspiciousRecords = records
            .Where(r => r.IsSuspiciousProxy)
            .ToList();

        if (suspiciousRecords.Count == 0)
            return;

        // 按进程分组统计
        var processGroups = suspiciousRecords
            .GroupBy(r => r.ProcessId)
            .Where(g => g.Key > 0);

        foreach (var group in processGroups)
        {
            var processId = group.Key;
            var connections = group.ToList();
            var processName = connections.First().ProcessName;

            var suspicious = _suspiciousProcesses.GetOrAdd(processId, _ =>
            {
                var info = new SuspiciousProcessInfo
                {
                    ProcessId = processId,
                    ProcessName = processName,
                    FirstDetected = DateTime.UtcNow
                };
                return info;
            });

            suspicious.LastDetected = DateTime.UtcNow;

            // 添加网络连接相关的API调用记录
            foreach (var conn in connections)
            {
                suspicious.ApiCalls.Add(new ApiCallRecord
                {
                    ProcessId = processId,
                    ProcessName = processName,
                    Category = ApiCategory.NetworkConnection,
                    ApiName = conn.Protocol == "TCP" ? "TCP Connect" : "TCP Accept",
                    Timestamp = conn.Timestamp,
                    Source = DetectionSource.NetworkMonitor,
                    Detail = $"{conn.RemoteAddress}:{conn.RemotePort} ({conn.SuspicionReason})"
                });
            }

            // 添加检测原因
            var reason = $"网络连接异常: {connections.Count}次可疑代理连接 (端口: {string.Join(", ", connections.Select(c => c.RemotePort).Distinct().Take(5))})";
            if (!suspicious.DetectionReasons.Contains(reason))
                suspicious.DetectionReasons.Add(reason);

            // 提高威胁评分
            suspicious.ThreatScore = Math.Min(suspicious.ThreatScore + connections.Count * 3, 100);
            suspicious.ThreatLevel = suspicious.ThreatScore switch
            {
                >= 80 => ThreatLevel.Critical,
                >= 60 => ThreatLevel.High,
                >= 40 => ThreatLevel.Medium,
                >= 20 => ThreatLevel.Low,
                _ => ThreatLevel.None
            };

            if (_logger.IsEnabled(LogLevel.Warning))
            {
                _logger.LogWarning("网络代理检测: PID={ProcessId} 进程={ProcessName} 可疑连接数={Count}",
                    processId, processName, connections.Count);
            }
        }
    }

    /// <summary>
    /// 移除已不存在的可疑进程</summary>
    public void RemoveStaleProcesses(HashSet<int> activeProcessIds)
    {
        foreach (var pid in _suspiciousProcesses.Keys)
        {
            if (!activeProcessIds.Contains(pid))
            {
                _suspiciousProcesses.TryRemove(pid, out _);
                _callFrequency.TryRemove(pid, out _);
            }
        }
    }

    /// <summary>
    /// 清空所有检测数据
    /// </summary>
    public void Clear()
    {
        _suspiciousProcesses.Clear();
        _callFrequency.Clear();
    }
}
