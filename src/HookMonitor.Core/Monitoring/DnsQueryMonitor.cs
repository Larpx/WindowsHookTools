using System.Collections.Concurrent;
using System.Runtime.Versioning;
using HookMonitor.Models;

namespace HookMonitor.Core.Monitoring;

/// <summary>
/// DNS查询事件监控器，通过ETW (Microsoft-Windows-DNS-Client) 监控DNS查询
/// 检测上网行为管理软件通过DNS劫持/重定向实现域名过滤
/// 纯被动监听ETW事件，完全不干预DNS解析过程
/// </summary>
[SupportedOSPlatform("windows")]
public class DnsQueryMonitor : IDisposable
{
    private readonly ConcurrentQueue<DnsQueryRecord> _queryRecords = new();
    private CancellationTokenSource? _cts;
    private Task? _monitorTask;
    private bool _isRunning;

    // Microsoft-Windows-DNS-Client
    private static readonly Guid DnsClientProviderGuid = new("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}");

    /// <summary>DNS查询记录缓存</summary>
    public ConcurrentQueue<DnsQueryRecord> QueryRecords => _queryRecords;

    /// <summary>是否正在运行</summary>
    public bool IsRunning => _isRunning;

    /// <summary>
    /// 启动DNS查询监控
    /// </summary>
    public bool Start()
    {
        if (_isRunning) return true;

        try
        {
            _cts = new CancellationTokenSource();
            _monitorTask = Task.Run(() => MonitorDnsQueries(_cts.Token), _cts.Token);
            _isRunning = true;
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 停止DNS查询监控
    /// </summary>
    public void Stop()
    {
        if (!_isRunning) return;
        _cts?.Cancel();
        _monitorTask?.Wait(TimeSpan.FromSeconds(5));
        _isRunning = false;
    }

    /// <summary>
    /// 获取并清空DNS查询记录
    /// </summary>
    public List<DnsQueryRecord> DrainQueryRecords()
    {
        var records = new List<DnsQueryRecord>();
        while (_queryRecords.TryDequeue(out var record))
        {
            records.Add(record);
        }
        return records;
    }

    /// <summary>
    /// 检测DNS查询是否被劫持到异常服务器
    /// </summary>
    public bool IsDnsHijacked(DnsQueryRecord record)
    {
        if (string.IsNullOrEmpty(record.DnsServer))
            return false;

        // 已知的公共DNS服务器
        var knownDnsServers = new HashSet<string>
        {
            "8.8.8.8", "8.8.4.4",       // Google DNS
            "1.1.1.1", "1.0.0.1",       // Cloudflare
            "9.9.9.9", "149.112.112.112", // Quad9
            "208.67.222.222", "208.67.220.220", // OpenDNS
            "114.114.114.114", "114.114.115.115", // 114DNS (中国)
            "223.5.5.5", "223.6.6.6",   // 阿里DNS
            "180.76.76.76",              // 百度DNS
            "119.29.29.29",              // 腾讯DNSPod
        };

        // 如果DNS服务器不是已知公共DNS，且不是本地地址，可能是被劫持
        if (!knownDnsServers.Contains(record.DnsServer))
        {
            // 检查是否为本地/私有地址
            if (!IsLocalOrPrivateAddress(record.DnsServer))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// 检查是否为本地或私有地址
    /// </summary>
    private bool IsLocalOrPrivateAddress(string address)
    {
        if (address == "127.0.0.1" || address == "::1")
            return true;

        if (System.Net.IPAddress.TryParse(address, out var ip))
        {
            var bytes = ip.GetAddressBytes();
            // 10.0.0.0/8
            if (bytes[0] == 10) return true;
            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            // 169.254.0.0/16 (APIPA)
            if (bytes[0] == 169 && bytes[1] == 254) return true;
        }

        return false;
    }

    /// <summary>
    /// DNS查询监控主循环
    /// </summary>
    private void MonitorDnsQueries(CancellationToken cancellationToken)
    {
        try
        {
            using var session = new Microsoft.Diagnostics.Tracing.Session.TraceEventSession(
                "HookMonitor-DnsSession", null);

            // 启用DNS客户端Provider
            session.EnableProvider(DnsClientProviderGuid,
                Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational,
                0x0000000000000001); // DNS_EVENT_KEYWORD_DNS_CLIENT

            session.Source.Dynamic.All += traceEvent =>
            {
                if (cancellationToken.IsCancellationRequested)
                    return;

                try
                {
                    var record = new DnsQueryRecord
                    {
                        Timestamp = DateTime.UtcNow,
                        QueryName = (string?)traceEvent.PayloadByName("QueryName") ?? "",
                        QueryType = (string?)traceEvent.PayloadByName("QueryType") ?? "",
                        QueryResult = (string?)traceEvent.PayloadByName("QueryResults") ?? "",
                        Status = (uint)(traceEvent.PayloadByName("Status") ?? 0u),
                        DnsServer = (string?)traceEvent.PayloadByName("DnsServer") ?? ""
                    };

                    // 尝试获取进程信息
                    var processId = (int)(traceEvent.PayloadByName("ProcessId") ?? 0);
                    record.ProcessId = processId;

                    if (processId > 0)
                    {
                        try
                        {
                            using var process = System.Diagnostics.Process.GetProcessById(processId);
                            record.ProcessName = process.ProcessName;
                        }
                        catch { /* 进程可能已退出 */ }
                    }

                    // 检测可疑DNS行为
                    record.IsSuspicious = IsDnsHijacked(record);
                    if (record.IsSuspicious)
                    {
                        record.SuspicionReason = $"DNS查询被重定向到非标准服务器: {record.DnsServer}";
                    }

                    _queryRecords.Enqueue(record);
                }
                catch { /* 静默处理事件解析错误 */ }
            };

            var processingTask = Task.Run(() =>
            {
                try
                {
                    session.Source.Process();
                }
                catch (OperationCanceledException) { }
                catch { }
            }, cancellationToken);

            cancellationToken.WaitHandle.WaitOne();
            session.Stop();
        }
        catch
        {
            // DNS监控可能因权限不足而失败
        }
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
        GC.SuppressFinalize(this);
    }
}