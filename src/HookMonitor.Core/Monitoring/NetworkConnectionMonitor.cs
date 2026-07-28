using System.Collections.Concurrent;
using System.Runtime.Versioning;
using Larpx.PersonalTools.HookMonitor.Models;

namespace Larpx.PersonalTools.HookMonitor.Core.Monitoring;

/// <summary>
/// TCP/UDP网络连接监控器，通过ETW (Microsoft-Windows-TCPIP) 监控网络连接
/// 检测上网行为管理软件的代理转发和流量劫持行为
/// 纯被动监听ETW事件，不干预网络连接
/// </summary>
[SupportedOSPlatform("windows")]
public class NetworkConnectionMonitor : IDisposable
{
    private readonly ConcurrentQueue<NetworkConnectionRecord> _connectionRecords = new();
    private CancellationTokenSource? _cts;
    private Task? _monitorTask;
    private bool _isRunning;

    // Microsoft-Windows-TCPIP Provider
    private static readonly Guid TcpIpProviderGuid = new("{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}");

    // 常见代理/上网行为管理端口
    private static readonly HashSet<int> KnownProxyPorts = new()
    {
        8080, 3128, 1080, 8888, 9999,  // HTTP代理
        1080, 9150,                      // SOCKS代理
        8118,                            // Privoxy
        8000, 8001, 8443,               // 常见企业代理
        6666, 9999,                      // 常见恶意代理
    };

    // 已知上网行为管理软件通信端口特征
    private static readonly HashSet<int> KnownFilterPorts = new()
    {
        8000, 8001, 8002, 8003,  // 深信服
        8443, 9443,              // 各种安全网关
        443, 80,                 // 标准Web
        5000, 5001,              // 常见管理端口
        6000, 7000, 9000,        // 常见内部端口
    };

    /// <summary>网络连接记录缓存</summary>
    public ConcurrentQueue<NetworkConnectionRecord> ConnectionRecords => _connectionRecords;

    /// <summary>是否正在运行</summary>
    public bool IsRunning => _isRunning;

    /// <summary>
    /// 启动网络连接监控
    /// </summary>
    public bool Start()
    {
        if (_isRunning) return true;

        try
        {
            _cts = new CancellationTokenSource();
            _monitorTask = Task.Run(() => MonitorNetworkConnections(_cts.Token), _cts.Token);
            _isRunning = true;
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 停止网络连接监控
    /// </summary>
    public void Stop()
    {
        if (!_isRunning) return;
        _cts?.Cancel();
        _monitorTask?.Wait(TimeSpan.FromSeconds(5));
        _isRunning = false;
    }

    /// <summary>
    /// 获取并清空连接记录
    /// </summary>
    public List<NetworkConnectionRecord> DrainConnectionRecords()
    {
        var records = new List<NetworkConnectionRecord>();
        while (_connectionRecords.TryDequeue(out var record))
        {
            records.Add(record);
        }
        return records;
    }

    /// <summary>
    /// 检测可疑代理连接
    /// </summary>
    public bool IsSuspiciousProxyConnection(NetworkConnectionRecord record)
    {
        // 检查目标端口是否为已知代理端口
        if (KnownProxyPorts.Contains(record.RemotePort))
            return true;

        // 检查是否连接到本地环回地址的异常端口（本地代理）
        if (IsLocalAddress(record.RemoteAddress) &&
            KnownFilterPorts.Contains(record.RemotePort))
            return true;

        return false;
    }

    /// <summary>
    /// 检查是否为本地地址
    /// </summary>
    private static bool IsLocalAddress(string address)
    {
        return address == "127.0.0.1" || address == "::1" || address == "0.0.0.0";
    }

    /// <summary>
    /// 网络连接监控主循环
    /// </summary>
    private void MonitorNetworkConnections(CancellationToken cancellationToken)
    {
        try
        {
            using var session = new Microsoft.Diagnostics.Tracing.Session.TraceEventSession(
                "HookMonitor-NetworkSession", null);

            // 启用TCP/IP内核Provider
            session.EnableKernelProvider(
                Microsoft.Diagnostics.Tracing.Parsers.KernelTraceEventParser.Keywords.NetworkTCPIP);

            // 注册TCP连接事件
            session.Source.Kernel.TcpIpConnect += tcpData =>
            {
                if (cancellationToken.IsCancellationRequested) return;

                try
                {
                    var record = new NetworkConnectionRecord
                    {
                        ProcessId = tcpData.ProcessID,
                        ProcessName = tcpData.ProcessName ?? $"PID:{tcpData.ProcessID}",
                        Protocol = "TCP",
                        LocalAddress = tcpData.saddr?.ToString() ?? "",
                        LocalPort = tcpData.sport,
                        RemoteAddress = tcpData.daddr?.ToString() ?? "",
                        RemotePort = tcpData.dport,
                        ConnectionState = "Connect",
                        Timestamp = DateTime.UtcNow
                    };

                    record.IsSuspiciousProxy = IsSuspiciousProxyConnection(record);
                    if (record.IsSuspiciousProxy)
                    {
                        record.SuspicionReason = $"连接到可疑代理端口 {record.RemotePort}";
                    }

                    _connectionRecords.Enqueue(record);
                }
                catch { /* 静默处理 */ }
            };

            session.Source.Kernel.TcpIpAccept += tcpData =>
            {
                if (cancellationToken.IsCancellationRequested) return;

                try
                {
                    var record = new NetworkConnectionRecord
                    {
                        ProcessId = tcpData.ProcessID,
                        ProcessName = tcpData.ProcessName ?? $"PID:{tcpData.ProcessID}",
                        Protocol = "TCP",
                        LocalAddress = tcpData.saddr?.ToString() ?? "",
                        LocalPort = tcpData.sport,
                        RemoteAddress = tcpData.daddr?.ToString() ?? "",
                        RemotePort = tcpData.dport,
                        ConnectionState = "Accept",
                        Timestamp = DateTime.UtcNow
                    };

                    // 本地监听端口可能是代理服务
                    if (KnownProxyPorts.Contains(record.LocalPort))
                    {
                        record.IsSuspiciousProxy = true;
                        record.SuspicionReason = $"在已知代理端口 {record.LocalPort} 上监听";
                    }

                    _connectionRecords.Enqueue(record);
                }
                catch { /* 静默处理 */ }
            };

            // 启用TCP/IP Provider获取更详细的事件
            session.EnableProvider(TcpIpProviderGuid,
                Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational);

            session.Source.Dynamic.All += traceEvent =>
            {
                if (cancellationToken.IsCancellationRequested) return;

                try
                {
                    // 处理TCP重传/重置事件（可能是流量劫持的迹象）
                    var eventName = traceEvent.EventName ?? "";
                    if (eventName.Contains("RST", StringComparison.OrdinalIgnoreCase) ||
                        eventName.Contains("Reset", StringComparison.OrdinalIgnoreCase))
                    {
                        var record = new NetworkConnectionRecord
                        {
                            ProcessId = (int)(traceEvent.PayloadByName("PID") ?? 0),
                            ProcessName = $"TCP Event: {eventName}",
                            Protocol = "TCP",
                            ConnectionState = "Reset",
                            Timestamp = DateTime.UtcNow,
                            IsSuspiciousProxy = true,
                            SuspicionReason = $"检测到TCP RST事件（可能的流量劫持）: {eventName}"
                        };
                        _connectionRecords.Enqueue(record);
                    }
                }
                catch { /* 静默处理 */ }
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
            // 网络监控可能因权限不足而失败
        }
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
        GC.SuppressFinalize(this);
    }
}