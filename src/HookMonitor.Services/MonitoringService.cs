using System.Collections.Concurrent;
using Larpx.PersonalTools.HookMonitor.Core;
using Larpx.PersonalTools.HookMonitor.Core.Hooking;
using Larpx.PersonalTools.HookMonitor.Core.Monitoring;
using Larpx.PersonalTools.HookMonitor.Models;
using Microsoft.Extensions.Logging;

namespace Larpx.PersonalTools.HookMonitor.Services;

/// <summary>
/// 监控管理服务，协调各监控组件的运行
/// 包含内核视角的检测手段：WFP、DNS、网络连接、LSP、DLL注入、代理、驱动检测
/// 所有检测均为纯被动读取，不修改任何系统配置，不对目标软件产生影响
/// </summary>
public class MonitoringService : IDisposable
{
    private readonly ILogger<MonitoringService> _logger;
    private readonly ProcessInfoService _processInfoService;
    private readonly ThreatDetectionService _threatDetectionService;
    private readonly MonitorConfig _config;

    // 原有监控组件
    private readonly HandleMonitor _handleMonitor;
    private readonly EtwMonitor _etwMonitor;
    private readonly HookPipeServer? _hookPipeServer;

    // 内核视角检测组件
    private readonly WfpDetector _wfpDetector;
    private readonly DnsQueryMonitor _dnsMonitor;
    private readonly NetworkConnectionMonitor _networkMonitor;
    private readonly LspDetector _lspDetector;
    private readonly InjectDetector _injectDetector;
    private readonly ProxyDetector _proxyDetector;

    private CancellationTokenSource? _cts;
    private Task? _monitoringTask;
    private readonly object _lock = new();

    // 内核检测结果缓存（避免每次循环都重新扫描）
    private List<NetworkFilterInfo>? _cachedWfpProviders;
    private List<WinsockLspInfo>? _cachedLsps;
    private List<InjectDetectionInfo>? _cachedInjections;
    private List<KernelDriverInfo>? _cachedDrivers;
    private ProxyDetectionResult? _cachedProxyResult;
    private DateTime _lastKernelScanTime = DateTime.MinValue;

    /// <summary>
    /// 当前监控状态
    /// </summary>
    public MonitoringStatus Status { get; private set; } = new();

    /// <summary>
    /// 可疑进程变更通知事件
    /// </summary>
    public event EventHandler<List<SuspiciousProcessInfo>>? SuspiciousProcessesUpdated;

    /// <summary>
    /// 内核检测结果更新事件（WFP、LSP、驱动、注入、代理等）
    /// </summary>
    public event EventHandler<KernelDetectionResult>? KernelDetectionUpdated;

    /// <summary>
    /// 初始化监控管理服务
    /// </summary>
    public MonitoringService(
        ILogger<MonitoringService> logger,
        ProcessInfoService processInfoService,
        ThreatDetectionService threatDetectionService,
        MonitorConfig? config = null)
    {
        _logger = logger;
        _processInfoService = processInfoService;
        _threatDetectionService = threatDetectionService;
        _config = config ?? new MonitorConfig();
        _handleMonitor = new HandleMonitor();
        _etwMonitor = new EtwMonitor();

        // 初始化内核视角检测组件
        _wfpDetector = new WfpDetector();
        _dnsMonitor = new DnsQueryMonitor();
        _networkMonitor = new NetworkConnectionMonitor();
        _lspDetector = new LspDetector();
        _injectDetector = new InjectDetector();
        _proxyDetector = new ProxyDetector();

        // 初始化IAT Hook管道服务端
        if (_config.EnableIatHook)
        {
            _hookPipeServer = new HookPipeServer();
            _hookPipeServer.ApiCallReceived += OnHookPipeApiCallReceived;
        }
    }

    /// <summary>
    /// 启动监控
    /// </summary>
    public bool Start()
    {
        lock (_lock)
        {
            if (Status.IsRunning)
                return true;

            try
            {
                _cts = new CancellationTokenSource();

                // 启动ETW监控
                if (_config.EnableEtw)
                {
                    var etwStarted = _etwMonitor.Start();
                    Status.IsEtwActive = etwStarted;
                    if (!etwStarted)
                        _logger.LogWarning("ETW监控启动失败，可能需要管理员权限");
                }

                // 启动DNS查询监控
                if (_config.EnableDnsMonitor)
                {
                    var dnsStarted = _dnsMonitor.Start();
                    Status.IsDnsMonitorActive = dnsStarted;
                    if (!dnsStarted)
                        _logger.LogWarning("DNS查询监控启动失败，可能需要管理员权限");
                }

                // 启动网络连接监控
                if (_config.EnableNetworkMonitor)
                {
                    var netStarted = _networkMonitor.Start();
                    Status.IsNetworkMonitorActive = netStarted;
                    if (!netStarted)
                        _logger.LogWarning("网络连接监控启动失败，可能需要管理员权限");
                }

                // 启动IAT Hook管道监听
                if (_config.EnableIatHook && _hookPipeServer != null)
                {
                    var pipeStarted = _hookPipeServer.Start();
                    Status.IsIatHookActive = pipeStarted;
                    if (!pipeStarted)
                        _logger.LogWarning("IAT Hook管道服务启动失败");
                    else
                        _logger.LogInformation("IAT Hook管道服务已启动，等待注入DLL连接");
                }

                // 执行一次性的内核级别检测
                ExecuteKernelDetections();

                // 启动主监控循环（异步）
                _monitoringTask = MonitoringLoopAsync(_cts.Token);

                Status.IsRunning = true;
                Status.StartTime = DateTime.UtcNow;
                Status.IsHandleScanActive = _config.EnableHandleScan;

                _logger.LogInformation("监控服务已启动，扫描间隔: {Interval}秒", _config.ScanIntervalSeconds);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "启动监控服务失败");
                Status.ErrorMessage = ex.Message;
                return false;
            }
        }
    }

    /// <summary>
    /// 停止监控
    /// </summary>
    public void Stop()
    {
        lock (_lock)
        {
            if (!Status.IsRunning)
                return;

            try
            {
                _cts?.Cancel();
                _monitoringTask?.Wait(TimeSpan.FromSeconds(10));

                if (_config.EnableEtw)
                {
                    _etwMonitor.Stop();
                    Status.IsEtwActive = false;
                }

                if (_config.EnableDnsMonitor)
                {
                    _dnsMonitor.Stop();
                    Status.IsDnsMonitorActive = false;
                }

                if (_config.EnableNetworkMonitor)
                {
                    _networkMonitor.Stop();
                    Status.IsNetworkMonitorActive = false;
                }

                if (_config.EnableIatHook && _hookPipeServer != null)
                {
                    _hookPipeServer.Stop();
                    Status.IsIatHookActive = false;
                }

                Status.IsRunning = false;
                Status.IsHandleScanActive = false;
                Status.IsWfpDetectionActive = false;
                Status.IsLspDetectionActive = false;
                Status.IsInjectDetectionActive = false;
                Status.IsProxyDetectionActive = false;
                Status.IsDriverDetectionActive = false;

                _logger.LogInformation("监控服务已停止");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "停止监控服务时发生错误");
            }
        }
    }

    /// <summary>
    /// 执行一次性的内核级别检测（WFP、LSP、注入、代理、驱动）
    /// 这些检测结果在启动时采集一次，后续可手动刷新
    /// </summary>
    private void ExecuteKernelDetections()
    {
        _logger.LogInformation("开始执行内核级别检测...");

        // WFP网络过滤器检测
        if (_config.EnableWfpDetection)
        {
            try
            {
                _cachedWfpProviders = _wfpDetector.GetThirdPartyProviders();
                Status.IsWfpDetectionActive = true;
                Status.DetectedWfpProviders = _cachedWfpProviders.Count;
                _logger.LogInformation("WFP检测完成: 发现 {Count} 个第三方Provider", _cachedWfpProviders.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "WFP检测失败");
                Status.IsWfpDetectionActive = false;
            }
        }

        // Winsock LSP检测
        if (_config.EnableLspDetection)
        {
            try
            {
                _cachedLsps = _lspDetector.GetSuspiciousLsps();
                Status.IsLspDetectionActive = true;
                Status.DetectedLsps = _cachedLsps.Count;
                _logger.LogInformation("LSP检测完成: 发现 {Count} 个可疑LSP", _cachedLsps.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "LSP检测失败");
                Status.IsLspDetectionActive = false;
            }
        }

        // DLL注入检测
        if (_config.EnableInjectDetection)
        {
            try
            {
                var appInitDlls = _injectDetector.DetectAppInitDlls();
                var appCertDlls = _injectDetector.DetectAppCertDlls();
                _cachedInjections = appInitDlls.Concat(appCertDlls).ToList();
                Status.IsInjectDetectionActive = true;
                Status.DetectedInjectedDlls = _cachedInjections.Count;
                _logger.LogInformation("注入检测完成: 发现 {Count} 个注入DLL", _cachedInjections.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "注入检测失败");
                Status.IsInjectDetectionActive = false;
            }
        }

        // 代理配置检测
        if (_config.EnableProxyDetection)
        {
            try
            {
                _cachedProxyResult = _proxyDetector.DetectProxyConfiguration();
                Status.IsProxyDetectionActive = true;
                if (_cachedProxyResult.IsBehaviorManagementProxy)
                {
                    _logger.LogWarning("检测到上网行为管理代理: {Reason}", _cachedProxyResult.DetectionReason);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "代理检测失败");
                Status.IsProxyDetectionActive = false;
            }
        }

        // 内核驱动检测
        if (_config.EnableDriverDetection)
        {
            try
            {
                _cachedDrivers = _injectDetector.GetThirdPartyDrivers();
                Status.IsDriverDetectionActive = true;
                Status.DetectedNetworkDrivers = _cachedDrivers.Count(d => d.IsNetworkFilter);
                _logger.LogInformation("驱动检测完成: 发现 {Count} 个第三方驱动（{NetCount} 个网络过滤驱动）",
                    _cachedDrivers.Count, Status.DetectedNetworkDrivers);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "驱动检测失败");
                Status.IsDriverDetectionActive = false;
            }
        }

        _lastKernelScanTime = DateTime.UtcNow;

        // 通知内核检测结果更新
        NotifyKernelDetectionUpdate();
    }

    /// <summary>
    /// 刷新内核级别检测（手动触发）
    /// </summary>
    public void RefreshKernelDetections()
    {
        ExecuteKernelDetections();
    }

    /// <summary>
    /// 获取内核检测结果
    /// </summary>
    public KernelDetectionResult GetKernelDetectionResult()
    {
        return new KernelDetectionResult
        {
            WfpProviders = _cachedWfpProviders ?? [],
            LspInfos = _cachedLsps ?? [],
            InjectInfos = _cachedInjections ?? [],
            KernelDrivers = _cachedDrivers ?? [],
            ProxyResult = _cachedProxyResult,
            LastScanTime = _lastKernelScanTime
        };
    }

    /// <summary>
    /// 通知内核检测结果更新
    /// </summary>
    private void NotifyKernelDetectionUpdate()
    {
        var result = GetKernelDetectionResult();
        KernelDetectionUpdated?.Invoke(this, result);
    }

    /// <summary>
    /// 主监控循环（异步，避免同步阻塞）
    /// </summary>
    private async Task MonitoringLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var scanStart = DateTime.UtcNow;

                // 1. 收集ETW事件
                if (_config.EnableEtw && _etwMonitor.IsRunning)
                {
                    var etwCalls = _etwMonitor.DrainCapturedCalls();
                    if (etwCalls.Count > 0)
                    {
                        _threatDetectionService.AnalyzeApiCalls(etwCalls);
                        Status.TotalApiCallsCaptured += etwCalls.Count;
                    }
                }

                // 2. 收集DNS查询事件
                if (_config.EnableDnsMonitor && _dnsMonitor.IsRunning)
                {
                    var dnsRecords = _dnsMonitor.DrainQueryRecords();
                    if (dnsRecords.Count > 0)
                    {
                        _threatDetectionService.AnalyzeDnsQueries(dnsRecords);
                    }
                }

                // 3. 收集网络连接事件
                if (_config.EnableNetworkMonitor && _networkMonitor.IsRunning)
                {
                    var netRecords = _networkMonitor.DrainConnectionRecords();
                    if (netRecords.Count > 0)
                    {
                        _threatDetectionService.AnalyzeNetworkConnections(netRecords);
                    }
                }

                // 4. 执行句柄扫描
                if (_config.EnableHandleScan)
                {
                    ScanHandles();
                }

                // 5. 行为分析
                if (_config.EnableBehaviorAnalysis)
                {
                    AnalyzeBehavior();
                }

                // 6. 更新状态
                Status.LastScanTime = DateTime.UtcNow;
                Status.SuspiciousProcessCount = _threatDetectionService.GetSuspiciousProcesses().Count;

                // 7. 通知UI更新
                var suspiciousProcesses = _threatDetectionService.GetSuspiciousProcesses();
                if (suspiciousProcesses.Count > 0)
                {
                    SuspiciousProcessesUpdated?.Invoke(this, suspiciousProcesses);
                }

                // 8. 等待下次扫描
                var elapsed = DateTime.UtcNow - scanStart;
                var delay = TimeSpan.FromSeconds(_config.ScanIntervalSeconds) - elapsed;
                if (delay > TimeSpan.Zero)
                {
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "监控循环中发生错误");
                Status.ErrorMessage = ex.Message;
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    /// <summary>
    /// 执行句柄扫描
    /// </summary>
    private void ScanHandles()
    {
        try
        {
            var handles = _handleMonitor.ScanHandles();
            Status.TotalProcessesScanned = handles.Select(h => h.ProcessId).Distinct().Count();

            var processGroups = handles.GroupBy(h => h.ProcessId);
            var handleResults = new Dictionary<int, HandleAnalysisResult>();

            foreach (var group in processGroups)
            {
                var result = _handleMonitor.AnalyzeProcessHandles(group.Key, handles);
                if (result.IsSuspiciousProcessEnum || result.IsSuspiciousScreenCapture)
                {
                    handleResults[group.Key] = result;
                }
            }

            _threatDetectionService.AnalyzeHandleResults(handleResults);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "句柄扫描失败");
        }
    }

    /// <summary>
    /// 行为分析，检测周期性调用模式
    /// </summary>
    private void AnalyzeBehavior()
    {
        var suspiciousProcesses = _threatDetectionService.GetSuspiciousProcesses();
        var activePids = new HashSet<int>();

        var allProcesses = _processInfoService.GetAllProcesses();
        foreach (var p in allProcesses)
        {
            activePids.Add(p.ProcessId);
        }

        foreach (var process in suspiciousProcesses)
        {
            if (!activePids.Contains(process.ProcessId))
                continue;

            var detail = _processInfoService.GetProcessDetail(process.ProcessId);
            if (detail != null)
            {
                process.FilePath ??= detail.FilePath;
                process.CommandLine ??= detail.CommandLine;
                process.Company ??= detail.Company;
                process.Description ??= detail.Description;
                process.FileVersion ??= detail.FileVersion;
                process.ParentProcessId = detail.ParentProcessId;
                process.ParentProcessName ??= detail.ParentProcessName;
                process.StartTime = detail.StartTime;
                process.SessionId = detail.SessionId;
                process.IsProtected = detail.IsProtected;
                process.IsService = detail.IsService;
                process.ServiceName ??= detail.ServiceName;
                process.Architecture ??= detail.Architecture;
                process.IsSystemCritical = CriticalProcessProvider.IsCriticalProcess(process.ProcessName);
            }

            _threatDetectionService.UpdateThreatScore(process);
        }

        _threatDetectionService.RemoveStaleProcesses(activePids);
    }

    /// <summary>
    /// 获取当前可疑进程列表
    /// </summary>
    public List<SuspiciousProcessInfo> GetSuspiciousProcesses()
    {
        return _threatDetectionService.GetSuspiciousProcesses();
    }

    /// <summary>
    /// IAT Hook管道数据接收回调
    /// </summary>
    private void OnHookPipeApiCallReceived(object? sender, ApiCallRecord record)
    {
        try
        {
            _threatDetectionService.AnalyzeApiCalls([record]);
            Status.TotalApiCallsCaptured++;

            _logger.LogDebug(
                "IAT Hook捕获: PID={ProcessId} 进程={ProcessName} API={ApiName} 详情={Detail}",
                record.ProcessId, record.ProcessName, record.ApiName, record.Detail);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "处理IAT Hook管道数据时发生错误");
        }
    }

    public void Dispose()
    {
        Stop();
        _etwMonitor.Dispose();
        _dnsMonitor.Dispose();
        _networkMonitor.Dispose();
        _hookPipeServer?.Dispose();
        _cts?.Dispose();
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// 内核检测结果汇总
/// </summary>
public class KernelDetectionResult
{
    /// <summary>WFP Provider列表</summary>
    public List<NetworkFilterInfo> WfpProviders { get; set; } = [];

    /// <summary>Winsock LSP列表</summary>
    public List<WinsockLspInfo> LspInfos { get; set; } = [];

    /// <summary>DLL注入检测列表</summary>
    public List<InjectDetectionInfo> InjectInfos { get; set; } = [];

    /// <summary>内核驱动列表</summary>
    public List<KernelDriverInfo> KernelDrivers { get; set; } = [];

    /// <summary>代理配置检测结果</summary>
    public ProxyDetectionResult? ProxyResult { get; set; }

    /// <summary>上次扫描时间</summary>
    public DateTime LastScanTime { get; set; }
}