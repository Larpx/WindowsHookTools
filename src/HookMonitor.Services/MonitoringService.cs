using System.Collections.Concurrent;
using HookMonitor.Core;
using HookMonitor.Core.Hooking;
using HookMonitor.Core.Monitoring;
using HookMonitor.Models;
using Microsoft.Extensions.Logging;

namespace HookMonitor.Services;

/// <summary>
/// 监控管理服务，协调各监控组件的运行
/// </summary>
public class MonitoringService : IDisposable
{
    private readonly ILogger<MonitoringService> _logger;
    private readonly ProcessInfoService _processInfoService;
    private readonly ThreatDetectionService _threatDetectionService;
    private readonly MonitorConfig _config;

    private readonly HandleMonitor _handleMonitor;
    private readonly EtwMonitor _etwMonitor;
    private readonly HookPipeServer? _hookPipeServer;

    private CancellationTokenSource? _cts;
    private Task? _monitoringTask;
    private readonly object _lock = new();

    /// <summary>
    /// 当前监控状态
    /// </summary>
    public MonitoringStatus Status { get; private set; } = new();

    /// <summary>
    /// 可疑进程变更通知事件
    /// </summary>
    public event EventHandler<List<SuspiciousProcessInfo>>? SuspiciousProcessesUpdated;

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
                    {
                        _logger.LogWarning("ETW监控启动失败，可能需要管理员权限");
                    }
                }

                // 启动IAT Hook管道监听
                if (_config.EnableIatHook && _hookPipeServer != null)
                {
                    var pipeStarted = _hookPipeServer.Start();
                    Status.IsIatHookActive = pipeStarted;
                    if (!pipeStarted)
                    {
                        _logger.LogWarning("IAT Hook管道服务启动失败");
                    }
                    else
                    {
                        _logger.LogInformation("IAT Hook管道服务已启动，等待注入DLL连接");
                    }
                }

                // 启动主监控循环（异步）
                _monitoringTask = MonitoringLoopAsync(_cts.Token);

                Status.IsRunning = true;
                Status.StartTime = DateTime.UtcNow;
                Status.IsHandleScanActive = _config.EnableHandleScan;

                if (_logger.IsEnabled(LogLevel.Information))
                {
                    _logger.LogInformation("监控服务已启动，扫描间隔: {Interval}秒", _config.ScanIntervalSeconds);
                }

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

                // 停止IAT Hook管道监听
                if (_config.EnableIatHook && _hookPipeServer != null)
                {
                    _hookPipeServer.Stop();
                    Status.IsIatHookActive = false;
                }

                Status.IsRunning = false;
                Status.IsHandleScanActive = false;

                _logger.LogInformation("监控服务已停止");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "停止监控服务时发生错误");
            }
        }
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

                // 2. 执行句柄扫描
                if (_config.EnableHandleScan)
                {
                    ScanHandles();
                }

                // 3. 行为分析
                if (_config.EnableBehaviorAnalysis)
                {
                    AnalyzeBehavior();
                }

                // 4. 更新状态
                Status.LastScanTime = DateTime.UtcNow;
                Status.SuspiciousProcessCount = _threatDetectionService.GetSuspiciousProcesses().Count;

                // 5. 通知UI更新
                var suspiciousProcesses = _threatDetectionService.GetSuspiciousProcesses();
                if (suspiciousProcesses.Count > 0)
                {
                    SuspiciousProcessesUpdated?.Invoke(this, suspiciousProcesses);
                }

                // 6. 等待下次扫描
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

            // 按进程分组分析
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

        // 获取当前活跃进程列表
        var allProcesses = _processInfoService.GetAllProcesses();
        foreach (var p in allProcesses)
        {
            activePids.Add(p.ProcessId);
        }

        // 为每个可疑进程补充详细信息
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

        // 清理已退出的可疑进程
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
    /// 将管道收到的API调用报告送入威胁检测流水线
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
        _hookPipeServer?.Dispose();
        _cts?.Dispose();
        GC.SuppressFinalize(this);
    }
}
