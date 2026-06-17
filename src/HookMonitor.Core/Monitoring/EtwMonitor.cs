using System.Collections.Concurrent;
using HookMonitor.Models;

namespace HookMonitor.Core.Monitoring;

/// <summary>
/// ETW事件监控器，通过Windows事件追踪检测可疑API调用
/// 使用ETW是Ring3下最安全的监控方式，无需注入，与HVCI完全兼容
/// </summary>
public class EtwMonitor : IDisposable
{
    private readonly ConcurrentQueue<ApiCallRecord> _capturedCalls = new();
    private CancellationTokenSource? _cts;
    private Task? _monitorTask;
    private bool _isRunning;

    /// <summary>
    /// 捕获的API调用记录
    /// </summary>
    public ConcurrentQueue<ApiCallRecord> CapturedCalls => _capturedCalls;

    /// <summary>
    /// 是否正在监控
    /// </summary>
    public bool IsRunning => _isRunning;

    /// <summary>
    /// 启动ETW监控
    /// </summary>
    public bool Start()
    {
        if (_isRunning) return true;

        try
        {
            _cts = new CancellationTokenSource();
            _monitorTask = Task.Run(() => MonitorEtwEvents(_cts.Token), _cts.Token);
            _isRunning = true;
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 停止ETW监控
    /// </summary>
    public void Stop()
    {
        if (!_isRunning) return;

        _cts?.Cancel();
        _monitorTask?.Wait(TimeSpan.FromSeconds(5));
        _isRunning = false;
    }

    /// <summary>
    /// 获取并清空已捕获的API调用记录
    /// </summary>
    public List<ApiCallRecord> DrainCapturedCalls()
    {
        var calls = new List<ApiCallRecord>();
        while (_capturedCalls.TryDequeue(out var call))
        {
            calls.Add(call);
        }
        return calls;
    }

    /// <summary>
    /// ETW事件监控主循环
    /// </summary>
    private void MonitorEtwEvents(CancellationToken cancellationToken)
    {
        try
        {
            // 使用TraceEvent库创建ETW会话
            using var session = new Microsoft.Diagnostics.Tracing.Session.TraceEventSession(
                "HookMonitor-EtwSession",
                null /* 实时会话 */);

            // 启用内核提供者（需要管理员权限）
            session.EnableKernelProvider(
                Microsoft.Diagnostics.Tracing.Parsers.KernelTraceEventParser.Keywords.Process |
                Microsoft.Diagnostics.Tracing.Parsers.KernelTraceEventParser.Keywords.ImageLoad |
                Microsoft.Diagnostics.Tracing.Parsers.KernelTraceEventParser.Keywords.Handle);

            // 注册事件处理
            session.Source.Kernel.ProcessStart += OnProcessStart;
            session.Source.Kernel.ProcessStop += OnProcessStop;
            session.Source.Kernel.ObjectCreateHandle += OnObjectCreateHandle;

            // 启用DXGI提供者（用于检测Desktop Duplication截屏）
            session.EnableProvider(
                new Guid("6b8de4e4-49cb-4b0b-9fa0-4e6b37e3aa1f"), // DXGI provider
                Microsoft.Diagnostics.Tracing.TraceEventLevel.Verbose);

            // 在后台线程处理事件
            var processingTask = Task.Run(() =>
            {
                try
                {
                    session.Source.Process();
                }
                catch (OperationCanceledException) { /* 正常退出 */ }
                catch { /* ETW会话可能因权限不足失败 */ }
            }, cancellationToken);

            // 等待取消信号
            cancellationToken.WaitHandle.WaitOne();

            session.Stop();
        }
        catch (Exception)
        {
            // ETW监控可能因权限不足或其他原因失败
            // 不影响其他监控方式
        }
    }

    private void OnProcessStart(Microsoft.Diagnostics.Tracing.Parsers.Kernel.ProcessTraceData data)
    {
        // 记录进程启动事件，用于后续行为分析
        _capturedCalls.Enqueue(new ApiCallRecord
        {
            ProcessId = data.ProcessID,
            ProcessName = data.ProcessName ?? string.Empty,
            Category = ApiCategory.ProcessEnumeration,
            ApiName = "ProcessStart",
            Timestamp = DateTime.UtcNow,
            Source = DetectionSource.Etw,
            Detail = $"命令行: {data.CommandLine}"
        });
    }

    private void OnProcessStop(Microsoft.Diagnostics.Tracing.Parsers.Kernel.ProcessTraceData data)
    {
        // 进程停止事件，可用于分析进程生命周期
    }

    private void OnObjectCreateHandle(Microsoft.Diagnostics.Tracing.Parsers.Kernel.ObjectHandleTraceData data)
    {
        // 监控句柄创建，检测进程句柄和位图句柄
        var objectTypeName = data.ObjectTypeName ?? string.Empty;

        if (objectTypeName.Equals("Process", StringComparison.OrdinalIgnoreCase))
        {
            _capturedCalls.Enqueue(new ApiCallRecord
            {
                ProcessId = data.ProcessID,
                ProcessName = data.ProcessName ?? string.Empty,
                Category = ApiCategory.ProcessEnumeration,
                ApiName = "NtOpenProcess",
                Timestamp = DateTime.UtcNow,
                Source = DetectionSource.Etw,
                Detail = $"目标进程: PID={data.ObjectName}"
            });
        }
        else if (objectTypeName.Equals("Bitmap", StringComparison.OrdinalIgnoreCase) ||
                 objectTypeName.Equals("DIBSection", StringComparison.OrdinalIgnoreCase))
        {
            _capturedCalls.Enqueue(new ApiCallRecord
            {
                ProcessId = data.ProcessID,
                ProcessName = data.ProcessName ?? string.Empty,
                Category = ApiCategory.ScreenCapture,
                ApiName = "CreateBitmap",
                Timestamp = DateTime.UtcNow,
                Source = DetectionSource.Etw,
                Detail = $"对象类型: {objectTypeName}"
            });
        }
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
        GC.SuppressFinalize(this);
    }
}
