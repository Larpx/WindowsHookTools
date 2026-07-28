using System.IO.Pipes;
using System.Runtime.InteropServices;
using Larpx.PersonalTools.HookMonitor.Models;

namespace Larpx.PersonalTools.HookMonitor.Core.Hooking;

/// <summary>
/// IAT Hook命名管道服务端
/// 接收HookMonitorAgent.dll通过命名管道发送的API调用报告
/// 管道名称：\\.\pipe\HookMonitorAgent
/// </summary>
public class HookPipeServer : IDisposable
{
    /// <summary>
    /// 与C端API_CALL_REPORT结构体对应的数据布局
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Ansi)]
    private struct API_CALL_REPORT
    {
        public uint ProcessId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ProcessName;
        public uint ApiCategory;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string ApiName;
        public uint Timestamp;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Detail;
    }

    private const string PIPE_NAME = "HookMonitorAgent";
    private const int PIPE_BUFFER_SIZE = 4096;

    private CancellationTokenSource? _cts;
    private Task? _listenTask;
    private bool _isRunning;

    /// <summary>
    /// 是否正在监听
    /// </summary>
    public bool IsRunning => _isRunning;

    /// <summary>
    /// 收到API调用报告时触发
    /// </summary>
    public event EventHandler<ApiCallRecord>? ApiCallReceived;

    /// <summary>
    /// 管道连接状态变更时触发
    /// </summary>
    public event EventHandler<bool>? ConnectionStateChanged;

    /// <summary>
    /// 启动管道监听
    /// </summary>
    public bool Start()
    {
        if (_isRunning) return true;

        try
        {
            _cts = new CancellationTokenSource();
            _listenTask = Task.Run(() => ListenAsync(_cts.Token), _cts.Token);
            _isRunning = true;
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 停止管道监听
    /// </summary>
    public void Stop()
    {
        if (!_isRunning) return;

        _cts?.Cancel();
        _listenTask?.Wait(TimeSpan.FromSeconds(5));
        _isRunning = false;
    }

    /// <summary>
    /// 异步监听管道连接，循环接收数据
    /// </summary>
    private async Task ListenAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipeServer = null;

            try
            {
                // 创建命名管道服务端
                pipeServer = new NamedPipeServerStream(
                    PIPE_NAME,
                    PipeDirection.In,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                // 异步等待客户端（注入的DLL）连接
                await pipeServer.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

                ConnectionStateChanged?.Invoke(this, true);

                // 连接建立后持续读取报告
                await ReadReportsAsync(pipeServer, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception)
            {
                // 管道异常，等待后重试
            }
            finally
            {
                ConnectionStateChanged?.Invoke(this, false);
                pipeServer?.Dispose();
            }
        }
    }

    /// <summary>
    /// 从管道流中持续读取API调用报告
    /// </summary>
    private async Task ReadReportsAsync(NamedPipeServerStream pipeServer, CancellationToken cancellationToken)
    {
        var reportSize = Marshal.SizeOf<API_CALL_REPORT>();
        var buffer = new byte[reportSize];

        while (!cancellationToken.IsCancellationRequested && pipeServer.IsConnected)
        {
            try
            {
                // 读取完整的报告结构
                var totalRead = 0;
                while (totalRead < reportSize)
                {
                    var bytesRead = await pipeServer.ReadAsync(
                        buffer.AsMemory(totalRead, reportSize - totalRead),
                        cancellationToken).ConfigureAwait(false);

                    if (bytesRead == 0)
                        return; // 客户端断开连接

                    totalRead += bytesRead;
                }

                // 将字节数组转换为结构体
                var report = BytesToReport(buffer);
                var record = ReportToApiCallRecord(report);
                ApiCallReceived?.Invoke(this, record);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception)
            {
                // 读取异常，可能客户端已断开
                break;
            }
        }
    }

    /// <summary>
    /// 将字节数组转换为API_CALL_REPORT结构体
    /// </summary>
    private static API_CALL_REPORT BytesToReport(byte[] buffer)
    {
        try
        {
            var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            try
            {
                return Marshal.PtrToStructure<API_CALL_REPORT>(handle.AddrOfPinnedObject());
            }
            finally
            {
                handle.Free();
            }
        }
        catch
        {
            return default;
        }
    }

    /// <summary>
    /// 将C端报告转换为.NET端ApiCallRecord模型
    /// </summary>
    private static ApiCallRecord ReportToApiCallRecord(API_CALL_REPORT report)
    {
        return new ApiCallRecord
        {
            ProcessId = (int)report.ProcessId,
            ProcessName = report.ProcessName ?? string.Empty,
            Category = report.ApiCategory switch
            {
                0 => ApiCategory.ProcessEnumeration,
                1 => ApiCategory.ScreenCapture,
                _ => ApiCategory.ProcessEnumeration
            },
            ApiName = report.ApiName ?? string.Empty,
            Timestamp = DateTime.UtcNow,
            Source = DetectionSource.IatHook,
            Detail = report.Detail
        };
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
        GC.SuppressFinalize(this);
    }
}
