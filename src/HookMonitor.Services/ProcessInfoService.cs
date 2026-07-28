using System.Diagnostics;
using Larpx.PersonalTools.HookMonitor.Core;
using Larpx.PersonalTools.HookMonitor.Core.Monitoring;
using Larpx.PersonalTools.HookMonitor.Models;
using Microsoft.Extensions.Logging;

namespace Larpx.PersonalTools.HookMonitor.Services;

/// <summary>
/// 进程信息服务，收集和缓存进程详细信息
/// </summary>
public class ProcessInfoService
{
    private readonly ProcessScanner _processScanner;
    private readonly ILogger<ProcessInfoService> _logger;
    private readonly Dictionary<int, ProcessDetailInfo> _detailCache = [];

    /// <summary>
    /// 初始化进程信息服务
    /// </summary>
    public ProcessInfoService(ILogger<ProcessInfoService> logger)
    {
        _logger = logger;
        _processScanner = new ProcessScanner();
    }

    /// <summary>
    /// 获取进程详细信息，优先使用缓存
    /// </summary>
    public ProcessDetailInfo? GetProcessDetail(int processId, bool forceRefresh = false)
    {
        if (!forceRefresh && _detailCache.TryGetValue(processId, out var cached))
            return cached;

        try
        {
            var detail = _processScanner.GetProcessDetail(processId);
            if (detail != null)
            {
                _detailCache[processId] = detail;
            }
            return detail;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "获取进程 {ProcessId} 详细信息失败", processId);
            return null;
        }
    }

    /// <summary>
    /// 获取所有运行中的进程基本信息
    /// </summary>
    public List<ProcessBasicInfo> GetAllProcesses()
    {
        try
        {
            return _processScanner.EnumerateProcesses();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "枚举系统进程失败");
            return [];
        }
    }

    /// <summary>
    /// 将 ProcessDetailInfo 转换为 SuspiciousProcessInfo
    /// </summary>
    public SuspiciousProcessInfo ToSuspiciousProcessInfo(ProcessDetailInfo detail)
    {
        return new SuspiciousProcessInfo
        {
            ProcessId = detail.ProcessId,
            ProcessName = detail.ProcessName,
            FilePath = detail.FilePath,
            CommandLine = detail.CommandLine,
            Company = detail.Company,
            Description = detail.Description,
            FileVersion = detail.FileVersion,
            ParentProcessId = detail.ParentProcessId,
            ParentProcessName = detail.ParentProcessName,
            StartTime = detail.StartTime,
            SessionId = detail.SessionId,
            HandleCount = detail.HandleCount,
            WorkingSetSize = detail.WorkingSetSize,
            IsProtected = detail.IsProtected,
            IsService = detail.IsService,
            ServiceName = detail.ServiceName,
            Architecture = detail.Architecture,
            IsSystemCritical = CriticalProcessProvider.IsCriticalProcess(detail.ProcessName)
        };
    }

    /// <summary>
    /// 清理已退出进程的缓存
    /// </summary>
    public void CleanupStaleCache()
    {
        var stalePids = new List<int>();
        foreach (var pid in _detailCache.Keys)
        {
            try
            {
                Process.GetProcessById(pid);
            }
            catch
            {
                stalePids.Add(pid);
            }
        }

        foreach (var pid in stalePids)
        {
            _detailCache.Remove(pid);
        }

        if (stalePids.Count > 0)
        {
            _logger.LogDebug("清理了 {Count} 个已退出进程的缓存", stalePids.Count);
        }
    }
}
