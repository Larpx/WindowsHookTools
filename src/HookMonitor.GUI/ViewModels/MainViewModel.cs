using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Larpx.PersonalTools.HookMonitor.Models;
using Larpx.PersonalTools.HookMonitor.Services;

namespace Larpx.PersonalTools.HookMonitor.GUI.ViewModels;

/// <summary>
/// 主窗口视图模型
/// </summary>
public partial class MainViewModel : ObservableObject
{
    private MonitoringService? _monitoringService;
    private MonitoringStatus _status = new();

    /// <summary>
    /// 可疑进程列表
    /// </summary>
    public ObservableCollection<SuspiciousProcessInfo> SuspiciousProcesses { get; } = [];

    /// <summary>
    /// 当前选中的进程
    /// </summary>
    [ObservableProperty]
    private SuspiciousProcessInfo? _selectedProcess;

    /// <summary>
    /// 是否正在监控
    /// </summary>
    [ObservableProperty]
    private bool _isMonitoring;

    /// <summary>
    /// 是否未在监控
    /// </summary>
    public bool IsNotMonitoring => !IsMonitoring;

    /// <summary>
    /// 状态指示器颜色
    /// </summary>
    public Brush StatusIndicatorColor => IsMonitoring
        ? new SolidColorBrush(Color.FromRgb(0x22, 0xC5, 0x5E)) // 绿色
        : new SolidColorBrush(Color.FromRgb(0x9C, 0xA3, 0xAF)); // 灰色

    /// <summary>
    /// 状态文本
    /// </summary>
    public string StatusText => IsMonitoring ? "监控中" : "已停止";

    /// <summary>
    /// 状态摘要
    /// </summary>
    public string StatusSummary => $"可疑进程: {_status.SuspiciousProcessCount}";

    /// <summary>
    /// 扫描计数文本
    /// </summary>
    public string ScanCountText => $"已扫描: {_status.TotalProcessesScanned} 个进程";

    /// <summary>
    /// API调用计数文本
    /// </summary>
    public string ApiCallCountText => $"API调用: {_status.TotalApiCallsCaptured}";

    partial void OnIsMonitoringChanged(bool value)
    {
        OnPropertyChanged(nameof(IsNotMonitoring));
        OnPropertyChanged(nameof(StatusIndicatorColor));
        OnPropertyChanged(nameof(StatusText));
    }

    /// <summary>
    /// 开始监控命令
    /// </summary>
    [RelayCommand]
    private void Start()
    {
        try
        {
            _monitoringService ??= App.Services.GetService(typeof(MonitoringService)) as MonitoringService;

            if (_monitoringService == null)
            {
                MessageBox.Show("无法初始化监控服务", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            _monitoringService.SuspiciousProcessesUpdated += OnSuspiciousProcessesUpdated;
            var started = _monitoringService.Start();

            if (started)
            {
                IsMonitoring = true;
            }
            else
            {
                MessageBox.Show("启动监控失败，请确保以管理员权限运行", "错误",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"启动监控时发生错误: {ex.Message}", "错误",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>
    /// 停止监控命令
    /// </summary>
    [RelayCommand]
    private void Stop()
    {
        try
        {
            if (_monitoringService != null)
            {
                _monitoringService.SuspiciousProcessesUpdated -= OnSuspiciousProcessesUpdated;
                _monitoringService.Stop();
            }
            IsMonitoring = false;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"停止监控时发生错误: {ex.Message}", "错误",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>
    /// 清除记录命令
    /// </summary>
    [RelayCommand]
    private void Clear()
    {
        SuspiciousProcesses.Clear();
        SelectedProcess = null;
    }

    /// <summary>
    /// 可疑进程更新回调
    /// </summary>
    private void OnSuspiciousProcessesUpdated(object? sender, List<SuspiciousProcessInfo> processes)
    {
        // 在UI线程更新
        Application.Current.Dispatcher.Invoke(() =>
        {
            // 更新列表（保留选中状态）
            var selectedPid = SelectedProcess?.ProcessId;

            SuspiciousProcesses.Clear();
            foreach (var process in processes)
            {
                SuspiciousProcesses.Add(process);
            }

            // 恢复选中
            if (selectedPid.HasValue)
            {
                SelectedProcess = SuspiciousProcesses.FirstOrDefault(p => p.ProcessId == selectedPid.Value);
            }

            // 更新状态
            if (_monitoringService != null)
            {
                _status = _monitoringService.Status;
                OnPropertyChanged(nameof(StatusSummary));
                OnPropertyChanged(nameof(ScanCountText));
                OnPropertyChanged(nameof(ApiCallCountText));
            }
        });
    }
}
