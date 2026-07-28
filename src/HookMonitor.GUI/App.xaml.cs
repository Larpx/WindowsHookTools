using System.Windows;
using Larpx.PersonalTools.HookMonitor.Models;
using Larpx.PersonalTools.HookMonitor.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Larpx.PersonalTools.HookMonitor.GUI;

/// <summary>
/// 应用程序入口
/// </summary>
public partial class App : Application
{
    private ServiceProvider? _serviceProvider;

    /// <summary>
    /// 全局服务提供者
    /// </summary>
    public static IServiceProvider Services { get; private set; } = null!;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var services = new ServiceCollection();
        ConfigureServices(services);
        _serviceProvider = services.BuildServiceProvider();
        Services = _serviceProvider;

        // 检查管理员权限
        if (!IsRunningAsAdmin())
        {
            MessageBox.Show(
                "本程序需要管理员权限运行以启用ETW监控和句柄扫描功能。\n" +
                "请右键选择\"以管理员身份运行\"。",
                "权限不足",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _serviceProvider?.Dispose();
        base.OnExit(e);
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        // 从appsettings.json读取配置
        var configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
            .Build();

        var config = new MonitorConfig();
        configuration.GetSection("MonitorConfig").Bind(config);

        services.AddLogging(builder =>
        {
            builder.AddDebug();
            builder.SetMinimumLevel(LogLevel.Debug);
        });

        services.AddSingleton(config);
        services.AddSingleton<ProcessInfoService>();
        services.AddSingleton<ThreatDetectionService>();
        services.AddSingleton<MonitoringService>();
    }

    /// <summary>
    /// 检查是否以管理员权限运行
    /// </summary>
    private static bool IsRunningAsAdmin()
    {
        try
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }
}
