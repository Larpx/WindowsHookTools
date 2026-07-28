using Larpx.PersonalTools.HookMonitor.Core;
using Larpx.PersonalTools.HookMonitor.Core.Hooking;
using Larpx.PersonalTools.HookMonitor.Models;
using Larpx.PersonalTools.HookMonitor.Services;

namespace Larpx.PersonalTools.HookMonitor.Tests;

/// <summary>
/// CriticalProcessProvider单元测试
/// </summary>
public class CriticalProcessProviderTests
{
    [Fact]
    public void IsCriticalProcess_KnownCriticalProcess_ReturnsTrue()
    {
        Assert.True(CriticalProcessProvider.IsCriticalProcess("csrss"));
        Assert.True(CriticalProcessProvider.IsCriticalProcess("lsass"));
        Assert.True(CriticalProcessProvider.IsCriticalProcess("svchost"));
        Assert.True(CriticalProcessProvider.IsCriticalProcess("dwm"));
    }

    [Fact]
    public void IsCriticalProcess_SecurityProcess_ReturnsTrue()
    {
        Assert.True(CriticalProcessProvider.IsCriticalProcess("MsMpEng"));
        Assert.True(CriticalProcessProvider.IsCriticalProcess("Huorong"));
    }

    [Fact]
    public void IsCriticalProcess_NormalProcess_ReturnsFalse()
    {
        Assert.False(CriticalProcessProvider.IsCriticalProcess("notepad"));
        Assert.False(CriticalProcessProvider.IsCriticalProcess("chrome"));
        Assert.False(CriticalProcessProvider.IsCriticalProcess("calc"));
    }

    [Fact]
    public void IsCriticalProcess_CaseInsensitive_ReturnsTrue()
    {
        Assert.True(CriticalProcessProvider.IsCriticalProcess("CSRSS"));
        Assert.True(CriticalProcessProvider.IsCriticalProcess("Svchost"));
    }

    [Fact]
    public void IsKnownLegitimate_KnownProcess_ReturnsTrue()
    {
        Assert.True(CriticalProcessProvider.IsKnownLegitimate("Taskmgr"));
        Assert.True(CriticalProcessProvider.IsKnownLegitimate("SnippingTool"));
        Assert.True(CriticalProcessProvider.IsKnownLegitimate("mstsc"));
    }

    [Fact]
    public void IsKnownLegitimate_UnknownProcess_ReturnsFalse()
    {
        Assert.False(CriticalProcessProvider.IsKnownLegitimate("malware"));
        Assert.False(CriticalProcessProvider.IsKnownLegitimate("unknown"));
    }
}

/// <summary>
/// DllInjector安全检查单元测试
/// </summary>
public class DllInjectorSafetyTests
{
    private readonly DllInjector _injector = new();

    [Fact]
    public void CheckInjectionSafety_CurrentProcess_ReturnsUnsafe()
    {
        var currentPid = System.Diagnostics.Process.GetCurrentProcess().Id;
        var result = _injector.CheckInjectionSafety("test", currentPid, false);

        Assert.False(result.IsSafe);
        Assert.Contains("自身进程", result.Reason);
    }

    [Fact]
    public void CheckInjectionSafety_CriticalProcess_ReturnsUnsafe()
    {
        var result = _injector.CheckInjectionSafety("csrss", 100, false);

        Assert.False(result.IsSafe);
        Assert.Contains("关键进程", result.Reason);
    }

    [Fact]
    public void CheckInjectionSafety_SecurityProcess_ReturnsUnsafe()
    {
        var result = _injector.CheckInjectionSafety("360safe", 200, false);

        Assert.False(result.IsSafe);
    }

    [Fact]
    public void CheckInjectionSafety_ProtectedProcess_ReturnsUnsafe()
    {
        var result = _injector.CheckInjectionSafety("someapp", 300, true);

        Assert.False(result.IsSafe);
        Assert.Contains("受保护", result.Reason);
    }

    [Fact]
    public void CheckInjectionSafety_LowPid_ReturnsUnsafe()
    {
        var result = _injector.CheckInjectionSafety("test", 4, false);

        Assert.False(result.IsSafe);
        Assert.Contains("内核进程", result.Reason);
    }

    [Fact]
    public void CheckInjectionSafety_NormalProcess_ReturnsSafe()
    {
        var result = _injector.CheckInjectionSafety("notepad", 5000, false);

        Assert.True(result.IsSafe);
        Assert.Null(result.Reason);
    }
}

/// <summary>
/// InjectionSafetyCheckResult单元测试
/// </summary>
public class InjectionSafetyCheckResultTests
{
    [Fact]
    public void Safe_CreatesSafeResult()
    {
        var result = InjectionSafetyCheckResult.Safe();

        Assert.True(result.IsSafe);
        Assert.Null(result.Reason);
    }

    [Fact]
    public void Unsafe_CreatesUnsafeResultWithReason()
    {
        var result = InjectionSafetyCheckResult.Unsafe("test reason");

        Assert.False(result.IsSafe);
        Assert.Equal("test reason", result.Reason);
    }
}

/// <summary>
/// Models单元测试
/// </summary>
public class ModelTests
{
    [Fact]
    public void ApiCallRecord_DefaultValues_AreCorrect()
    {
        var record = new ApiCallRecord();

        Assert.Equal(0, record.ProcessId);
        Assert.Equal(string.Empty, record.ProcessName);
        Assert.Equal(ApiCategory.ProcessEnumeration, record.Category);
        Assert.Equal(string.Empty, record.ApiName);
        Assert.Equal(DetectionSource.Etw, record.Source);
        Assert.Null(record.Detail);
        Assert.True(record.Timestamp <= DateTime.UtcNow);
        Assert.True(record.Timestamp > DateTime.UtcNow.AddMinutes(-1));
    }

    [Fact]
    public void SuspiciousProcessInfo_DefaultValues_AreCorrect()
    {
        var info = new SuspiciousProcessInfo();

        Assert.Equal(0, info.ProcessId);
        Assert.Equal(string.Empty, info.ProcessName);
        Assert.Equal(ThreatLevel.None, info.ThreatLevel);
        Assert.Equal(0, info.ThreatScore);
        Assert.Empty(info.ApiCalls);
        Assert.Empty(info.DetectionReasons);
        Assert.Equal(0, info.CallFrequency);
    }

    [Fact]
    public void MonitorConfig_DefaultValues_AreCorrect()
    {
        var config = new MonitorConfig();

        Assert.Equal(10, config.ScanIntervalSeconds);
        Assert.Equal(30, config.ThreatThreshold);
        Assert.True(config.EnableEtw);
        Assert.True(config.EnableHandleScan);
        Assert.False(config.EnableIatHook);
        Assert.True(config.EnableBehaviorAnalysis);
        Assert.Empty(config.WhitelistedProcesses);
        Assert.Empty(config.BlacklistedProcesses);
    }

    [Fact]
    public void SuspiciousProcessInfo_PrimaryDetectionReason_WithReasons_ReturnsFirst()
    {
        var info = new SuspiciousProcessInfo
        {
            DetectionReasons = ["原因A", "原因B"]
        };

        Assert.Equal("原因A", info.PrimaryDetectionReason);
    }

    [Fact]
    public void SuspiciousProcessInfo_PrimaryDetectionReason_WithoutReasons_ReturnsUnknown()
    {
        var info = new SuspiciousProcessInfo();

        Assert.Equal("未知", info.PrimaryDetectionReason);
    }
}

/// <summary>
/// ThreatDetectionService单元测试
/// </summary>
public class ThreatDetectionServiceTests
{
    private readonly ThreatDetectionService _service;

    public ThreatDetectionServiceTests()
    {
        var logger = new TestLogger<ThreatDetectionService>();
        _service = new ThreatDetectionService(logger);
    }

    [Fact]
    public void GetSuspiciousProcesses_Initially_ReturnsEmpty()
    {
        var processes = _service.GetSuspiciousProcesses();

        Assert.Empty(processes);
    }

    [Fact]
    public void AddOrUpdateSuspiciousProcess_AddsProcess()
    {
        var process = new SuspiciousProcessInfo
        {
            ProcessId = 1234,
            ProcessName = "test",
            ThreatScore = 50,
            ThreatLevel = ThreatLevel.Medium
        };

        _service.AddOrUpdateSuspiciousProcess(process);

        var result = _service.GetSuspiciousProcesses();
        Assert.Single(result);
        Assert.Equal(1234, result[0].ProcessId);
    }

    [Fact]
    public void AddOrUpdateSuspiciousProcess_UpdatesExistingProcess()
    {
        var process1 = new SuspiciousProcessInfo
        {
            ProcessId = 1234,
            ProcessName = "test",
            ThreatScore = 50,
            ThreatLevel = ThreatLevel.Medium,
            DetectionReasons = ["原因A"]
        };

        _service.AddOrUpdateSuspiciousProcess(process1);

        var process2 = new SuspiciousProcessInfo
        {
            ProcessId = 1234,
            ProcessName = "test",
            ThreatScore = 80,
            ThreatLevel = ThreatLevel.Critical,
            DetectionReasons = ["原因B"]
        };

        _service.AddOrUpdateSuspiciousProcess(process2);

        var result = _service.GetSuspiciousProcesses();
        Assert.Single(result);
        Assert.Equal(80, result[0].ThreatScore);
        Assert.Equal(ThreatLevel.Critical, result[0].ThreatLevel);
        Assert.Contains("原因A", result[0].DetectionReasons);
        Assert.Contains("原因B", result[0].DetectionReasons);
    }

    [Fact]
    public void RemoveStaleProcesses_RemovesInactiveProcesses()
    {
        var process = new SuspiciousProcessInfo
        {
            ProcessId = 9999,
            ProcessName = "test"
        };

        _service.AddOrUpdateSuspiciousProcess(process);

        var activePids = new HashSet<int> { 1, 2, 3 }; // 不包含9999
        _service.RemoveStaleProcesses(activePids);

        Assert.Empty(_service.GetSuspiciousProcesses());
    }

    [Fact]
    public void Clear_RemovesAllProcesses()
    {
        _service.AddOrUpdateSuspiciousProcess(new SuspiciousProcessInfo
        {
            ProcessId = 1,
            ProcessName = "test1"
        });
        _service.AddOrUpdateSuspiciousProcess(new SuspiciousProcessInfo
        {
            ProcessId = 2,
            ProcessName = "test2"
        });

        _service.Clear();

        Assert.Empty(_service.GetSuspiciousProcesses());
    }
}

/// <summary>
/// 简单的测试用Logger实现
/// </summary>
internal class TestLogger<T> : Microsoft.Extensions.Logging.ILogger<T>
{
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;
    public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId,
        TState state, Exception? exception, Func<TState, Exception?, string> formatter) { }
}
