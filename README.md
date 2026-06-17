# HookMonitor - 进程行为监控工具

一款基于 .NET 10 的 WPF 桌面应用，用于在 Ring3（用户态）下检测系统中可疑的截屏 API 调用和进程枚举行为。兼容 Windows 11 25H2 + HVCI（内存完整性），无需驱动程序。

## 功能特性

- **截屏行为检测**：监控 BitBlt、PrintWindow、GetDC(NULL)、Desktop Duplication 等截屏 API 调用
- **进程枚举检测**：监控 NtQuerySystemInformation、CreateToolhelp32Snapshot、EnumProcesses 等进程枚举 API
- **可疑进程定位**：获取进程路径、命令行参数、PID、父进程、架构等详细信息
- **威胁评分系统**：基于 API 调用频率、句柄特征、进程特征等多维度评分
- **HVCI 兼容**：IAT Hook 仅修改可写数据段，不触发内存完整性保护

## 监控方式

| 监控方式 | 原理 | 需要注入 | HVCI 兼容 | 管理员权限 |
|----------|------|----------|-----------|------------|
| ETW 事件追踪 | Windows 内核级事件追踪 | 否 | 完全兼容 | 是 |
| 系统句柄扫描 | NtQuerySystemInformation 枚举句柄 | 否 | 完全兼容 | 是 |
| IAT Hook | 修改导入地址表拦截 API 调用 | 是 | 兼容 | 是 |

> 默认启用 ETW + 句柄扫描，IAT Hook 为高级功能（需手动启用）。

## 项目结构

```
src/
├── HookMonitor.Core/       # 核心逻辑（ETW监控、句柄扫描、IAT Hook、NT API声明）
├── HookMonitor.Models/     # 数据模型（配置、威胁等级、进程信息等）
├── HookMonitor.GUI/        # WPF 界面（MVVM 架构）
├── HookMonitor.Services/   # 业务服务（监控协调、威胁检测、进程信息）
├── HookMonitor.Native/     # 原生 C DLL（注入式 IAT Hook 代理）
└── HookMonitor.Tests/      # 单元测试
```

## 技术栈

- **运行时**：.NET 10
- **UI 框架**：WPF + CommunityToolkit.Mvvm
- **ETW**：Microsoft.Diagnostics.Tracing.TraceEvent
- **进程信息**：WMI (System.Management)
- **底层 API**：NtQuerySystemInformation、NtQueryInformationProcess、NtQueryObject
- **DI 容器**：Microsoft.Extensions.DependencyInjection
- **日志**：Microsoft.Extensions.Logging

## 系统要求

- Windows 10 1809+ / Windows 11（推荐 Windows 11 25H2）
- .NET 10 Runtime
- **管理员权限**（ETW 和句柄扫描需要）
- x64 架构

## 构建与运行

### 前置条件

- .NET 10 SDK
- Visual Studio 2022 v17.14+ 或 VS Code + C# Dev Kit
- MSVC 编译工具（编译 Native DLL，可选）

### 构建

```bash
# 还原依赖
dotnet restore

# 构建解决方案
dotnet build --configuration Release

# 编译 Native DLL（可选，IAT Hook 功能需要）
cd src/HookMonitor.Native
build.bat
```

### 运行

```bash
# 以管理员权限运行
dotnet run --project src/HookMonitor.GUI --configuration Release
```

> 必须以管理员身份运行，否则 ETW 监控和句柄扫描功能不可用。

## 配置

配置文件位于 `src/HookMonitor.GUI/appsettings.json`：

```json
{
  "MonitorConfig": {
    "ScanIntervalSeconds": 10,
    "ThreatThreshold": 30,
    "EnableEtw": true,
    "EnableHandleScan": true,
    "EnableIatHook": false,
    "EnableBehaviorAnalysis": true,
    "ProcessEnumFrequencyThreshold": 6,
    "ScreenCaptureFrequencyThreshold": 3
  }
}
```

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| ScanIntervalSeconds | 扫描间隔（秒） | 10 |
| ThreatThreshold | 威胁评分阈值 | 30 |
| EnableEtw | 启用 ETW 监控 | true |
| EnableHandleScan | 启用句柄扫描 | true |
| EnableIatHook | 启用 IAT Hook（高级） | false |
| EnableBehaviorAnalysis | 启用行为分析 | true |
| ProcessEnumFrequencyThreshold | 进程枚举频率阈值（次/分） | 6 |
| ScreenCaptureFrequencyThreshold | 截屏频率阈值（次/分） | 3 |

## 威胁评分

| 评分范围 | 等级 | 颜色 |
|----------|------|------|
| >= 80 | 严重 | 红色 |
| >= 60 | 高危 | 橙色 |
| >= 40 | 中等 | 黄色 |
| >= 20 | 低危 | 蓝色 |
| < 20 | 无 | 灰色 |

评分因素：
- API 调用频率（进程枚举、截屏、键盘记录、剪贴板访问）
- 句柄特征（进程句柄数量、位图句柄数量、访问权限模式）
- 进程特征（是否为服务、是否有数字签名、是否可获取路径）
- 白名单减分（任务管理器、截图工具、远程桌面等已知合法进程）

## 安全设计

- **不注入关键进程**：内置 26+ 个系统关键进程和 20+ 个安全软件进程的黑名单
- **不注入受保护进程（PPL）**：自动检测并跳过 PPL 进程
- **IAT Hook 兼容 HVCI**：仅修改 IAT（可写数据段），不修改代码段
- **异常安全**：所有关键操作均有 try-catch 保护，不会导致蓝屏
- **ETW 无侵入**：ETW 是内核级事件机制，无需注入任何进程

## 监控的 API 列表

### 进程枚举 API

| API | DLL | 检测方式 |
|-----|-----|----------|
| NtQuerySystemInformation | ntdll.dll | IAT Hook / ETW |
| CreateToolhelp32Snapshot | kernel32.dll | IAT Hook |
| EnumProcesses | psapi.dll | IAT Hook |
| NtOpenProcess | ntdll.dll | ETW 句柄创建事件 |

### 截屏 API

| API | DLL | 检测方式 |
|-----|-----|----------|
| BitBlt | gdi32.dll | IAT Hook |
| PrintWindow | user32.dll | IAT Hook |
| GetDC(NULL) | user32.dll | IAT Hook |
| GetWindowDC | user32.dll | IAT Hook |
| CreateCompatibleBitmap | gdi32.dll | IAT Hook |
| Desktop Duplication | DXGI | ETW |

## 许可证

MIT License
