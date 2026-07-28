# HookMonitor

[中文](README.md) | [English](README.en.md)

文档：[用户使用说明](docs/用户使用说明.md) · [开发说明](docs/开发说明.md)

一款基于 .NET 的 WPF 桌面工具，在用户态检测可疑截屏、进程枚举等行为，兼容 Windows 11 内存完整性（HVCI），无需驱动程序。

## 能做什么

- 检测截屏与进程枚举等可疑行为  
- 定位可疑进程并给出威胁等级提示  
- 默认使用系统事件追踪 + 句柄扫描；高级注入式拦截可选  

## 程序怎样工作（简要）

1. 以管理员身份启动界面程序。  
2. 开始监控后，程序周期性收集相关系统线索并评分。  
3. 在列表中查看可疑进程与原因，不需要时停止监控。

## 快速开始

```bash
dotnet restore
dotnet build --configuration Release
dotnet run --project src/HookMonitor.GUI --configuration Release
```

更完整的环境、Native DLL 与配置说明见 [开发说明](docs/开发说明.md)。日常使用见 [用户使用说明](docs/用户使用说明.md)。

## 项目说明

| 项 | 内容 |
|----|------|
| 产品 | HookMonitor（仓库 WindowsHookTools） |
| 结构 | `src/` 源码 · `docs/` 文档 · `scripts/` 脚本 |
| 许可 | MIT（见 [LICENSE](LICENSE)） |

## License

MIT License
