# HookMonitor

[中文](README.md) | [English](README.en.md)

Docs: [User Guide (zh)](docs/用户使用说明.md) · [Developer Guide (zh)](docs/开发说明.md)

A .NET WPF desktop tool that detects suspicious screen-capture and process-enumeration behavior in user mode. Works with Windows 11 memory integrity (HVCI) and does not require a kernel driver.

## What it does

- Flags suspicious capture / process-enumeration activity  
- Surfaces suspect processes with a threat level  
- Defaults to ETW + handle scanning; optional IAT hook injection  

## How it works (brief)

1. Start the GUI as Administrator.  
2. Start monitoring; the app scores relevant system signals.  
3. Review the list, then stop monitoring when done.

## Quick start

```bash
dotnet restore
dotnet build --configuration Release
dotnet run --project src/HookMonitor.GUI --configuration Release
```

See the Chinese [developer guide](docs/开发说明.md) for environment, native DLL, and configuration details.

## Project

| Item | Notes |
|------|--------|
| Product | HookMonitor (repo: WindowsHookTools) |
| Layout | `src/` · `docs/` · `scripts/` |
| License | MIT — see [LICENSE](LICENSE) |

## License

MIT License
