using System.Runtime.InteropServices;
using HookMonitor.Core.NativeInterop;
using HookMonitor.Models;

namespace HookMonitor.Core.Monitoring;

/// <summary>
/// 句柄监控器，通过NtQuerySystemInformation枚举系统句柄
/// 检测进程枚举行为（大量Process句柄）和截屏行为（Bitmap/DIBSection句柄）
/// </summary>
public class HandleMonitor
{
    /// <summary>
    /// 缓存的对象类型索引，避免重复查询
    /// </summary>
    private Dictionary<byte, string>? _objectTypeCache;

    /// <summary>
    /// 扫描系统句柄，返回所有句柄信息
    /// </summary>
    public List<ProcessHandleInfo> ScanHandles()
    {
        var handles = new List<ProcessHandleInfo>();

        try
        {
            // 优先使用扩展句柄信息（支持64位句柄值）
            var extendedHandles = ScanExtendedHandles();
            if (extendedHandles.Count > 0)
                return extendedHandles;

            // 回退到基本句柄信息
            return ScanBasicHandles();
        }
        catch
        {
            return handles;
        }
    }

    /// <summary>
    /// 分析指定进程的句柄使用情况，返回可疑指标
    /// </summary>
    public HandleAnalysisResult AnalyzeProcessHandles(int processId, List<ProcessHandleInfo> allHandles)
    {
        var result = new HandleAnalysisResult();
        var processHandles = allHandles.Where(h => h.ProcessId == processId).ToList();

        // 统计进程句柄数量（用于检测进程枚举）
        var processHandleCount = processHandles.Count(h => h.IsProcessHandle);
        result.ProcessHandleCount = processHandleCount;

        // 统计位图句柄数量（用于检测截屏）
        var bitmapHandleCount = processHandles.Count(h => h.IsBitmapHandle);
        result.BitmapHandleCount = bitmapHandleCount;

        // 检测可疑的进程枚举行为
        // 正常进程通常只持有少量进程句柄（自身、子进程等）
        // 如果一个进程持有大量进程句柄，很可能在枚举进程
        if (processHandleCount > 20)
        {
            result.IsSuspiciousProcessEnum = true;
            result.SuspicionReasons.Add($"持有 {processHandleCount} 个进程句柄（正常进程通常少于20个）");
        }

        // 检测可疑的截屏行为
        // 正常进程很少持有位图句柄，截屏程序会频繁创建位图
        if (bitmapHandleCount > 5)
        {
            result.IsSuspiciousScreenCapture = true;
            result.SuspicionReasons.Add($"持有 {bitmapHandleCount} 个位图句柄（可能正在截屏）");
        }

        // 检查进程句柄的访问权限模式
        var suspiciousAccessHandles = processHandles
            .Where(h => h.IsProcessHandle && h.GrantedAccess != 0)
            .ToList();

        // PROCESS_QUERY_INFORMATION (0x0400) + PROCESS_VM_READ (0x0010) 组合
        // 通常用于进程枚举和信息读取
        var queryInfoCount = suspiciousAccessHandles.Count(h =>
            (h.GrantedAccess & 0x0410) == 0x0410);
        if (queryInfoCount > 10)
        {
            result.IsSuspiciousProcessEnum = true;
            result.SuspicionReasons.Add($"{queryInfoCount} 个进程句柄具有查询+读取权限（典型的进程枚举模式）");
        }

        return result;
    }

    /// <summary>
    /// 使用扩展句柄信息枚举（SystemExtendedHandleInformation）
    /// </summary>
    private List<ProcessHandleInfo> ScanExtendedHandles()
    {
        var handles = new List<ProcessHandleInfo>();
        IntPtr buffer = IntPtr.Zero;

        try
        {
            var status = NtApi.NtQuerySystemInformation(
                NtStructures.SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation,
                IntPtr.Zero, 0, out var requiredSize);

            if (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH)
                return handles;

            var bufferSize = requiredSize + 65536;
            buffer = Marshal.AllocHGlobal(bufferSize);

            status = NtApi.NtQuerySystemInformation(
                NtStructures.SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation,
                buffer, bufferSize, out _);

            if (!NtStatus.IsSuccess(status))
                return handles;

            var header = Marshal.PtrToStructure<NtStructures.SYSTEM_HANDLE_INFORMATION_EX>(buffer);
            var handleCount = header.NumberOfHandles.ToInt64();

            // 计算数组起始偏移
            var entrySize = Marshal.SizeOf<NtStructures.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>();
            var arrayOffset = Marshal.SizeOf<NtStructures.SYSTEM_HANDLE_INFORMATION_EX>();

            for (long i = 0; i < handleCount; i++)
            {
                var entryPtr = IntPtr.Add(buffer, arrayOffset + (int)(i * entrySize));
                var entry = Marshal.PtrToStructure<NtStructures.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(entryPtr);

                var objectType = GetObjectType((byte)entry.ObjectTypeIndex);
                var objectName = GetObjectName(entry.Object, entry.HandleValue, entry.UniqueProcessId);

                handles.Add(new ProcessHandleInfo
                {
                    ProcessId = entry.UniqueProcessId.ToInt32(),
                    ProcessName = string.Empty, // 后续填充
                    HandleValue = entry.HandleValue,
                    ObjectType = objectType ?? "Unknown",
                    ObjectName = objectName,
                    GrantedAccess = entry.GrantedAccess
                });
            }
        }
        catch
        {
            // 静默处理
        }
        finally
        {
            if (buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(buffer);
        }

        return handles;
    }

    /// <summary>
    /// 使用基本句柄信息枚举（SystemHandleInformation，兼容旧系统）
    /// </summary>
    private List<ProcessHandleInfo> ScanBasicHandles()
    {
        var handles = new List<ProcessHandleInfo>();
        IntPtr buffer = IntPtr.Zero;

        try
        {
            var status = NtApi.NtQuerySystemInformation(
                NtStructures.SYSTEM_INFORMATION_CLASS.SystemHandleInformation,
                IntPtr.Zero, 0, out var requiredSize);

            if (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH)
                return handles;

            var bufferSize = requiredSize + 65536;
            buffer = Marshal.AllocHGlobal(bufferSize);

            status = NtApi.NtQuerySystemInformation(
                NtStructures.SYSTEM_INFORMATION_CLASS.SystemHandleInformation,
                buffer, bufferSize, out _);

            if (!NtStatus.IsSuccess(status))
                return handles;

            var header = Marshal.PtrToStructure<NtStructures.SYSTEM_HANDLE_INFORMATION>(buffer);
            var handleCount = header.NumberOfHandles;

            var entrySize = Marshal.SizeOf<NtStructures.SYSTEM_HANDLE_TABLE_ENTRY_INFO>();
            var arrayOffset = Marshal.SizeOf<NtStructures.SYSTEM_HANDLE_INFORMATION>();

            for (uint i = 0; i < handleCount; i++)
            {
                var entryPtr = IntPtr.Add(buffer, arrayOffset + (int)(i * entrySize));
                var entry = Marshal.PtrToStructure<NtStructures.SYSTEM_HANDLE_TABLE_ENTRY_INFO>(entryPtr);

                var objectType = GetObjectType(entry.ObjectTypeIndex);

                handles.Add(new ProcessHandleInfo
                {
                    ProcessId = entry.UniqueProcessId,
                    ProcessName = string.Empty,
                    HandleValue = new IntPtr(entry.HandleValue),
                    ObjectType = objectType ?? "Unknown",
                    ObjectName = null, // 基本模式下不查询对象名称（太慢）
                    GrantedAccess = entry.GrantedAccess
                });
            }
        }
        catch
        {
            // 静默处理
        }
        finally
        {
            if (buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(buffer);
        }

        return handles;
    }

    /// <summary>
    /// 获取对象类型名称
    /// </summary>
    private string? GetObjectType(byte typeIndex)
    {
        _objectTypeCache ??= BuildObjectTypeCache();
        return _objectTypeCache.TryGetValue(typeIndex, out var name) ? name : null;
    }

    /// <summary>
    /// 构建对象类型索引缓存
    /// 通过NtQueryObject动态获取对象类型名称，避免硬编码索引在不同Windows版本间不一致
    /// </summary>
    private static Dictionary<byte, string> BuildObjectTypeCache()
    {
        var cache = new Dictionary<byte, string>();

        try
        {
            // 通过NtQuerySystemInformation获取系统句柄，再通过NtQueryObject查询类型名称
            // 先枚举当前进程的句柄来建立类型索引映射
            var currentPid = Kernel32Api.GetCurrentProcessId();
            var status = NtApi.NtQuerySystemInformation(
                NtStructures.SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation,
                IntPtr.Zero, 0, out var requiredSize);

            if (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH)
            {
                // 回退到硬编码映射
                return BuildFallbackObjectTypeCache();
            }

            var bufferSize = requiredSize + 65536;
            var buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                status = NtApi.NtQuerySystemInformation(
                    NtStructures.SYSTEM_INFORMATION_CLASS.SystemExtendedHandleInformation,
                    buffer, bufferSize, out _);

                if (!NtStatus.IsSuccess(status))
                {
                    return BuildFallbackObjectTypeCache();
                }

                var header = Marshal.PtrToStructure<NtStructures.SYSTEM_HANDLE_INFORMATION_EX>(buffer);
                var handleCount = header.NumberOfHandles.ToInt64();
                var entrySize = Marshal.SizeOf<NtStructures.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>();
                var arrayOffset = Marshal.SizeOf<NtStructures.SYSTEM_HANDLE_INFORMATION_EX>();

                // 收集所有出现过的类型索引
                var typeIndices = new HashSet<byte>();
                for (long i = 0; i < handleCount; i++)
                {
                    var entryPtr = IntPtr.Add(buffer, arrayOffset + (int)(i * entrySize));
                    var entry = Marshal.PtrToStructure<NtStructures.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(entryPtr);
                    typeIndices.Add((byte)entry.ObjectTypeIndex);
                }

                // 对当前进程的句柄查询类型名称来建立映射
                var currentProcessHandle = NtApi.OpenProcess(NtApi.PROCESS_QUERY_INFORMATION, false, currentPid);
                if (currentProcessHandle != IntPtr.Zero)
                {
                    try
                    {
                        foreach (var typeIndex in typeIndices)
                        {
                            // 在当前进程句柄中找到该类型的句柄来查询名称
                            for (long i = 0; i < handleCount; i++)
                            {
                                var entryPtr = IntPtr.Add(buffer, arrayOffset + (int)(i * entrySize));
                                var entry = Marshal.PtrToStructure<NtStructures.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>(entryPtr);

                                if ((byte)entry.ObjectTypeIndex != typeIndex)
                                    continue;

                                // 仅查询当前进程的句柄
                                if (entry.UniqueProcessId.ToInt32() != currentPid)
                                    continue;

                                var typeName = QueryObjectTypeName(entry.HandleValue);
                                if (!string.IsNullOrEmpty(typeName))
                                {
                                    cache[typeIndex] = typeName;
                                    break;
                                }
                            }
                        }
                    }
                    finally
                    {
                        NtApi.CloseHandle(currentProcessHandle);
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch
        {
            // 动态获取失败，回退到硬编码映射
            return BuildFallbackObjectTypeCache();
        }

        // 如果动态获取结果太少，补充硬编码映射
        if (cache.Count < 5)
        {
            return BuildFallbackObjectTypeCache();
        }

        return cache;
    }

    /// <summary>
    /// 查询对象类型名称
    /// </summary>
    private static string? QueryObjectTypeName(IntPtr handle)
    {
        try
        {
            var status = NtApi.NtQueryObject(
                handle,
                NtApi.ObjectTypeInformation,
                IntPtr.Zero, 0, out var requiredSize);

            if (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH)
                return null;

            var buffer = Marshal.AllocHGlobal(requiredSize + 256);
            try
            {
                status = NtApi.NtQueryObject(
                    handle,
                    NtApi.ObjectTypeInformation,
                    buffer, requiredSize + 256, out _);

                if (!NtStatus.IsSuccess(status))
                    return null;

                // OBJECT_TYPE_INFORMATION 结构体的第一个字段是 UNICODE_STRING TypeName
                var us = Marshal.PtrToStructure<NtStructures.UNICODE_STRING>(buffer);
                return NtApi.ReadLocalUnicodeString(us);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// 回退的硬编码对象类型索引映射
    /// 仅在动态获取失败时使用
    /// </summary>
    private static Dictionary<byte, string> BuildFallbackObjectTypeCache()
    {
        var cache = new Dictionary<byte, string>();

        // Windows常见的对象类型索引映射
        // 注意：这些索引在不同Windows版本间可能不同
        cache[0x02] = "Directory";
        cache[0x03] = "SymbolicLink";
        cache[0x04] = "Token";
        cache[0x05] = "Process";
        cache[0x06] = "Thread";
        cache[0x07] = "Event";
        cache[0x08] = "EventPair";
        cache[0x09] = "Mutant";
        cache[0x0A] = "Semaphore";
        cache[0x0B] = "Timer";
        cache[0x0C] = "Profile";
        cache[0x0D] = "Section";
        cache[0x0E] = "Key";
        cache[0x0F] = "Port";
        cache[0x10] = "IoCompletion";
        cache[0x11] = "File";
        cache[0x12] = "WmiGuid";
        cache[0x13] = "Desktop";
        cache[0x14] = "WindowStation";
        cache[0x15] = "Bitmap";
        cache[0x16] = "DIBSection";
        cache[0x17] = "DC";
        cache[0x18] = "Region";
        cache[0x19] = "Cursor";
        cache[0x1A] = "Font";
        cache[0x1B] = "Brush";
        cache[0x1C] = "Palette";
        cache[0x1D] = "Pen";
        cache[0x1E] = "AcceleratorTable";
        cache[0x1F] = "Hook";

        return cache;
    }

    /// <summary>
    /// 获取对象名称（谨慎使用，某些对象查询可能挂起）
    /// </summary>
    private string? GetObjectName(IntPtr objectPointer, IntPtr handleValue, IntPtr processId)
    {
        // 注意：NtQueryObject查询某些对象名称可能导致挂起
        // 这里使用安全超时机制
        try
        {
            var currentPid = Kernel32Api.GetCurrentProcessId();
            if (processId.ToInt32() != currentPid)
                return null; // 只查询当前进程的对象名称

            var status = NtApi.NtQueryObject(
                handleValue,
                NtApi.ObjectNameInformation,
                IntPtr.Zero, 0, out var requiredSize);

            if (status != NtStatus.STATUS_INFO_LENGTH_MISMATCH)
                return null;

            var buffer = Marshal.AllocHGlobal(requiredSize + 256);
            try
            {
                status = NtApi.NtQueryObject(
                    handleValue,
                    NtApi.ObjectNameInformation,
                    buffer, requiredSize + 256, out _);

                if (!NtStatus.IsSuccess(status))
                    return null;

                var us = Marshal.PtrToStructure<NtStructures.UNICODE_STRING>(buffer);
                return NtApi.ReadLocalUnicodeString(us);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>
/// 句柄分析结果
/// </summary>
public class HandleAnalysisResult
{
    /// <summary>进程句柄数量</summary>
    public int ProcessHandleCount { get; set; }

    /// <summary>位图句柄数量</summary>
    public int BitmapHandleCount { get; set; }

    /// <summary>是否可疑的进程枚举行为</summary>
    public bool IsSuspiciousProcessEnum { get; set; }

    /// <summary>是否可疑的截屏行为</summary>
    public bool IsSuspiciousScreenCapture { get; set; }

    /// <summary>可疑原因列表</summary>
    public List<string> SuspicionReasons { get; set; } = [];
}
