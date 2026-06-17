using System.Runtime.InteropServices;

namespace HookMonitor.Core.NativeInterop;

/// <summary>
/// NT API 相关结构体定义
/// </summary>
public static class NtStructures
{
    /// <summary>
    /// 系统信息类别枚举（NtQuerySystemInformation用）
    /// </summary>
    public enum SYSTEM_INFORMATION_CLASS
    {
        SystemBasicInformation = 0,
        SystemPerformanceInformation = 2,
        SystemTimeOfDayInformation = 3,
        SystemProcessInformation = 5,
        SystemModuleInformation = 11,
        SystemHandleInformation = 16,
        SystemObjectInformation = 17,
        SystemExtendedHandleInformation = 64,
    }

    /// <summary>
    /// 进程信息类别枚举（NtQueryInformationProcess用）
    /// </summary>
    public enum PROCESS_INFORMATION_CLASS
    {
        ProcessBasicInformation = 0,
        ProcessImageFileName = 27,
        ProcessBreakOnTermination = 29,
    }

    /// <summary>
    /// SYSTEM_PROCESS_INFORMATION 结构体
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_PROCESS_INFORMATION
    {
        public uint NextEntryOffset;
        public uint NumberOfThreads;
        public long WorkingSetPrivateSize;
        public long HardFaultCount;
        public uint NumberOfThreadsHighWatermark;
        public ulong CycleTime;
        public long CreateTime;
        public long UserTime;
        public long KernelTime;
        public UNICODE_STRING ImageName;
        public int BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
        public uint HandleCount;
        public uint SessionId;
        public IntPtr UniqueProcessKey;
        public long PeakVirtualSize;
        public long VirtualSize;
        public long PeakWorkingSetSize;
        public long WorkingSetSize;
        public long QuotaPeakPagedPoolUsage;
        public long QuotaPagedPoolUsage;
        public long QuotaPeakNonPagedPoolUsage;
        public long QuotaNonPagedPoolUsage;
        public long PagefileUsage;
        public long PeakPagefileUsage;
        public long PrivatePageCount;
        public long ReadOperationCount;
        public long WriteOperationCount;
        public long OtherOperationCount;
        public long ReadTransferCount;
        public long WriteTransferCount;
        public long OtherTransferCount;
    }

    /// <summary>
    /// UNICODE_STRING 结构体
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    /// <summary>
    /// SYSTEM_HANDLE_TABLE_ENTRY_INFO 结构体
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
    {
        public ushort UniqueProcessId;
        public ushort CreatorBackTraceIndex;
        public byte ObjectTypeIndex;
        public byte HandleAttributes;
        public ushort HandleValue;
        public IntPtr Object;
        public uint GrantedAccess;
    }

    /// <summary>
    /// SYSTEM_HANDLE_INFORMATION 结构体
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_HANDLE_INFORMATION
    {
        public uint NumberOfHandles;
        // 后跟 SYSTEM_HANDLE_TABLE_ENTRY_INFO 数组
    }

    /// <summary>
    /// SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX 扩展结构体
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        public IntPtr Object;
        public IntPtr UniqueProcessId;
        public IntPtr HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    /// <summary>
    /// SYSTEM_HANDLE_INFORMATION_EX 扩展结构体
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_HANDLE_INFORMATION_EX
    {
        public IntPtr NumberOfHandles;
        public IntPtr Reserved;
        // 后跟 SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX 数组
    }

    /// <summary>
    /// OBJECT_TYPE_INFORMATION 结构体
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_TYPE_INFORMATION
    {
        public UNICODE_STRING TypeName;
        public uint TotalNumberOfObjects;
        public uint TotalNumberOfHandles;
        public uint TotalPagedPoolUsage;
        public uint TotalNonPagedPoolUsage;
        public uint TotalNamePoolUsage;
        public uint TotalHandleTableUsage;
        public uint HighWaterNumberOfObjects;
        public uint HighWaterNumberOfHandles;
        public uint HighWaterPagedPoolUsage;
        public uint HighWaterNonPagedPoolUsage;
        public uint HighWaterNamePoolUsage;
        public uint HighWaterHandleTableUsage;
        public uint InvalidAttributes;
        public GENERIC_MAPPING GenericMapping;
        public uint ValidAccessMask;
        public byte SecurityRequired;
        public byte MaintainHandleCount;
        public byte TypeIndex;
        public byte ReservedByte;
        public uint PoolType;
        public uint DefaultPagedPoolCharge;
        public uint DefaultNonPagedPoolCharge;
    }

    /// <summary>
    /// GENERIC_MAPPING 结构体
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct GENERIC_MAPPING
    {
        public uint GenericRead;
        public uint GenericWrite;
        public uint GenericExecute;
        public uint GenericAll;
    }

    /// <summary>
    /// PROCESS_BASIC_INFORMATION 结构体
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }
}
