using System.Runtime.InteropServices;
using Larpx.PersonalTools.HookMonitor.Core.NativeInterop;

namespace Larpx.PersonalTools.HookMonitor.Core.Hooking;

/// <summary>
/// IAT（Import Address Table）Hook引擎
/// 通过修改导入地址表实现API拦截，兼容HVCI（内存完整性）
/// IAT位于可写数据段，修改不触发HVCI保护
/// </summary>
public class IatHookEngine
{
    /// <summary>
    /// IAT Hook信息
    /// </summary>
    private class HookInfo
    {
        public IntPtr OriginalFunction { get; set; }
        public IntPtr HookFunction { get; set; }
        public IntPtr IatEntry { get; set; }
        public string DllName { get; set; } = string.Empty;
        public string FunctionName { get; set; } = string.Empty;
    }

    private readonly List<HookInfo> _hooks = [];
    private readonly object _lock = new();

    /// <summary>
    /// 安装IAT Hook
    /// </summary>
    /// <param name="targetModule">目标模块基址</param>
    /// <param name="dllName">导入DLL名称</param>
    /// <param name="functionName">导入函数名称</param>
    /// <param name="hookFunction">Hook函数指针</param>
    /// <returns>原始函数指针，调用失败返回IntPtr.Zero</returns>
    public IntPtr InstallHook(IntPtr targetModule, string dllName, string functionName, IntPtr hookFunction)
    {
        lock (_lock)
        {
            try
            {
                var iatEntry = FindIatEntry(targetModule, dllName, functionName);
                if (iatEntry == IntPtr.Zero)
                    return IntPtr.Zero;

                var originalFunction = Marshal.ReadIntPtr(iatEntry);

                // 修改IAT条目（IAT在可写段，不需要VirtualProtect）
                // 但某些情况下IAT可能在只读段，需要先修改保护属性
                var oldProtect = uint.MinValue;
                var protectResult = VirtualProtect(
                    iatEntry, IntPtr.Size,
                    0x04 /* PAGE_READWRITE */,
                    out oldProtect);

                if (!protectResult)
                    return IntPtr.Zero;

                Marshal.WriteIntPtr(iatEntry, hookFunction);

                VirtualProtect(iatEntry, IntPtr.Size, oldProtect, out _);

                var hookInfo = new HookInfo
                {
                    OriginalFunction = originalFunction,
                    HookFunction = hookFunction,
                    IatEntry = iatEntry,
                    DllName = dllName,
                    FunctionName = functionName
                };
                _hooks.Add(hookInfo);

                return originalFunction;
            }
            catch
            {
                return IntPtr.Zero;
            }
        }
    }

    /// <summary>
    /// 卸载所有IAT Hook
    /// </summary>
    public void UninstallAll()
    {
        lock (_lock)
        {
            foreach (var hook in _hooks)
            {
                try
                {
                    var oldProtect = uint.MinValue;
                    if (VirtualProtect(hook.IatEntry, IntPtr.Size, 0x04, out oldProtect))
                    {
                        Marshal.WriteIntPtr(hook.IatEntry, hook.OriginalFunction);
                        VirtualProtect(hook.IatEntry, IntPtr.Size, oldProtect, out _);
                    }
                }
                catch
                {
                    // 静默处理卸载失败
                }
            }
            _hooks.Clear();
        }
    }

    /// <summary>
    /// 在目标模块的IAT中查找指定函数的条目
    /// </summary>
    private IntPtr FindIatEntry(IntPtr moduleBase, string dllName, string functionName)
    {
        try
        {
            // 读取DOS头
            var dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(moduleBase);
            if (dosHeader.e_magic != 0x5A4D) // "MZ"
                return IntPtr.Zero;

            // 读取NT头
            var ntHeadersPtr = IntPtr.Add(moduleBase, dosHeader.e_lfanew);
            var ntHeaders = Marshal.PtrToStructure<IMAGE_NT_HEADERS>(ntHeadersPtr);
            if (ntHeaders.Signature != 0x4550) // "PE"
                return IntPtr.Zero;

            // 获取导入目录
            var importDirectory = ntHeaders.OptionalHeader.DataDirectory[1]; // IMAGE_DIRECTORY_ENTRY_IMPORT
            if (importDirectory.VirtualAddress == 0)
                return IntPtr.Zero;

            var importDirRva = importDirectory.VirtualAddress;
            var importDirPtr = IntPtr.Add(moduleBase, (int)importDirRva);

            // 遍历导入描述符
            var descriptorIndex = 0;
            while (true)
            {
                var descriptorPtr = IntPtr.Add(importDirPtr,
                    descriptorIndex * Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>());
                var descriptor = Marshal.PtrToStructure<IMAGE_IMPORT_DESCRIPTOR>(descriptorPtr);

                if (descriptor.Name == 0)
                    break;

                // 读取DLL名称
                var namePtr = IntPtr.Add(moduleBase, (int)descriptor.Name);
                var currentDllName = Marshal.PtrToStringAnsi(namePtr) ?? string.Empty;

                if (currentDllName.Equals(dllName, StringComparison.OrdinalIgnoreCase))
                {
                    // 找到目标DLL，遍历其导入的函数
                    return FindFunctionInImportDescriptor(
                        moduleBase, descriptor, functionName);
                }

                descriptorIndex++;
            }

            return IntPtr.Zero;
        }
        catch
        {
            return IntPtr.Zero;
        }
    }

    /// <summary>
    /// 在导入描述符中查找指定函数
    /// </summary>
    private IntPtr FindFunctionInImportDescriptor(
        IntPtr moduleBase, IMAGE_IMPORT_DESCRIPTOR descriptor, string functionName)
    {
        var thunkPtr = descriptor.FirstThunk != 0
            ? IntPtr.Add(moduleBase, (int)descriptor.FirstThunk)
            : IntPtr.Zero;

        var originalThunkPtr = descriptor.OriginalFirstThunk != 0
            ? IntPtr.Add(moduleBase, (int)descriptor.OriginalFirstThunk)
            : IntPtr.Zero;

        var index = 0;
        while (true)
        {
            var currentThunk = Marshal.ReadIntPtr(IntPtr.Add(thunkPtr, index * IntPtr.Size));
            if (currentThunk == IntPtr.Zero)
                break;

            // 检查是否按序号导入
            if (originalThunkPtr != IntPtr.Zero)
            {
                var originalEntry = Marshal.ReadIntPtr(IntPtr.Add(originalThunkPtr, index * IntPtr.Size));
                if (originalEntry == IntPtr.Zero)
                    break;

                // 最高位为1表示按序号导入
                if ((originalEntry.ToInt64() & 0x80000000) == 0)
                {
                    // 按名称导入，读取函数名
                    var hintPtr = IntPtr.Add(moduleBase, originalEntry.ToInt32() + 2); // 跳过Hint
                    var currentFuncName = Marshal.PtrToStringAnsi(hintPtr) ?? string.Empty;

                    if (currentFuncName.Equals(functionName, StringComparison.OrdinalIgnoreCase))
                    {
                        return IntPtr.Add(thunkPtr, index * IntPtr.Size);
                    }
                }
            }

            index++;
        }

        return IntPtr.Zero;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(
        IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    #region PE结构体定义

    [StructLayout(LayoutKind.Sequential)]
    private struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res;
        public ushort e_oemid;
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2;
        public int e_lfanew;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IMAGE_NT_HEADERS
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IMAGE_OPTIONAL_HEADER
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IMAGE_IMPORT_DESCRIPTOR
    {
        public uint OriginalFirstThunk;
        public uint TimeDateStamp;
        public uint ForwarderChain;
        public uint Name;
        public uint FirstThunk;
    }

    #endregion
}
