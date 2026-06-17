namespace HookMonitor.Core.NativeInterop;

/// <summary>
/// NT状态码定义，来自ntstatus.h
/// </summary>
public static class NtStatus
{
    public const uint Success = 0x00000000;
    public const uint Information = 0x40000000;
    public const uint Warning = 0x80000000;
    public const uint Error = 0xC0000000;

    public const uint STATUS_SUCCESS = 0x00000000;
    public const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
    public const uint STATUS_ACCESS_DENIED = 0xC0000022;
    public const uint STATUS_INVALID_HANDLE = 0xC0000008;
    public const uint STATUS_INVALID_PARAMETER = 0xC000000D;
    public const uint STATUS_BUFFER_TOO_SMALL = 0xC0000023;
    public const uint STATUS_NOT_FOUND = 0xC0000225;
    public const uint STATUS_ACCESS_VIOLATION = 0xC0000005;
    public const uint STATUS_PRIVILEGE_NOT_HELD = 0xC0000061;
    public const uint STATUS_PROCESS_IS_PROTECTED = 0xC0000712;

    /// <summary>
    /// 判断NT状态码是否表示成功
    /// </summary>
    public static bool IsSuccess(uint status) => status == STATUS_SUCCESS;

    /// <summary>
    /// 判断NT状态码是否表示需要更大缓冲区
    /// </summary>
    public static bool IsInfoLengthMismatch(uint status) => status == STATUS_INFO_LENGTH_MISMATCH;
}
