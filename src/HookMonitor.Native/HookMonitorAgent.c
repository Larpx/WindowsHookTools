/**
 * HookMonitorAgent.c
 *
 * 注入式监控代理DLL，通过IAT Hook拦截目标进程的API调用
 * 兼容HVCI（内存完整性），仅修改IAT（可写数据段），不修改代码段
 *
 * 监控的API类别：
 * 1. 进程枚举：NtQuerySystemInformation, CreateToolhelp32Snapshot, EnumProcesses
 * 2. 截屏相关：BitBlt, PrintWindow, GetDC, GetWindowDC, CreateCompatibleBitmap
 *
 * 通信方式：命名管道（\\.\pipe\HookMonitorAgent）
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ntdll.lib")

/* ===== 常量定义 ===== */

#define PIPE_NAME L"\\\\.\\pipe\\HookMonitorAgent"
#define PIPE_BUFFER_SIZE 4096
#define MAX_API_NAME 64
#define MAX_REPORT_SIZE 512

/* API类别枚举 */
#define API_CATEGORY_PROCESS_ENUM  0
#define API_CATEGORY_SCREEN_CAPTURE 1

/* ===== 数据结构 ===== */

typedef struct _API_CALL_REPORT {
    DWORD ProcessId;
    CHAR  ProcessName[MAX_PATH];
    DWORD ApiCategory;
    CHAR  ApiName[MAX_API_NAME];
    DWORD Timestamp;
    CHAR  Detail[256];
} API_CALL_REPORT;

typedef struct _HOOK_ENTRY {
    CHAR  DllName[MAX_PATH];
    CHAR  FunctionName[MAX_API_NAME];
    PVOID OriginalFunction;
    PVOID HookFunction;
    PVOID IatEntry;
} HOOK_ENTRY;

/* ===== 全局变量 ===== */

static HOOK_ENTRY g_Hooks[32];
static INT g_HookCount = 0;
static HANDLE g_PipeHandle = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_ReportLock;
static BOOL g_Initialized = FALSE;
static HMODULE g_hModule = NULL;

/* ===== 原始函数指针 ===== */

/* 进程枚举API */
typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);
static NtQuerySystemInformation_t Original_NtQuerySystemInformation = NULL;

typedef HANDLE (WINAPI *CreateToolhelp32Snapshot_t)(
    DWORD dwFlags, DWORD th32ProcessID);
static CreateToolhelp32Snapshot_t Original_CreateToolhelp32Snapshot = NULL;

typedef BOOL (WINAPI *EnumProcesses_t)(
    DWORD *lpidProcess, DWORD cb, DWORD *cbNeeded);
static EnumProcesses_t Original_EnumProcesses = NULL;

/* 截屏API */
typedef BOOL (WINAPI *BitBlt_t)(
    HDC hdc, int x, int y, int cx, int cy,
    HDC hdcSrc, int x1, int y1, DWORD rop);
static BitBlt_t Original_BitBlt = NULL;

typedef BOOL (WINAPI *PrintWindow_t)(
    HWND hwnd, HDC hdcBlt, UINT nFlags);
static PrintWindow_t Original_PrintWindow = NULL;

typedef HDC (WINAPI *GetDC_t)(HWND hWnd);
static GetDC_t Original_GetDC = NULL;

typedef HDC (WINAPI *GetWindowDC_t)(HWND hWnd);
static GetWindowDC_t Original_GetWindowDC = NULL;

typedef HBITMAP (WINAPI *CreateCompatibleBitmap_t)(
    HDC hdc, int cx, int cy);
static CreateCompatibleBitmap_t Original_CreateCompatibleBitmap = NULL;

/* ===== 前向声明 ===== */

static BOOL ConnectToPipe(VOID);
static VOID ReportApiCall(DWORD apiCategory, LPCSTR apiName, LPCSTR detail);
static BOOL InstallIatHook(PVOID targetModule, LPCSTR dllName,
                           LPCSTR functionName, PVOID hookFunction,
                           PVOID *originalFunction, PVOID *iatEntry);
static BOOL UninstallAllHooks(VOID);
static PVOID FindIatEntry(PVOID moduleBase, LPCSTR dllName, LPCSTR functionName);

/* ===== Hook函数实现 ===== */

/**
 * NtQuerySystemInformation Hook
 * 拦截进程枚举调用（SystemProcessInformation = 5）
 */
NTSTATUS NTAPI Hooked_NtQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength)
{
    NTSTATUS status = Original_NtQuerySystemInformation(
        SystemInformationClass, SystemInformation,
        SystemInformationLength, ReturnLength);

    /* 仅监控进程信息查询（类5）和句柄信息查询（类16/64） */
    if (SystemInformationClass == 5 ||
        SystemInformationClass == 16 ||
        SystemInformationClass == 64)
    {
        CHAR detail[64];
        sprintf_s(detail, sizeof(detail), "InfoClass=%lu", SystemInformationClass);
        ReportApiCall(API_CATEGORY_PROCESS_ENUM, "NtQuerySystemInformation", detail);
    }

    return status;
}

/**
 * CreateToolhelp32Snapshot Hook
 * 拦截进程快照创建
 */
HANDLE WINAPI Hooked_CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
{
    HANDLE result = Original_CreateToolhelp32Snapshot(dwFlags, th32ProcessID);

    /* TH32CS_SNAPPROCESS = 0x00000002 */
    if (dwFlags & 0x2)
    {
        CHAR detail[64];
        sprintf_s(detail, sizeof(detail), "Flags=0x%X, PID=%lu", dwFlags, th32ProcessID);
        ReportApiCall(API_CATEGORY_PROCESS_ENUM, "CreateToolhelp32Snapshot", detail);
    }

    return result;
}

/**
 * EnumProcesses Hook
 * 拦截进程枚举
 */
BOOL WINAPI Hooked_EnumProcesses(DWORD *lpidProcess, DWORD cb, DWORD *cbNeeded)
{
    BOOL result = Original_EnumProcesses(lpidProcess, cb, cbNeeded);

    CHAR detail[64];
    sprintf_s(detail, sizeof(detail), "BufferSize=%lu", cb);
    ReportApiCall(API_CATEGORY_PROCESS_ENUM, "EnumProcesses", detail);

    return result;
}

/**
 * BitBlt Hook
 * 拦截屏幕位块传输（截屏核心API）
 */
BOOL WINAPI Hooked_BitBlt(HDC hdc, int x, int y, int cx, int cy,
                          HDC hdcSrc, int x1, int y1, DWORD rop)
{
    BOOL result = Original_BitBlt(hdc, x, y, cx, cy, hdcSrc, x1, y1, rop);

    /* CAPTUREBLT (0x40000000) 标志表示包含分层窗口，典型的截屏操作 */
    CHAR detail[128];
    sprintf_s(detail, sizeof(detail), "Size=%dx%d, ROP=0x%08X%s",
              cx, cy, rop, (rop & 0x40000000) ? " [CAPTUREBLT]" : "");
    ReportApiCall(API_CATEGORY_SCREEN_CAPTURE, "BitBlt", detail);

    return result;
}

/**
 * PrintWindow Hook
 * 拦截窗口打印（截屏API之一）
 */
BOOL WINAPI Hooked_PrintWindow(HWND hwnd, HDC hdcBlt, UINT nFlags)
{
    BOOL result = Original_PrintWindow(hwnd, hdcBlt, nFlags);

    CHAR detail[64];
    sprintf_s(detail, sizeof(detail), "Flags=%u", nFlags);
    ReportApiCall(API_CATEGORY_SCREEN_CAPTURE, "PrintWindow", detail);

    return result;
}

/**
 * GetDC Hook
 * 拦截设备上下文获取（截屏前置操作）
 */
HDC WINAPI Hooked_GetDC(HWND hWnd)
{
    HDC result = Original_GetDC(hWnd);

    if (hWnd == NULL)
    {
        /* GetDC(NULL) 获取整个屏幕DC，典型的截屏前置操作 */
        ReportApiCall(API_CATEGORY_SCREEN_CAPTURE, "GetDC", "hWnd=NULL [ScreenDC]");
    }

    return result;
}

/**
 * GetWindowDC Hook
 * 拦截窗口DC获取
 */
HDC WINAPI Hooked_GetWindowDC(HWND hWnd)
{
    HDC result = Original_GetWindowDC(hWnd);

    CHAR detail[64];
    sprintf_s(detail, sizeof(detail), "hWnd=0x%p", hWnd);
    ReportApiCall(API_CATEGORY_SCREEN_CAPTURE, "GetWindowDC", detail);

    return result;
}

/**
 * CreateCompatibleBitmap Hook
 * 拦截兼容位图创建（截屏时创建目标位图）
 */
HBITMAP WINAPI Hooked_CreateCompatibleBitmap(HDC hdc, int cx, int cy)
{
    HBITMAP result = Original_CreateCompatibleBitmap(hdc, cx, cy);

    /* 检查是否为屏幕尺寸的位图（典型截屏特征） */
    int screenX = GetSystemMetrics(SM_CXSCREEN);
    int screenY = GetSystemMetrics(SM_CYSCREEN);

    if (cx >= screenX && cy >= screenY)
    {
        CHAR detail[128];
        sprintf_s(detail, sizeof(detail), "Size=%dx%d [ScreenSize=%dx%d]",
                  cx, cy, screenX, screenY);
        ReportApiCall(API_CATEGORY_SCREEN_CAPTURE, "CreateCompatibleBitmap", detail);
    }

    return result;
}

/* ===== 通信函数 ===== */

/**
 * 连接到命名管道
 */
static BOOL ConnectToPipe(VOID)
{
    if (g_PipeHandle != INVALID_HANDLE_VALUE)
        return TRUE;

    g_PipeHandle = CreateFileW(
        PIPE_NAME,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (g_PipeHandle == INVALID_HANDLE_VALUE)
        return FALSE;

    return TRUE;
}

/**
 * 向主程序报告API调用
 */
static VOID ReportApiCall(DWORD apiCategory, LPCSTR apiName, LPCSTR detail)
{
    EnterCriticalSection(&g_ReportLock);

    __try
    {
        API_CALL_REPORT report = {0};
        report.ProcessId = GetCurrentProcessId();
        report.ApiCategory = apiCategory;
        report.Timestamp = GetTickCount();

        strncpy_s(report.ApiName, sizeof(report.ApiName), apiName, _TRUNCATE);
        strncpy_s(report.Detail, sizeof(report.Detail), detail, _TRUNCATE);

        /* 获取进程名 */
        CHAR processPath[MAX_PATH] = {0};
        if (GetModuleFileNameA(NULL, processPath, MAX_PATH))
        {
            LPCSTR name = strrchr(processPath, '\\');
            if (name)
                name++;
            else
                name = processPath;
            strncpy_s(report.ProcessName, sizeof(report.ProcessName), name, _TRUNCATE);
        }

        /* 尝试发送报告 */
        if (g_PipeHandle == INVALID_HANDLE_VALUE)
        {
            ConnectToPipe();
        }

        if (g_PipeHandle != INVALID_HANDLE_VALUE)
        {
            DWORD bytesWritten = 0;
            if (!WriteFile(g_PipeHandle, &report, sizeof(report), &bytesWritten, NULL))
            {
                /* 管道可能已断开，关闭并重试 */
                CloseHandle(g_PipeHandle);
                g_PipeHandle = INVALID_HANDLE_VALUE;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        /* 异常安全：静默处理所有异常 */
    }

    LeaveCriticalSection(&g_ReportLock);
}

/* ===== IAT Hook实现 ===== */

/**
 * 在目标模块的IAT中查找指定函数的条目
 * IAT位于可写数据段，修改不触发HVCI保护
 */
static PVOID FindIatEntry(PVOID moduleBase, LPCSTR dllName, LPCSTR functionName)
{
    __try
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
        if (dosHeader->e_magic != 0x5A4D) /* "MZ" */
            return NULL;

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != 0x4550) /* "PE" */
            return NULL;

        PIMAGE_DATA_DIRECTORY importDir = &ntHeaders->OptionalHeader.DataDirectory[1];
        if (importDir->VirtualAddress == 0)
            return NULL;

        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(
            (BYTE*)moduleBase + importDir->VirtualAddress);

        while (importDesc->Name != 0)
        {
            LPCSTR currentDllName = (LPCSTR)((BYTE*)moduleBase + importDesc->Name);

            if (_stricmp(currentDllName, dllName) == 0)
            {
                /* 找到目标DLL，遍历其导入函数 */
                PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(
                    (BYTE*)moduleBase + importDesc->FirstThunk);
                PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)(
                    (BYTE*)moduleBase + importDesc->OriginalFirstThunk);

                while (firstThunk->u1.Function != 0)
                {
                    /* 检查是否按序号导入 */
                    if (originalThunk && !(originalThunk->u1.Ordinal & 0x80000000))
                    {
                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(
                            (BYTE*)moduleBase + originalThunk->u1.AddressOfData);

                        if (strcmp(importByName->Name, functionName) == 0)
                        {
                            return &firstThunk->u1.Function;
                        }
                    }

                    firstThunk++;
                    if (originalThunk)
                        originalThunk++;
                }
            }

            importDesc++;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
    }

    return NULL;
}

/**
 * 安装IAT Hook
 */
static BOOL InstallIatHook(PVOID targetModule, LPCSTR dllName,
                           LPCSTR functionName, PVOID hookFunction,
                           PVOID *originalFunction, PVOID *iatEntry)
{
    PVOID entry = FindIatEntry(targetModule, dllName, functionName);
    if (entry == NULL)
        return FALSE;

    /* 保存原始函数指针 */
    *originalFunction = *(PVOID*)entry;
    *iatEntry = entry;

    /* 修改IAT条目（IAT在可写段，兼容HVCI） */
    DWORD oldProtect = 0;
    if (VirtualProtect(entry, sizeof(PVOID), PAGE_READWRITE, &oldProtect))
    {
        *(PVOID*)entry = hookFunction;
        VirtualProtect(entry, sizeof(PVOID), oldProtect, &oldProtect);
        return TRUE;
    }

    return FALSE;
}

/**
 * 卸载所有IAT Hook
 */
static BOOL UninstallAllHooks(VOID)
{
    for (INT i = 0; i < g_HookCount; i++)
    {
        __try
        {
            DWORD oldProtect = 0;
            if (VirtualProtect(g_Hooks[i].IatEntry, sizeof(PVOID), PAGE_READWRITE, &oldProtect))
            {
                *(PVOID*)g_Hooks[i].IatEntry = g_Hooks[i].OriginalFunction;
                VirtualProtect(g_Hooks[i].IatEntry, sizeof(PVOID), oldProtect, &oldProtect);
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            /* 静默处理 */
        }
    }
    g_HookCount = 0;
    return TRUE;
}

/* ===== 安装所有Hook ===== */

static BOOL InstallAllHooks(VOID)
{
    PVOID mainModule = (PVOID)GetModuleHandle(NULL);
    BOOL success = TRUE;

    /* 进程枚举API Hook */

    /* NtQuerySystemInformation - ntdll.dll */
    if (!InstallIatHook(mainModule, "ntdll.dll", "NtQuerySystemInformation",
                        Hooked_NtQuerySystemInformation,
                        (PVOID*)&Original_NtQuerySystemInformation,
                        &g_Hooks[g_HookCount].IatEntry))
    {
        /* IAT中可能没有直接导入，尝试动态获取 */
        Original_NtQuerySystemInformation = (NtQuerySystemInformation_t)
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    }
    else
    {
        strncpy_s(g_Hooks[g_HookCount].DllName, MAX_PATH, "ntdll.dll", _TRUNCATE);
        strncpy_s(g_Hooks[g_HookCount].FunctionName, MAX_API_NAME, "NtQuerySystemInformation", _TRUNCATE);
        g_Hooks[g_HookCount].OriginalFunction = Original_NtQuerySystemInformation;
        g_Hooks[g_HookCount].HookFunction = Hooked_NtQuerySystemInformation;
        g_HookCount++;
    }

    /* CreateToolhelp32Snapshot - kernel32.dll */
    if (InstallIatHook(mainModule, "kernel32.dll", "CreateToolhelp32Snapshot",
                       Hooked_CreateToolhelp32Snapshot,
                       (PVOID*)&Original_CreateToolhelp32Snapshot,
                       &g_Hooks[g_HookCount].IatEntry))
    {
        strncpy_s(g_Hooks[g_HookCount].DllName, MAX_PATH, "kernel32.dll", _TRUNCATE);
        strncpy_s(g_Hooks[g_HookCount].FunctionName, MAX_API_NAME, "CreateToolhelp32Snapshot", _TRUNCATE);
        g_Hooks[g_HookCount].OriginalFunction = Original_CreateToolhelp32Snapshot;
        g_Hooks[g_HookCount].HookFunction = Hooked_CreateToolhelp32Snapshot;
        g_HookCount++;
    }

    /* EnumProcesses - psapi.dll */
    if (InstallIatHook(mainModule, "psapi.dll", "EnumProcesses",
                       Hooked_EnumProcesses,
                       (PVOID*)&Original_EnumProcesses,
                       &g_Hooks[g_HookCount].IatEntry))
    {
        strncpy_s(g_Hooks[g_HookCount].DllName, MAX_PATH, "psapi.dll", _TRUNCATE);
        strncpy_s(g_Hooks[g_HookCount].FunctionName, MAX_API_NAME, "EnumProcesses", _TRUNCATE);
        g_Hooks[g_HookCount].OriginalFunction = Original_EnumProcesses;
        g_Hooks[g_HookCount].HookFunction = Hooked_EnumProcesses;
        g_HookCount++;
    }

    /* 截屏API Hook */

    /* BitBlt - gdi32.dll */
    if (InstallIatHook(mainModule, "gdi32.dll", "BitBlt",
                       Hooked_BitBlt,
                       (PVOID*)&Original_BitBlt,
                       &g_Hooks[g_HookCount].IatEntry))
    {
        strncpy_s(g_Hooks[g_HookCount].DllName, MAX_PATH, "gdi32.dll", _TRUNCATE);
        strncpy_s(g_Hooks[g_HookCount].FunctionName, MAX_API_NAME, "BitBlt", _TRUNCATE);
        g_Hooks[g_HookCount].OriginalFunction = Original_BitBlt;
        g_Hooks[g_HookCount].HookFunction = Hooked_BitBlt;
        g_HookCount++;
    }

    /* PrintWindow - user32.dll */
    if (InstallIatHook(mainModule, "user32.dll", "PrintWindow",
                       Hooked_PrintWindow,
                       (PVOID*)&Original_PrintWindow,
                       &g_Hooks[g_HookCount].IatEntry))
    {
        strncpy_s(g_Hooks[g_HookCount].DllName, MAX_PATH, "user32.dll", _TRUNCATE);
        strncpy_s(g_Hooks[g_HookCount].FunctionName, MAX_API_NAME, "PrintWindow", _TRUNCATE);
        g_Hooks[g_HookCount].OriginalFunction = Original_PrintWindow;
        g_Hooks[g_HookCount].HookFunction = Hooked_PrintWindow;
        g_HookCount++;
    }

    /* GetDC - user32.dll */
    if (InstallIatHook(mainModule, "user32.dll", "GetDC",
                       Hooked_GetDC,
                       (PVOID*)&Original_GetDC,
                       &g_Hooks[g_HookCount].IatEntry))
    {
        strncpy_s(g_Hooks[g_HookCount].DllName, MAX_PATH, "user32.dll", _TRUNCATE);
        strncpy_s(g_Hooks[g_HookCount].FunctionName, MAX_API_NAME, "GetDC", _TRUNCATE);
        g_Hooks[g_HookCount].OriginalFunction = Original_GetDC;
        g_Hooks[g_HookCount].HookFunction = Hooked_GetDC;
        g_HookCount++;
    }

    /* GetWindowDC - user32.dll */
    if (InstallIatHook(mainModule, "user32.dll", "GetWindowDC",
                       Hooked_GetWindowDC,
                       (PVOID*)&Original_GetWindowDC,
                       &g_Hooks[g_HookCount].IatEntry))
    {
        strncpy_s(g_Hooks[g_HookCount].DllName, MAX_PATH, "user32.dll", _TRUNCATE);
        strncpy_s(g_Hooks[g_HookCount].FunctionName, MAX_API_NAME, "GetWindowDC", _TRUNCATE);
        g_Hooks[g_HookCount].OriginalFunction = Original_GetWindowDC;
        g_Hooks[g_HookCount].HookFunction = Hooked_GetWindowDC;
        g_HookCount++;
    }

    /* CreateCompatibleBitmap - gdi32.dll */
    if (InstallIatHook(mainModule, "gdi32.dll", "CreateCompatibleBitmap",
                       Hooked_CreateCompatibleBitmap,
                       (PVOID*)&Original_CreateCompatibleBitmap,
                       &g_Hooks[g_HookCount].IatEntry))
    {
        strncpy_s(g_Hooks[g_HookCount].DllName, MAX_PATH, "gdi32.dll", _TRUNCATE);
        strncpy_s(g_Hooks[g_HookCount].FunctionName, MAX_API_NAME, "CreateCompatibleBitmap", _TRUNCATE);
        g_Hooks[g_HookCount].OriginalFunction = Original_CreateCompatibleBitmap;
        g_Hooks[g_HookCount].HookFunction = Hooked_CreateCompatibleBitmap;
        g_HookCount++;
    }

    return g_HookCount > 0;
}

/* ===== DLL入口点 ===== */

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_ReportLock);

        /* 尝试连接管道 */
        ConnectToPipe();

        /* 安装IAT Hook */
        if (InstallAllHooks())
        {
            g_Initialized = TRUE;
        }
        break;
    }

    case DLL_PROCESS_DETACH:
    {
        if (g_Initialized)
        {
            UninstallAllHooks();
        }

        if (g_PipeHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(g_PipeHandle);
            g_PipeHandle = INVALID_HANDLE_VALUE;
        }

        DeleteCriticalSection(&g_ReportLock);
        break;
    }
    }
    return TRUE;
}
