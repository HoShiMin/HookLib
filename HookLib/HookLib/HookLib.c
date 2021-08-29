#include "HookLib.h"

#if _KERNEL_MODE
    #include <ntifs.h>
#ifdef _AMD64_
    #include <minwindef.h>
#endif
    #include <intrin.h>
#else
    #define _USER_MODE 1

    #define WIN32_LEAN_AND_MEAN

    #define WIN32_NO_STATUS
    #include <windows.h>
    #undef WIN32_NO_STATUS

    #include <winternl.h>
    
    #pragma comment(lib, "ntdll.lib")
#endif

#include <ntstatus.h>

#define ZYDIS_STATIC_DEFINE
#include <Zydis/Zydis.h>

#if !defined offsetof
    #define offsetof(s, m) ((size_t)&(((s*)0)->m))
#endif

#if _USER_MODE
    #define NtCurrentProcess() ((HANDLE)-1)
    #define NtCurrentThread()  ((HANDLE)-2)

    #ifdef _AMD64_
        #define teb() ((const void*)__readgsqword(0x30))
        #define peb() ((const void*)__readgsqword(0x60))
        #define pid() (*(const unsigned int*)((const unsigned char*)teb() + 0x40)) /* TEB::ClientId.UniqueProcessId */
        #define tid() (*(const unsigned int*)((const unsigned char*)teb() + 0x48)) /* TEB::ClientId.UniqueThreadId */
    #else
        #define teb() ((const void*)__readfsdword(0x18))
        #define peb() ((const void*)__readfsdword(0x30))
        #define pid() (*(const unsigned int*)((const unsigned char*)teb() + 0x20)) /* TEB::ClientId.UniqueProcessId */
        #define tid() (*(const unsigned int*)((const unsigned char*)teb() + 0x24)) /* TEB::ClientId.UniqueThreadId */
    #endif
#endif

#if _KERNEL_MODE
    #define pid() (unsigned int)(size_t)PsGetCurrentProcessId()
    #define tid() (unsigned int)(size_t)PsGetCurrentThreadId()
#endif

#ifdef _AMD64_
    typedef long long ssize_t;
#else
    typedef long ssize_t;
#endif

typedef unsigned char bool;
#define true ((bool)1)
#define false ((bool)0)

#define nullptr ((void*)0)

#define unused(...) __VA_ARGS__

#define k_pageSize 4096u

// For debug purposes:
#define k_forceLongJumps           false
#define k_enableIntermediateJumps  true

// 'WRK' is the custom prefix to bypass these structs redeclaration error:

typedef struct
{
    union
    {
        LARGE_INTEGER KernelTime;
#if _USER_MODE
        HANDLE hThread; // We use this member as a thread handle storage
#elif _KERNEL_MODE
        PETHREAD thread;
#endif
    } u0;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} WRK_SYSTEM_THREAD_INFORMATION;

typedef struct
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    WRK_SYSTEM_THREAD_INFORMATION Threads[1];
} WRK_SYSTEM_PROCESS_INFORMATION;

#if _USER_MODE
    typedef enum
    {
        MemoryBasicInformation
    } MEMORY_INFORMATION_CLASS;
#elif _KERNEL_MODE
    typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemBasicInformation = 0,
        SystemPerformanceInformation = 2,
        SystemTimeOfDayInformation = 3,
        SystemProcessInformation = 5,
        SystemProcessorPerformanceInformation = 8,
        SystemInterruptInformation = 23,
        SystemExceptionInformation = 33,
        SystemRegistryQuotaInformation = 37,
        SystemLookasideInformation = 45,
        SystemCodeIntegrityInformation = 103,
        SystemPolicyInformation = 134,
    } SYSTEM_INFORMATION_CLASS;
#endif // _KERNEL_MODE

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS infoClass,
    OUT PVOID buf,
    IN ULONG len,
    OUT OPTIONAL PULONG returned
);

#if _USER_MODE
NTSYSAPI NTSTATUS NTAPI ZwAllocateVirtualMemory(
    IN HANDLE hProcess,
    IN OUT PVOID* baseAddress,
    IN ULONG zeroBits,
    IN OUT PSIZE_T regionSize,
    IN ULONG allocationType,
    IN ULONG protect
);

NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(
    IN HANDLE hProcess,
    IN PVOID baseAddress,
    IN MEMORY_INFORMATION_CLASS infoClass,
    OUT PVOID buf,
    IN SIZE_T length,
    OUT OPTIONAL PSIZE_T resultLength
);

NTSYSAPI NTSTATUS NTAPI ZwFreeVirtualMemory(
    IN HANDLE hProcess,
    IN PVOID* baseAddress,
    IN OUT PSIZE_T regionSize,
    IN ULONG freeType
);

NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
    IN HANDLE hProcess,
    IN OUT PVOID* baseAddress,
    IN OUT PSIZE_T numberOfBytes,
    IN ULONG newProt,
    OUT PULONG oldProt
);
#elif _KERNEL_MODE
typedef NTSTATUS (NTAPI* FnZwProtectVirtualMemory)(
    IN HANDLE hProcess,
    IN OUT PVOID* baseAddress,
    IN OUT PSIZE_T numberOfBytes,
    IN ULONG newProt,
    OUT PULONG oldProt
);
#endif


NTSYSAPI NTSTATUS NTAPI ZwOpenThread(
    OUT PHANDLE hThread,
    IN ACCESS_MASK access,
    IN const OBJECT_ATTRIBUTES* objAttrs,
    IN const CLIENT_ID* clientId
);

NTSYSAPI NTSTATUS NTAPI ZwYieldExecution();

#if _USER_MODE
    NTSYSAPI NTSTATUS NTAPI ZwSuspendThread(
        IN HANDLE hThread,
        OUT OPTIONAL PULONG previousSuspendCount
    );

    NTSYSAPI NTSTATUS NTAPI ZwResumeThread(
        IN HANDLE hThread,
        OUT OPTIONAL PULONG suspendCount
    );

    NTSYSAPI NTSTATUS NTAPI ZwGetContextThread(
        IN HANDLE hThread,
        OUT PCONTEXT ctx
    );

    NTSYSAPI NTSTATUS NTAPI ZwSetContextThread(
        IN HANDLE hThread,
        IN PCONTEXT ctx
    );
#endif

#if _KERNEL_MODE
#ifdef _AMD64_
    NTSYSAPI NTSTATUS NTAPI ZwQueryInformationThread(
        _In_ HANDLE hThread,
        _In_ THREADINFOCLASS info,
        _In_ PVOID buf,
        _In_ ULONG size,
        _Out_opt_ PULONG returned
    );

    NTSYSAPI const void* NTAPI PsGetProcessWow64Process(PEPROCESS process);
#endif

    NTSYSAPI BOOLEAN NTAPI KeIsAttachedProcess();
    NTSYSAPI NTSTATUS NTAPI PsSuspendProcess(PEPROCESS process);
    NTSYSAPI NTSTATUS NTAPI PsResumeProcess(PEPROCESS process);
    NTSYSAPI NTSTATUS NTAPI PsGetContextThread(_In_ PETHREAD thread, _Inout_ PCONTEXT ctx, _In_ KPROCESSOR_MODE mode);
    NTSYSAPI NTSTATUS NTAPI PsSetContextThread(_In_ PETHREAD thread, _Inout_ PCONTEXT ctx, _In_ KPROCESSOR_MODE mode);
    typedef NTSTATUS (NTAPI* FnPspGetContextThreadInternal)(_In_ PETHREAD thread, _Inout_ PCONTEXT ctx, _In_ KPROCESSOR_MODE contextDisposition, _In_ KPROCESSOR_MODE queryContextForPart, _In_ BOOLEAN unwindStack);
    typedef NTSTATUS (NTAPI* FnPspSetContextThreadInternal)(_In_ PETHREAD thread, _Inout_ PCONTEXT ctx, _In_ KPROCESSOR_MODE contextDisposition, _In_ KPROCESSOR_MODE setContextForPart, _In_ BOOLEAN unwindStack);
#endif

NTSYSAPI NTSTATUS NTAPI ZwFlushInstructionCache(
    IN HANDLE hProcess,
    IN PVOID baseAddress,
    IN SIZE_T numberOfBytesToFlush
);

#if _USER_MODE
    NTSYSAPI NTSTATUS NTAPI ZwClose(HANDLE handle);

    NTSYSAPI NTSTATUS NTAPI LdrGetDllHandle(
        IN OPTIONAL PWORD path,
        IN OPTIONAL PVOID unused,
        IN PUNICODE_STRING moduleFileName,
        OUT PHANDLE hModule
    );

    NTSYSAPI NTSTATUS NTAPI LdrGetProcedureAddress(
        IN HMODULE hModule,
        IN OPTIONAL PANSI_STRING funcName,
        IN OPTIONAL WORD ordinal,
        OUT PVOID* funcAddress
    );

    void* lookupModule(const wchar_t* modName)
    {
        if (!modName)
        {
            return nullptr;
        }

        UNICODE_STRING name;
        RtlInitUnicodeString(&name, modName);
        HMODULE hModule = nullptr;
        const NTSTATUS status = LdrGetDllHandle(nullptr, nullptr, &name, &hModule);
        if (!NT_SUCCESS(status))
        {
            return nullptr;
        }

        return hModule;
    }

    void* lookupFunction(const void* hModule, const char* funcName)
    {
        if (!hModule || !funcName)
        {
            return nullptr;
        }

        void* addr = nullptr;
        ANSI_STRING name;
        RtlInitAnsiString(&name, funcName);
        const NTSTATUS status = LdrGetProcedureAddress((HMODULE)hModule, &name, 0, &addr);
        if (!NT_SUCCESS(status))
        {
            return nullptr;
        }

        return addr;
    }
#endif

#if _KERNEL_MODE
typedef struct
{
    unsigned long long forMagic;
    unsigned long long forBase;
} Salt;

static Salt g_salt = { .forMagic = 0, .forBase = 0 };

static const Salt* getSalt()
{
    return &g_salt;
}

static void initSalt()
{
    while (!g_salt.forMagic && !g_salt.forBase)
    {
        LARGE_INTEGER tickCount = { .QuadPart = 0 };
        KeQueryTickCount(&tickCount);

        const unsigned long seed = tickCount.LowPart;
        const unsigned long k_distributedBits = 0x5956C34D;
        const unsigned long saltForSalt = seed ^ k_distributedBits;

        const unsigned long forMagicLow = RtlRandom((unsigned long*)&seed) ^ saltForSalt;
        const unsigned long forMagicHigh = RtlRandom((unsigned long*)&forMagicLow) ^ saltForSalt;

        const unsigned long forBaseLow = RtlRandom((unsigned long*)&forMagicHigh) ^ saltForSalt;
        const unsigned long forBaseHigh = RtlRandom((unsigned long*)&forBaseLow) ^ saltForSalt;

        g_salt.forMagic = ((unsigned long long)forMagicHigh << 32) | (unsigned long long)forMagicLow;
        g_salt.forBase = ((unsigned long long)forBaseHigh << 32) | (unsigned long long)forBaseLow;
    }
}
#endif

static volatile long g_busy = 0;

static void acquireGlobalLock()
{
    while (InterlockedCompareExchange(&g_busy, true, false) == true)
    {
        _mm_pause();
    }
}

static void releaseGlobalLock()
{
    InterlockedExchange(&g_busy, false);
}

static size_t inline alignDown(size_t value, size_t factor)
{
    return value & ~(factor - 1);
}

static size_t inline alignUp(size_t value, size_t factor)
{
    return alignDown(value - 1, factor) + factor;
}

static bool inline aligned(size_t value, size_t factor)
{
    return (value & (factor - 1)) == 0;
}

static ssize_t delta(const void* const src, const void* const dest)
{
    return (ssize_t)(size_t)dest - (ssize_t)(size_t)src;
}

static size_t absDelta(const void* const src, const void* const dest)
{
    return (src < dest) ? ((size_t)dest - (size_t)src) : ((size_t)src - (size_t)dest);
}

static bool relativeJumpable(const void* from, const void* to)
{
    const size_t k_2gb = 2ul * 1024ul * 1048576ul;
    return absDelta(from, to) < k_2gb;
}

#if _KERNEL_MODE
static const unsigned int k_poolTag = 'kooH';

static void* allocKernel(size_t size)
{
    void* const buf = ExAllocatePoolWithTag(NonPagedPool, size, k_poolTag); // Always RWX
    if (buf)
    {
        memset(buf, 0, size);
    }
    return buf;
}

static void freeKernel(void* const base)
{
    if (base)
    {
        ExFreePoolWithTag(base, k_poolTag);
    }
}


static FnZwProtectVirtualMemory g_virtualProtect = nullptr;

static FnZwProtectVirtualMemory findVirtualProtect()
{
    // Windows 8.1 and above:
    const UNICODE_STRING name = RTL_CONSTANT_STRING(L"ZwProtectVirtualMemory");
    const FnZwProtectVirtualMemory fn = (FnZwProtectVirtualMemory)MmGetSystemRoutineAddress((UNICODE_STRING*)&name);
    if (fn)
    {
        return fn;
    }

    RTL_OSVERSIONINFOW ver;
    ver.dwOSVersionInfoSize = sizeof(ver);
    const NTSTATUS verStatus = RtlGetVersion(&ver);
    if (!NT_SUCCESS(verStatus))
    {
        return nullptr;
    }

    typedef enum
    {
        unknown,
        win7, // 6.1
        win8  // 6.2 (Windows 8.0)
    } WinVer;

    if (ver.dwMajorVersion != 6)
    {
        return nullptr;
    }

    WinVer winVer = unknown;
    switch (ver.dwMinorVersion)
    {
    case 1:
    {
        winVer = win7;
        break;
    }
    case 2:
    {
        winVer = win8;
        break;
    }
    default:
    {
        return nullptr;
    }
    }

    #pragma pack(push, 1)
    typedef union
    {
        unsigned char raw[32]; // With alignment
        struct
        {
            unsigned char movRaxRsp[3];          // 48 8B C4     | mov rax, rsp
            unsigned char cli;                   // FA           | cli
            unsigned int subRsp10h;              // 48 83 EC 10  | sub rsp, 10h
            unsigned char pushRax_0;             // 50           | push rax
            unsigned char pushfq;                // 9C           | pushfq
            unsigned short push10h;              // 6A 10        | push 10h
            unsigned char leaRaxOpcode[3];       // 48 8D 05     | -+
            unsigned int KiServiceLinkage;       // NN NN NN NN  | -+-> lea rax, KiServiceLinkage
            unsigned char pushRax_1;             // 50           | push rax
            unsigned char movEaxOpcode;          // 8B           | -+
            unsigned int syscallNumber;          // NN NN NN NN  | -+-> mov eax, SyscallNumber
            unsigned char jmpOpcode;             // E9           | -+
            unsigned int KiServiceLinkageOffset; // NN NN NN NN  | -+-> jmp KiServiceLinkage
        } layout;
    } ZwStubLayout64;
    #pragma pack(pop)

    #pragma pack(push, 1)
    typedef union
    {
        unsigned char raw[20];
        struct
        {
            unsigned char movEaxOpcode;   // B8           | -+
            unsigned int syscallNumber;   // NN NN NN NN  | -+-> mov eax, SyscallNumber
            unsigned char pushf;          // 9C           | pushf
            unsigned short push8h;        // 6A 08        | push 8
            unsigned char callOpcode;     // E8           | -+
            unsigned int KiSystemService; // NN NN NN NN  | -+-> call KiSystemService
            unsigned char retn8;          // C2 08 00     | retn 8
        } layout;
    } ZwStubLayout32;
    #pragma pack(pop)

#ifdef _AMD64_
    typedef ZwStubLayout64 ZwStubLayout;
    const UNICODE_STRING nearestKnownFuncName = RTL_CONSTANT_STRING(L"ZwIsProcessInJob"); // The same for Windows 7 and Windows 8.0
    const unsigned int k_syscallNumberWin7 = 0x4D;
    const unsigned int k_syscallNumberWin8 = 0x4E;
#else
    typedef ZwStubLayout32 ZwStubLayout;
    const UNICODE_STRING nearestKnownFuncNameWin7 = RTL_CONSTANT_STRING(L"ZwPropagationFailed"); // Windows 7
    const UNICODE_STRING nearestKnownFuncNameWin8 = RTL_CONSTANT_STRING(L"ZwPulseEvent"); // Windows 8.0
    const UNICODE_STRING nearestKnownFuncName = (winVer == win7)
        ? nearestKnownFuncNameWin7
        : nearestKnownFuncNameWin8;
    const unsigned int k_syscallNumberWin7 = 0xD7;
    const unsigned int k_syscallNumberWin8 = 0xC3;
#endif

    const ZwStubLayout* const nearestKnownFunc = MmGetSystemRoutineAddress((UNICODE_STRING*)&nearestKnownFuncName);
    if (!nearestKnownFunc)
    {
        return nullptr;
    }

    const ZwStubLayout* const candidate = (nearestKnownFunc + 1);

    const bool syscallMatches = (winVer == win7)
        ? (candidate->layout.syscallNumber == k_syscallNumberWin7)
        : (candidate->layout.syscallNumber == k_syscallNumberWin8);

    if (!syscallMatches)
    {
        return nullptr;
    }

    return (FnZwProtectVirtualMemory)candidate;
}

static bool initVirtualProtect()
{
    if (g_virtualProtect)
    {
        return true;
    }

    g_virtualProtect = findVirtualProtect();
    return g_virtualProtect != nullptr;
}


static bool isUserAddress(const void* const addr)
{
    return (size_t)addr <= (size_t)MM_HIGHEST_USER_ADDRESS;
}

static bool isKernelAddress(const void* const addr)
{
    return (size_t)addr >= (size_t)MM_SYSTEM_RANGE_START;
}

#ifdef _AMD64_
static bool isWow64Process(PEPROCESS process)
{
    return PsGetProcessWow64Process(process) != nullptr;
}
#endif

typedef struct
{
    const PMDL mdl;
    void* const addr;
} Mapping;

static Mapping makeWriteableMapping(void* const addr, unsigned long size)
{
    const PMDL mdl = IoAllocateMdl(addr, size, false, false, nullptr);
    if (!mdl)
    {
        const Mapping mapping = { .mdl = nullptr, .addr = nullptr };
        return mapping;
    }

    bool locked = false;
    __try
    {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        locked = true;

        void* const mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, nullptr, false, NormalPagePriority);
        if (mapped)
        {
            const NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
            if (!NT_SUCCESS(status))
            {
                MmUnmapLockedPages(mapped, mdl);
                MmUnlockPages(mdl);
                IoFreeMdl(mdl);

                const Mapping mapping = { .mdl = nullptr, .addr = nullptr };
                return mapping;
            }

            const Mapping mapping = { .mdl = mdl, .addr = mapped };
            return mapping;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        if (locked)
        {
            MmUnlockPages(mdl);
        }
    }

    IoFreeMdl(mdl);

    const Mapping mapping = { .mdl = nullptr, .addr = nullptr };
    return mapping;
}

static bool isMappingValid(const Mapping* const mapping)
{
    return mapping->addr != nullptr;
}

static void freeMapping(Mapping* const mapping)
{
    if (mapping->addr)
    {
        MmUnmapLockedPages(mapping->addr, mapping->mdl);
    }

    if (mapping->mdl)
    {
        MmUnlockPages(mapping->mdl);
        IoFreeMdl(mapping->mdl);
    }
}
#endif

static void* allocUser(void* base, size_t size, unsigned long protect)
{
    const NTSTATUS status = ZwAllocateVirtualMemory(
        NtCurrentProcess(),
        &base,
        base ? 12 : 0, // Align by page size ((1 << 12) == 4096)
        (SIZE_T*)&size,
        MEM_RESERVE | MEM_COMMIT,
        protect
    );

    if (!NT_SUCCESS(status))
    {
        return nullptr;
    }

    memset(base, 0, size);
    return base;
}

static unsigned int protectUser(void* addr, size_t size, unsigned int protect)
{
    unsigned long prevProtect = 0;
#if _USER_MODE
    const NTSTATUS status = ZwProtectVirtualMemory(NtCurrentProcess(), &addr, (SIZE_T*)&size, protect, &prevProtect);
#elif _KERNEL_MODE
    const NTSTATUS status = g_virtualProtect(NtCurrentProcess(), &addr, (SIZE_T*)&size, protect, &prevProtect);
#endif
    return NT_SUCCESS(status) ? prevProtect : 0;
}

static void freeUser(void* base)
{
    size_t regionSize = 0;
    ZwFreeVirtualMemory(NtCurrentProcess(), &base, (SIZE_T*)&regionSize, MEM_RELEASE);
}




#pragma pack(push, 1)
typedef struct
{
    unsigned char opcode; // E9          |
    unsigned long offset; // 44 33 22 11 | jmp rip+0x11223344 
} RelJump;

typedef struct
{
    unsigned short opcode; // FF 25       |
    unsigned long offset;  // 00 00 00 00 | jmp [rip+00h]
    unsigned long address; // 44 33 22 11 | <-- RIP is points to
} LongJump32;

typedef struct
{
    unsigned short opcode;      // FF 25                   |
    unsigned long offset;       // 00 00 00 00             | jmp [rip+00h]
    unsigned long long address; // 77 66 55 44 33 22 11 00 | <-- RIP is points to
} LongJump64;
#pragma pack(pop)

static RelJump makeRelJump(const void* from, const void* to)
{
    const unsigned long delta = (unsigned long)((size_t)to - ((size_t)from + sizeof(RelJump)));
    const RelJump jump =
    {
        .opcode = 0xE9,
        .offset = delta
    };
    return jump;
}

static LongJump32 makeLongJump32(const void* dest)
{
    const LongJump32 jump =
    {
        .opcode = 0x25FF,
        .offset = 0x00000000,
        .address = (unsigned long)((size_t)dest)
    };
    return jump;
}

static LongJump64 makeLongJump64(const void* dest)
{
    const LongJump64 jump =
    {
        .opcode = 0x25FF,
        .offset = 0x00000000,
        .address = ((size_t)dest)
    };
    return jump;
}


typedef struct
{
    unsigned char beginning[48];
    unsigned char original[32];
    void* fn;
    union
    {
        LongJump64 x64;
        LongJump32 x32;
    } intermediate;
    unsigned char affectedBytes;
    unsigned char indexInPage;
} HookData;

#if _KERNEL_MODE
typedef unsigned long long Magic;
static const Magic k_hookPageMagic = 0x1EE7C0DE;
#endif

typedef struct _HookPage
{
    struct Header
    {
#if _KERNEL_MODE
        Magic magic;
        unsigned long long pageBase;
#endif
        unsigned long long freeBitmap; // Each setted bit is a free cell
        struct _HookPage* prev;
        struct _HookPage* next;
    } header;
    HookData cells[(k_pageSize - sizeof(struct Header)) / sizeof(HookData)];
} HookPage;

static HookPage* g_pages = nullptr;

static HookPage* getHookPagesList()
{
    return g_pages;
}

static void setHookPagesList(const HookPage* const firstPage)
{
    g_pages = (HookPage*)firstPage;
}

#if _KERNEL_MODE
static bool isHookPage(const void* const page)
{
    const unsigned int k_allocationGranularity = 64 * 1024;
    if (!aligned((size_t)page, k_allocationGranularity))
    {
        return false;
    }

    const HookPage* const candidate = (const HookPage*)page;
    const PEPROCESS currentProcess = PsGetCurrentProcess();
    const Salt* const salt = getSalt();
    return ((candidate->header.magic ^ ((size_t)currentProcess) ^ salt->forMagic) == k_hookPageMagic)
        && ((candidate->header.pageBase ^ ((size_t)currentProcess) ^ salt->forBase) == (size_t)page);
}

static HookPage* lookupHookPagesList()
{
    void* baseAddress = nullptr;
    MEMORY_BASIC_INFORMATION info;
    SIZE_T returned = 0;
    while (NT_SUCCESS(ZwQueryVirtualMemory(NtCurrentProcess(), baseAddress, MemoryBasicInformation, &info, sizeof(info), &returned)))
    {
        const bool isThisHookPage = (info.Protect == PAGE_EXECUTE_READWRITE)
            && (info.RegionSize == k_pageSize)
            && (info.Type == MEM_PRIVATE)
            && ((info.State & MEM_COMMIT) == MEM_COMMIT)
            && isHookPage(info.BaseAddress);

        if (!isThisHookPage)
        {
            baseAddress = (void*)((size_t)info.BaseAddress + info.RegionSize);
            continue;
        }

        HookPage* hookPage = (HookPage*)info.BaseAddress;
        while (hookPage->header.prev)
        {
            hookPage = hookPage->header.prev;
        }

        return hookPage;
    }

    return nullptr;
}

static void resetHookPagesList()
{
    g_pages = nullptr;
}
#endif

static HookPage* allocHookPage(void* const preferred)
{
    HookPage* const page = (HookPage*)allocUser(preferred, sizeof(HookPage), PAGE_EXECUTE_READWRITE);
    if (!page)
    {
        return nullptr;
    }

#if _KERNEL_MODE
    const PEPROCESS currentProcess = PsGetCurrentProcess();
    const Salt* const salt = getSalt();
    page->header.magic = k_hookPageMagic ^ ((size_t)currentProcess) ^ salt->forMagic;
    page->header.pageBase = (size_t)page ^ ((size_t)currentProcess) ^ salt->forBase;
#endif

    const unsigned char k_cellsCount = sizeof(((const HookPage*)nullptr)->cells) / sizeof(*(((const HookPage*)nullptr)->cells));
    page->header.freeBitmap = (1ull << k_cellsCount) - 1ull;
    return page;
}

static void unlinkHookPage(HookPage* page);

static void freeHookPage(HookPage* const page)
{
    if (getHookPagesList() == page)
    {
        const HookPage* const next = page->header.next;
        setHookPagesList(next);
    }

    unlinkHookPage(page);
    
    freeUser(page);
}

static bool isHookPageEmpty(const HookPage* const page)
{
    const unsigned char k_cellsCount = sizeof(((const HookPage*)nullptr)->cells) / sizeof(*(((const HookPage*)nullptr)->cells));
    return page->header.freeBitmap == ((1ull << k_cellsCount) - 1ull);
}

static bool isHookPageFilled(const HookPage* const page)
{
    return page->header.freeBitmap == 0;
}

static bool isHookPageHasFreeCells(const HookPage* const page)
{
    return page->header.freeBitmap != 0;
}

static void insertHookPage(HookPage* page)
{
    HookPage* const pages = getHookPagesList();

    if (!pages)
    {
        page->header.prev = nullptr;
        page->header.next = nullptr;
        setHookPagesList(page);
        return;
    }

    for (HookPage* entry = pages; entry != nullptr; entry = entry->header.next)
    {
        HookPage* const next = entry->header.next;
        if ((page > entry) && (!next || (page < next)))
        {
            entry->header.next = page;
            page->header.prev = entry;
            page->header.next = next;
            if (next)
            {
                next->header.prev = page;
            }
            break;
        }
    }
}

static void unlinkHookPage(HookPage* page)
{
    HookPage* const prev = page->header.prev;
    HookPage* const next = page->header.next;
    if (prev)
    {
        prev->header.next = next;
    }

    if (next)
    {
        next->header.prev = prev;
    }

    page->header.prev = nullptr;
    page->header.next = nullptr;
}

static HookPage* findHookPage(void* addr)
{
    HookPage* const pages = getHookPagesList();
    for (HookPage* entry = pages; entry != nullptr; entry = entry->header.next)
    {
        if (!relativeJumpable(entry, addr))
        {
            if ((void*)entry < addr)
            {
                continue;
            }

            if (addr < (void*)entry)
            {
                return nullptr;
            }
        }

        const bool hasFreeCells = !isHookPageFilled(entry);
        if (hasFreeCells)
        {
            return entry;
        }
    }

    return nullptr;
}

static HookData* claimHookCell(HookPage* page)
{
    unsigned long firstFree = 0;
    const bool hasFreeCell = BitScanForward64(&firstFree, page->header.freeBitmap);
    if (!hasFreeCell)
    {
        return nullptr;
    }

    page->header.freeBitmap &= ~(1ull << firstFree);

    HookData* const cell = &page->cells[firstFree];
    cell->indexInPage = (unsigned char)firstFree;

    return cell;
}

static HookPage* releaseHookCell(HookData* data)
{
    HookPage* page = (HookPage*)((unsigned char*)data - offsetof(HookPage, cells[data->indexInPage]));
    page->header.freeBitmap |= (1ull << data->indexInPage);
    memset(data, 0, sizeof(*data));
    return page;
}




typedef WRK_SYSTEM_PROCESS_INFORMATION ProcInfo;
typedef WRK_SYSTEM_THREAD_INFORMATION ThreadInfo;


static ProcInfo* makeProcSnapshot()
{
    unsigned long len = 0;
    const NTSTATUS lengthStatus = ZwQuerySystemInformation(SystemProcessInformation, nullptr, 0, &len);
    if (lengthStatus != STATUS_INFO_LENGTH_MISMATCH)
    {
        return nullptr;
    }

    ProcInfo* info = nullptr;

    while (1)
    {
        const unsigned long k_additionalSize = 4096 * 5;
        len += k_additionalSize;
        info = allocUser(nullptr, len, PAGE_READWRITE);
        if (!info)
        {
            return nullptr;
        }

        const NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, info, len, &len);
        if (NT_SUCCESS(status))
        {
            break;
        }

        freeUser(info);

        if (status != STATUS_INFO_LENGTH_MISMATCH)
        {
            return nullptr;
        }
    }

    return info;
}

static void freeProcSnapshot(ProcInfo* snapshot)
{
    if (snapshot)
    {
        freeUser(snapshot);
    }
}



#if _KERNEL_MODE
static bool isCurrentThreadBelongsToCurrentProcess()
{
    const PETHREAD thread = PsGetCurrentThread();
    if (IoIsSystemThread(thread))
    {
        return false;
    }

    const bool attached = KeIsAttachedProcess();

    return !attached;
}
#endif



typedef enum
{
    stop,
    next
} EnumAction;

typedef enum
{
    failed,
    completed,
    stopped
} EnumStatus;

static EnumStatus forEachProcess(const ProcInfo* const snapshot, EnumAction(*const cb)(const ProcInfo* proc, void* arg), void* const arg)
{
    if (!snapshot)
    {
        return failed;
    }

    const ProcInfo* info = snapshot;

    EnumStatus enumStatus = completed;
    bool needToContinue = true;
    do {
        const EnumAction action = cb(info, arg);
        if (action == stop)
        {
            enumStatus = stopped;
            break;
        }

        needToContinue = info->NextEntryOffset != 0;
        if (needToContinue)
        {
            info = (const ProcInfo*)((const unsigned char*)info + info->NextEntryOffset);
        }
    } while (needToContinue);

    return enumStatus;
}

static EnumStatus forEachThread(const ProcInfo* const proc, EnumAction(*const cb)(const ProcInfo* proc, const ThreadInfo* thread, void* arg), void* const arg)
{
    if (!proc)
    {
        return failed;
    }

    EnumStatus enumStatus = completed;

    for (unsigned long i = 0; i < proc->NumberOfThreads; ++i)
    {
        const EnumAction action = cb(proc, &proc->Threads[i], arg);
        if (action == stop)
        {
            enumStatus = stopped;
            break;
        }
    }

    return enumStatus;
}


static EnumAction findCurrentProcessCallback(const ProcInfo* const proc, void* const arg)
{
    if (((size_t)proc->UniqueProcessId) == pid())
    {
        const ProcInfo** const currentProcess = (const ProcInfo**)arg;
        *currentProcess = proc;
        return stop;
    }

    return next;
}

static const ProcInfo* findCurrentProcess(const ProcInfo* const snapshot)
{
    ProcInfo* currentProcess = nullptr;
    const EnumStatus enumStatus = forEachProcess(snapshot, findCurrentProcessCallback, &currentProcess);
    if (enumStatus != stopped)
    {
        return nullptr;
    }

    return currentProcess;
}


#if _USER_MODE
static EnumAction beginHookSessionCallback(const ProcInfo* proc, const ThreadInfo* thread, void* arg)
{
    unused(proc, arg);

    ThreadInfo* const mutableThread = (ThreadInfo*)thread;
    mutableThread->u0.hThread = 0;

    if (((size_t)thread->ClientId.UniqueThread) == tid())
    {
        return next;
    }

    OBJECT_ATTRIBUTES attrs;
    InitializeObjectAttributes(&attrs, nullptr, 0, nullptr, nullptr);

    HANDLE hThread = nullptr;
    const NTSTATUS openStatus = ZwOpenThread(&hThread, THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, &attrs, &thread->ClientId);
    if (!NT_SUCCESS(openStatus) || !hThread)
    {
        return next;
    }

    unsigned long prevSuspendCount = 0;
    const NTSTATUS suspendStatus = ZwSuspendThread(hThread, &prevSuspendCount);
    if (!NT_SUCCESS(suspendStatus))
    {
        ZwClose(hThread);
        return next;
    }

    mutableThread->u0.hThread = hThread;
    return next;
}
#elif _KERNEL_MODE
typedef struct
{
    FnPspGetContextThreadInternal get;
    FnPspSetContextThreadInternal set;
} ContextFunctions;

static ContextFunctions lookupContextFunctions()
{
#ifdef _AMD64_
    /*
        Ps[Get/Set]ContextThread(PETHREAD:rcx, CONTEXT*:rdx, KPROCESSOR_MODE:r8):
          +00:      sub rsp, 38h                            | 48 83 EC 38
          +04:      mov r9b, r8b                            | 45 8A C8
          +07:      mov[b/l] [rsp+38h+arg5], 1              | C6 44 24 20 01 or C7 44 24 20 01 00 00 00
          +12/15:   call Psp[Get/Set]ContextThreadInternal  | E8 NN NN NN NN
          +17/20:   add rsp, 38h                            | 48 83 C4 38
          +21/24:   retn                                    | C3
    */

    #pragma pack(push, 1)
    typedef struct
    {
        unsigned int subRsp38h;
        unsigned char movR9bR8b[3];
        unsigned char movOpcode;
    } LayoutGeneric;
    #pragma pack(pop)

    #pragma pack(push, 1)
    typedef struct
    {
        unsigned int subRsp38h;
        unsigned char movR9bR8b[3];
        unsigned char movbArg5[5]; // C6 44 24 20 01 | movb [rsp+38h+arg5], 1
        unsigned char callOpcode;
        int calleeOffset;
        unsigned int addRsp38h;
        unsigned char retn;
    } LayoutMovb;
    #pragma pack(pop)

    #pragma pack(push, 1)
    typedef struct
    {
        unsigned int subRsp38h;
        unsigned char movR9bR8b[3];
        unsigned char movlArg5[8]; // C7 44 24 20 01 00 00 00 | movl [rsp+38h+arg5], 1
        unsigned char callOpcode;
        int calleeOffset;
        unsigned int addRsp38h;
        unsigned char retn;
    } LayoutMovl;
    #pragma pack(pop)
#else
    /*
        Ps[Get/Set]ContextThread(PETHREAD:[esp+4], CONTEXT*:[esp+8], KPROCESSOR_MODE:[esp+12]):
          +00:   mov edi, edi                            | 8B FF
          +02:   push ebp                                | 55
          +03:   mov ebp, esp                            | 8B EC
          +05:   push 1                                  | 6A 01
          +07:   push [ebp+arg2]                         | FF 75 10
          +10:   push [ebp+arg2]                         | FF 75 10
          +13:   push [ebp+arg1]                         | FF 75 0C
          +16:   push [ebp+arg0]                         | FF 75 08
          +19:   call Psp[Get/Set]ContextThreadInternal  | E8 NN NN NN NN
          +24:   pop ebp                                 | 5D
          +25:   retn 0Ch                                | C2 0C 00
    */

    #pragma pack(push, 1)
    typedef struct
    {
        unsigned short movEdiEdi;
        unsigned char pushEbp;
        unsigned short movEbpEsp;
        unsigned short push1; // Arg4
        unsigned char pushArg3[3];
        unsigned char pushArg2[3];
        unsigned char pushArg1[3];
        unsigned char pushArg0[3];
        unsigned char callOpcode;
        int calleeOffset;
        unsigned char popEbp;
        unsigned char retn;
        unsigned short argsSize;
    } Layout;
    #pragma pack(pop)
#endif

    const unsigned char k_callOpcode = 0xE8;

#ifdef _AMD64_
    const LayoutGeneric* const getLayoutGeneric = (const LayoutGeneric*)PsGetContextThread;
    const LayoutGeneric* const setLayoutGeneric = (const LayoutGeneric*)PsSetContextThread;
    
    const unsigned char k_movbOpcode = 0xC6;
    const unsigned char k_movlOpcode = 0xC7;

    const __unaligned int* getCalleeOffsetAddress = nullptr;
    const __unaligned int* setCalleeOffsetAddress = nullptr;

    if ((getLayoutGeneric->movOpcode == k_movlOpcode) && (setLayoutGeneric->movOpcode == k_movlOpcode))
    {
        const LayoutMovl* const getLayout = (const LayoutMovl*)PsGetContextThread;
        const LayoutMovl* const setLayout = (const LayoutMovl*)PsSetContextThread;
        if ((getLayout->callOpcode != k_callOpcode) || (setLayout->callOpcode != k_callOpcode))
        {
            const ContextFunctions functions = { .get = nullptr, .set = nullptr };
            return functions;
        }

        getCalleeOffsetAddress = &getLayout->calleeOffset;
        setCalleeOffsetAddress = &setLayout->calleeOffset;
    }
    else if ((getLayoutGeneric->movOpcode == k_movbOpcode) && (setLayoutGeneric->movOpcode == k_movbOpcode))
    {
        const LayoutMovb* const getLayout = (const LayoutMovb*)PsGetContextThread;
        const LayoutMovb* const setLayout = (const LayoutMovb*)PsSetContextThread;
        if ((getLayout->callOpcode != k_callOpcode) || (setLayout->callOpcode != k_callOpcode))
        {
            const ContextFunctions functions = { .get = nullptr, .set = nullptr };
            return functions;
        }

        getCalleeOffsetAddress = &getLayout->calleeOffset;
        setCalleeOffsetAddress = &setLayout->calleeOffset;
    }
    else
    {
        const ContextFunctions functions = { .get = nullptr, .set = nullptr };
        return functions;
    }
    
#else
    const Layout* const getLayout = (const Layout*)PsGetContextThread;
    const Layout* const setLayout = (const Layout*)PsSetContextThread;
    if ((getLayout->callOpcode != k_callOpcode) || (setLayout->callOpcode != k_callOpcode))
    {
        const ContextFunctions functions = { .get = nullptr, .set = nullptr };
        return functions;
    }

    const int* const getCalleeOffsetAddress = &getLayout->calleeOffset;
    const int* const setCalleeOffsetAddress = &setLayout->calleeOffset;
#endif

    const FnPspGetContextThreadInternal get = (FnPspGetContextThreadInternal)((const unsigned char*)(getCalleeOffsetAddress + 1) + *getCalleeOffsetAddress);
    const FnPspSetContextThreadInternal set = (FnPspSetContextThreadInternal)((const unsigned char*)(setCalleeOffsetAddress + 1) + *setCalleeOffsetAddress);

    const ContextFunctions functions = { .get = get, .set = set };

    return functions;
}


typedef unsigned int CrossThreadFlags;

typedef struct
{
    unsigned int offset;
    unsigned int flag;
} TerminatingFlag;

static TerminatingFlag parseThreadTerminatingFlag()
{
#ifdef _AMD64_
    /*
        PsIsThreadTerminating(PETHREAD:rcx):
          +00:   mov eax, [rcx+offset]  | 8B 81 NN NN NN NN
          +06:   and al, 1              | 24 01
          +08:   retn                   | C3
    */

    #pragma pack(push, 1)
    typedef struct
    {
        unsigned short movEaxOpcode;
        unsigned int offset;
        unsigned char andAlOpcode;
        unsigned char value;
        unsigned char retn;
    } Layout;
    #pragma pack(pop)

    const unsigned short k_movEaxOffsetOpcode = 0x818B;
    const unsigned char k_retnOpcode = 0xC3;

#else
    /*
        PsIsThreadTerminating(PETHREAD:[esp+4]):
          +00:   mov edi, edi             | 8B FF
          +02:   push ebp                 | 55
          +03:   mov ebp, esp             | 8B EC
          +05:   mov eax, [ebp+PETHREAD]  | 8B 45 08
          +08:   mov eax, [eax+offset]    | 8B 80 NN NN NN NN
          +14:   and al, 1                | 24 01
          +16:   pop ebp                  | 5D
          +17:   retn 4                   | C2 04 00
    */

    #pragma pack(push, 1)
    typedef struct
    {
        unsigned char beginning[8];
        unsigned short movEaxOpcode;
        unsigned int offset;
        unsigned char andAlOpcode;
        unsigned char value;
        unsigned char popEbp;
        unsigned char retn;
        unsigned short argsSize;
    } Layout;
    #pragma pack(pop)

    const unsigned short k_movEaxOffsetOpcode = 0x808B;
    const unsigned char k_retnOpcode = 0xC2;

#endif

    const unsigned char k_andAlOpcode = 0x24;

    const Layout* const layout = (const Layout*)PsIsThreadTerminating;
    if ((layout->movEaxOpcode != k_movEaxOffsetOpcode) || (layout->andAlOpcode != k_andAlOpcode) || (layout->retn != k_retnOpcode))
    {
        const TerminatingFlag flag = { .offset = 0, .flag = 0 };
        return flag;
    }

    const TerminatingFlag flag = { .offset = layout->offset, .flag = layout->value };
    return flag;
}

static void setThreadIsTerminating(PETHREAD thread, const TerminatingFlag* flag)
{
    *(CrossThreadFlags*)((unsigned char*)thread + flag->offset) |= (CrossThreadFlags)flag->flag;
}

static void resetThreadIsTerminating(PETHREAD thread, const TerminatingFlag* flag)
{
    *(CrossThreadFlags*)((unsigned char*)thread + flag->offset) &= ~(CrossThreadFlags)flag->flag;
}

static bool suspendCurrentProcess()
{
    const PEPROCESS currentProcess = PsGetCurrentProcess();

    if (!isCurrentThreadBelongsToCurrentProcess())
    {
        const NTSTATUS status = PsSuspendProcess(currentProcess);
        return NT_SUCCESS(status);
    }

    const TerminatingFlag flag = parseThreadTerminatingFlag();
    if (!flag.offset)
    {
        return false;
    }

    const PETHREAD currentThread = PsGetCurrentThread();
    setThreadIsTerminating(currentThread, &flag);
    const NTSTATUS status = PsSuspendProcess(currentProcess); // Exclude the current thread from suspension as all terminating threads will be skipped
    resetThreadIsTerminating(currentThread, &flag);

    return NT_SUCCESS(status);
}

static void resumeCurrentProcess()
{
    PsResumeProcess(PsGetCurrentProcess());
}

static EnumAction beginHookSessionCallback(const ProcInfo* proc, const ThreadInfo* thread, void* arg)
{
    unused(proc, arg);

    ThreadInfo* const mutableThread = (ThreadInfo*)thread;
    mutableThread->u0.thread = 0;

    if (((size_t)thread->ClientId.UniqueThread) == tid())
    {
        return next;
    }

    const NTSTATUS lookupStatus = PsLookupThreadByThreadId(thread->ClientId.UniqueThread, &mutableThread->u0.thread);
    if (!NT_SUCCESS(lookupStatus))
    {
        return next;
    }

    return next;
}
#endif


static bool beginHookSession(ProcInfo* process)
{
    acquireGlobalLock();

#if _KERNEL_MODE
    initSalt();

    const bool suspendStatus = suspendCurrentProcess();
    if (!suspendStatus)
    {
        return false;
    }

    HookPage* const firstPage = lookupHookPagesList();
    setHookPagesList(firstPage);
#endif

    const EnumStatus enumStatus = forEachThread(process, beginHookSessionCallback, nullptr);
    return enumStatus != failed;
}

#if _KERNEL_MODE
static void beginKernelHookSession()
{
    initSalt();
    acquireGlobalLock();
}
#endif

static EnumAction endHookSessionCallback(const ProcInfo* proc, const ThreadInfo* thread, void* arg)
{
    unused(proc, arg);

    ThreadInfo* const mutableThread = (ThreadInfo*)thread;

#if _USER_MODE
    if (!mutableThread->u0.hThread)
    {
        return next;
    }

    unsigned long suspendCount = 0;
    ZwResumeThread(mutableThread->u0.hThread, &suspendCount);
    ZwClose(mutableThread->u0.hThread);
    mutableThread->u0.hThread = 0;
#elif _KERNEL_MODE
    if (!mutableThread->u0.thread)
    {
        return next;
    }

    ObDereferenceObject(mutableThread->u0.thread);
    mutableThread->u0.thread = nullptr;
#endif

    return next;
}

static bool endHookSession(ProcInfo* process)
{
    ZwFlushInstructionCache(NtCurrentProcess(), 0, 0);
    const EnumStatus enumStatus = forEachThread(process, endHookSessionCallback, nullptr);

#if _KERNEL_MODE
    resumeCurrentProcess();
    resetHookPagesList();
#endif

    releaseGlobalLock();
    return enumStatus != failed;
}

#if _KERNEL_MODE
static void endKernelHookSession()
{
    ZwFlushInstructionCache(NtCurrentProcess(), 0, 0);
    releaseGlobalLock();
}
#endif



static void* findPageForRelativeJump(const void* addr)
{
    const unsigned long k_granularity = 64 * 1024;

    unsigned char* base = (unsigned char*)alignUp((size_t)addr, k_granularity);

    MEMORY_BASIC_INFORMATION info;
    SIZE_T resLen = 0;

    // Forward:
    while (NT_SUCCESS(ZwQueryVirtualMemory(NtCurrentProcess(), (void*)base, MemoryBasicInformation, &info, sizeof(info), &resLen)))
    {
        if (info.State == MEM_FREE)
        {
            return base;
        }

        base += info.RegionSize;
        base = (unsigned char*)alignUp((size_t)base, k_granularity);

        if (!relativeJumpable(base, addr))
        {
            break;
        }
    }

    base = (unsigned char*)(alignDown((size_t)addr, k_granularity) - 1);

    // Backward:
    while (NT_SUCCESS(ZwQueryVirtualMemory(NtCurrentProcess(), (void*)base, MemoryBasicInformation, &info, sizeof(info), &resLen)))
    {
        if (info.State == MEM_FREE)
        {
            return base;
        }

        base = ((unsigned char*)info.BaseAddress) - 1;
        
        if (!relativeJumpable(base, addr))
        {
            break;
        }
    }

    return nullptr; // Not found
}





static void relocate(void* const addr, ssize_t relocationDelta, unsigned char patchSizeInBits)
{
    switch (patchSizeInBits)
    {
    case sizeof(char) * 8:
    {
        *(char*)(addr) -= (char)relocationDelta;
        break;
    }
    case sizeof(short) * 8:
    {
        *(short*)(addr) -= (short)relocationDelta;
        break;
    }
    case sizeof(int) * 8:
    {
        *(int*)(addr) -= (int)relocationDelta;
        break;
    }
    case sizeof(long long) * 8:
    {
        *(long long*)(addr) -= (long long)relocationDelta;
        break;
    }
    }
}

static bool relocatable(unsigned char relocatableBits, size_t length)
{
    const size_t availableRange = (size_t)(((1ull << relocatableBits) - 1ul) / 2);
    return length < availableRange;
}

typedef enum
{
    x32,
    x64,
    native = (sizeof(size_t) == sizeof(unsigned int)) ? x32 : x64
} Arch;

static unsigned char relocateBeginning(Arch arch, const void* from, void* to, unsigned int bytesToRelocate)
{
    ZydisDecoder decoder;
    if (arch == x64)
    {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    }
    else
    {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);
    }

    unsigned char relocatedBytes = 0;

    const unsigned char* srcInstr = (const unsigned char*)from;
    ZydisDecodedInstruction instr;
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, srcInstr, 16, &instr)))
    {
        unsigned char* const destInstr = (unsigned char*)to + (srcInstr - (const unsigned char*)from);
        memcpy(destInstr, srcInstr, instr.length);

        if (instr.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
        {
            const ssize_t direction = delta(srcInstr, destInstr);
            const size_t length = direction >= 0 ? ((size_t)direction) : ((size_t)-direction);

            if (instr.raw.disp.offset)
            {
                if (!relocatable(instr.raw.disp.size, length))
                {
                    return 0; // It is impossible to relocate this instruction
                }

                relocate(destInstr + instr.raw.disp.offset, direction, instr.raw.disp.size);
            }

            for (unsigned char i = 0; i < 2; ++i)
            {
                if (instr.raw.imm[i].offset && instr.raw.imm[i].is_relative)
                {
                    if (!relocatable(instr.raw.imm[i].size, length))
                    {
                        return 0; // It is impossible to relocate this instruction
                    }

                    relocate(destInstr + instr.raw.imm[i].offset, direction, instr.raw.imm[i].size);
                }
            }
        }

        srcInstr += instr.length;
        relocatedBytes += instr.length;
        if (relocatedBytes >= bytesToRelocate)
        {
            break;
        }
    }

    return relocatedBytes;
}


static bool writeToUser(void* const dest, const void* const src, unsigned long size)
{
    const unsigned int prevProtect = protectUser(dest, size, PAGE_EXECUTE_READWRITE);
    if (!prevProtect)
    {
        return false;
    }

    memcpy(dest, src, size);

    protectUser(dest, size, prevProtect);
    return true;
}

#if _KERNEL_MODE
static bool writeToKernel(void* const dest, const void* const src, const unsigned long size)
{
    Mapping mapping = makeWriteableMapping(dest, size);
    if (!isMappingValid(&mapping))
    {
        return false;
    }

    memcpy(mapping.addr, src, size);

    freeMapping(&mapping);
    return true;
}
#endif

static bool writeToReadonly(void* const dest, const void* const src, const unsigned long size)
{
#if _USER_MODE
    const bool status = writeToUser(dest, src, size);
#elif _KERNEL_MODE
    const bool status = isKernelAddress(dest)
        ? writeToKernel(dest, src, size)
        : writeToUser(dest, src, size);
#endif

    return status;
}


static void writeJumpToContinuation(const Arch arch, void* const from, const void* const to)
{
    if (relativeJumpable(from, to))
    {
        *(RelJump*)(from) = makeRelJump(from, to);
    }
    else
    {
        if (arch == x64)
        {
            *(LongJump64*)(from) = makeLongJump64(to);
        }
        else
        {
            *(LongJump32*)(from) = makeLongJump32(to);
        }
    }
}

static bool applyHook(const Arch arch, HookData* const hook, void* const fn, const void* const handler)
{
    if (!hook || !fn)
    {
        return false;
    }

    const bool needLongJump = k_forceLongJumps || !relativeJumpable(fn, handler);
    const bool intermediateJumpAppliable = k_enableIntermediateJumps && needLongJump && relativeJumpable(fn, &hook->intermediate);

    if (needLongJump && !intermediateJumpAppliable)
    {
        // Absolute jump:
        if (arch == x64)
        {
            const unsigned char relocatedBytes = relocateBeginning(arch, fn, hook->beginning, sizeof(LongJump64));
            if (!relocatedBytes)
            {
                return false;
            }

            memcpy(hook->original, fn, relocatedBytes);

            const LongJump64 jump = makeLongJump64(handler);
            const bool status = writeToReadonly(fn, &jump, sizeof(jump));
            if (!status)
            {
                return false;
            }

            const void* const beginningContinuation = (const unsigned char*)fn + relocatedBytes;
            writeJumpToContinuation(x64, &hook->beginning[relocatedBytes], beginningContinuation);

            hook->affectedBytes = relocatedBytes;
        }
        else
        {
            const unsigned char relocatedBytes = relocateBeginning(arch, fn, hook->beginning, sizeof(LongJump32));
            if (!relocatedBytes)
            {
                return false;
            }

            memcpy(hook->original, fn, relocatedBytes);

            const LongJump32 jump = makeLongJump32(handler);
            const bool status = writeToReadonly(fn, &jump, sizeof(jump));
            if (!status)
            {
                return false;
            }

            const void* const beginningContinuation = (const unsigned char*)fn + relocatedBytes;
            writeJumpToContinuation(x32, &hook->beginning[relocatedBytes], beginningContinuation);

            hook->affectedBytes = relocatedBytes;
        }
    }
    else
    {
        // Relative jump:
        if (intermediateJumpAppliable)
        {
            const unsigned char relocatedBytes = relocateBeginning(arch, fn, hook->beginning, sizeof(RelJump));
            if (!relocatedBytes)
            {
                return false;
            }

            if (arch == x64)
            {
                hook->intermediate.x64 = makeLongJump64(handler);
            }
            else
            {
                hook->intermediate.x32 = makeLongJump32(handler);
            }

            memcpy(hook->original, fn, relocatedBytes);

            const RelJump jump = makeRelJump(fn, &hook->intermediate);
            const bool status = writeToReadonly(fn, &jump, sizeof(jump));
            if (!status)
            {
                return false;
            }

            const void* const beginningContinuation = (const unsigned char*)fn + relocatedBytes;
            writeJumpToContinuation(arch, &hook->beginning[relocatedBytes], beginningContinuation);

            hook->affectedBytes = relocatedBytes;
        }
        else
        {
            const unsigned char relocatedBytes = relocateBeginning(arch, fn, hook->beginning, sizeof(RelJump));
            if (!relocatedBytes)
            {
                return false;
            }

            memcpy(hook->original, fn, relocatedBytes);

            const RelJump jump = makeRelJump(fn, handler);
            const bool status = writeToReadonly(fn, &jump, sizeof(jump));
            if (!status)
            {
                return false;
            }

            const void* const beginningContinuation = (const unsigned char*)fn + relocatedBytes;
            writeJumpToContinuation(arch, &hook->beginning[relocatedBytes], beginningContinuation);

            hook->affectedBytes = relocatedBytes;
        }
    }

    hook->fn = fn;
    return true;
}


#if _USER_MODE
static void* setHook(Arch arch, void* fn, const void* handler)
{
    HookPage* const existingPage = findHookPage(fn);
    if (existingPage)
    {
        HookData* const freeHookCell = claimHookCell(existingPage);
        const bool hookStatus = applyHook(arch, freeHookCell, fn, handler);
        if (hookStatus)
        {
            return freeHookCell->beginning;
        }
        releaseHookCell(freeHookCell);
        return nullptr;
    }

    void* const nearestFreePage = findPageForRelativeJump(fn); // Nullable
    HookPage* const newPage = allocHookPage(nearestFreePage);
    if (!newPage)
    {
        return nullptr;
    }
    
    HookData* const freeHookCell = claimHookCell(newPage);
    const bool hookStatus = applyHook(arch, freeHookCell, fn, handler);
    if (!hookStatus)
    {
        releaseHookCell(freeHookCell);
        freeHookPage(newPage);
        return nullptr;
    }

    insertHookPage(newPage);

    return freeHookCell->beginning;
}
#else
static void* setHook(Arch arch, void* fn, const void* handler)
{
    if (isUserAddress(fn))
    {
        HookPage* const existingPage = findHookPage(fn);
        if (existingPage)
        {
            HookData* const freeHookCell = claimHookCell(existingPage);
            const bool hookStatus = applyHook(arch, freeHookCell, fn, handler);
            if (hookStatus)
            {
                return freeHookCell->beginning;
            }
            releaseHookCell(freeHookCell);
        }

        void* const nearestFreePage = findPageForRelativeJump(fn); // Nullable
        HookPage* const newPage = allocHookPage(nearestFreePage);
        if (!newPage)
        {
            return nullptr;
        }

        HookData* const freeHookCell = claimHookCell(newPage);
        const bool hookStatus = applyHook(arch, freeHookCell, fn, handler);
        if (!hookStatus)
        {
            releaseHookCell(freeHookCell);
            freeHookPage(newPage);
            return nullptr;
        }

        insertHookPage(newPage);

        return freeHookCell->beginning;
    }
    else
    {
        HookData* const hookData = (HookData*)allocKernel(sizeof(HookData));
        const bool hookStatus = applyHook(arch, hookData, fn, handler);
        if (!hookStatus)
        {
            freeKernel(hookData);
            return nullptr;
        }

        return hookData->beginning;
    }
}
#endif

typedef enum
{
    fixForHook,
    fixForUnhook
} FixupType;

typedef union
{
    Hook* hooks;
    Unhook* unhooks;
} HooksUnhooks;

static size_t calcNewInstructionPointer(const HooksUnhooks hooksUnhooks, const size_t count, size_t ip, const FixupType type)
{
    bool needToFix = false;
    switch (type)
    {
    case fixForHook:
    {
        for (const Hook* hook = hooksUnhooks.hooks; hook != &hooksUnhooks.hooks[count]; ++hook)
        {
            if (!hook->original)
            {
                continue;
            }

            const HookData* const hookData = (HookData*)((unsigned char*)hook->original - offsetof(HookData, beginning));
            if ((ip >= (size_t)hookData->fn) && (ip < ((size_t)hookData->fn + hookData->affectedBytes)))
            {
                needToFix = true;
                const size_t offset = (size_t)ip - (size_t)hookData->fn;
                ip = (size_t)&hookData->beginning[offset];
            }
        }
        break;
    }
    case fixForUnhook:
    {
        for (const Unhook* unhook = hooksUnhooks.unhooks; unhook != &hooksUnhooks.unhooks[count]; ++unhook)
        {
            if (!unhook->original)
            {
                continue;
            }

            const HookData* const hookData = (HookData*)((unsigned char*)unhook->original - offsetof(HookData, beginning));
            if ((ip >= (size_t)hookData->beginning) && (ip < ((size_t)hookData->beginning + hookData->affectedBytes)))
            {
                needToFix = true;
                const size_t offset = (size_t)ip - (size_t)hookData->beginning;
                ip = (size_t)hookData->fn + offset;
            }
        }
        break;
    }
    }

    return ip;
}



#if _USER_MODE
static void fixupContexts(const ProcInfo* const proc, const HooksUnhooks hooksUnhooks, const size_t count, const FixupType type)
{
    const unsigned int currentTid = tid();

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;

    for (const ThreadInfo* thread = proc->Threads; thread != &proc->Threads[proc->NumberOfThreads]; ++thread)
    {
        if ((size_t)thread->ClientId.UniqueThread == currentTid)
        {
            continue;
        }

#ifdef _AMD64_
        size_t* const currentIp = (size_t*)&ctx.Rip;
#else
        size_t* const currentIp = (size_t*)&ctx.Eip;
#endif

        *currentIp = 0;

        const NTSTATUS getCtxStatus = ZwGetContextThread(thread->u0.hThread, &ctx);
        if (!NT_SUCCESS(getCtxStatus))
        {
            continue;
        }

        const size_t newIp = calcNewInstructionPointer(hooksUnhooks, count, *currentIp, type);
        const bool needToFix = (newIp != *currentIp);

        if (needToFix)
        {
            *currentIp = newIp;
            ZwSetContextThread(thread->u0.hThread, &ctx);
        }
    }
}
#elif _KERNEL_MODE
#ifdef _AMD64_

/* These structs and defines are from winnt.h which we can't include as it causes redeclaration conflicts with ntifs.h */

#define WOW64_SIZE_OF_80387_REGISTERS      80

#define WOW64_MAXIMUM_SUPPORTED_EXTENSION     512

typedef struct _WOW64_FLOATING_SAVE_AREA {
    DWORD   ControlWord;
    DWORD   StatusWord;
    DWORD   TagWord;
    DWORD   ErrorOffset;
    DWORD   ErrorSelector;
    DWORD   DataOffset;
    DWORD   DataSelector;
    BYTE    RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
    DWORD   Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA;

typedef WOW64_FLOATING_SAVE_AREA* PWOW64_FLOATING_SAVE_AREA;

#include "pshpack4.h"

//
// Context Frame
//
//  This frame has a several purposes: 1) it is used as an argument to
//  NtContinue, 2) is is used to constuct a call frame for APC delivery,
//  and 3) it is used in the user level thread creation routines.
//
//  The layout of the record conforms to a standard call frame.
//

typedef struct _WOW64_CONTEXT {

    //
    // The flags values within this flag control the contents of
    // a CONTEXT record.
    //
    // If the context record is used as an input parameter, then
    // for each portion of the context record controlled by a flag
    // whose value is set, it is assumed that that portion of the
    // context record contains valid context. If the context record
    // is being used to modify a threads context, then only that
    // portion of the threads context will be modified.
    //
    // If the context record is used as an IN OUT parameter to capture
    // the context of a thread, then only those portions of the thread's
    // context corresponding to set flags will be returned.
    //
    // The context record is never used as an OUT only parameter.
    //

    DWORD ContextFlags;

    //
    // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
    // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
    // included in CONTEXT_FULL.
    //

    DWORD   Dr0;
    DWORD   Dr1;
    DWORD   Dr2;
    DWORD   Dr3;
    DWORD   Dr6;
    DWORD   Dr7;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
    //

    WOW64_FLOATING_SAVE_AREA FloatSave;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_SEGMENTS.
    //

    DWORD   SegGs;
    DWORD   SegFs;
    DWORD   SegEs;
    DWORD   SegDs;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_INTEGER.
    //

    DWORD   Edi;
    DWORD   Esi;
    DWORD   Ebx;
    DWORD   Edx;
    DWORD   Ecx;
    DWORD   Eax;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_CONTROL.
    //

    DWORD   Ebp;
    DWORD   Eip;
    DWORD   SegCs;              // MUST BE SANITIZED
    DWORD   EFlags;             // MUST BE SANITIZED
    DWORD   Esp;
    DWORD   SegSs;

    //
    // This section is specified/returned if the ContextFlags word
    // contains the flag CONTEXT_EXTENDED_REGISTERS.
    // The format and contexts are processor specific
    //

    BYTE    ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];

} WOW64_CONTEXT;

typedef WOW64_CONTEXT* PWOW64_CONTEXT;

#include "poppack.h"

/* End of types from winnt.h */

static void fixupWow64Contexts(const ProcInfo* const proc, const HooksUnhooks hooksUnhooks, const size_t hooksCount, const FixupType type)
{
    WOW64_CONTEXT* const ctx = (WOW64_CONTEXT*)allocUser(nullptr, sizeof(WOW64_CONTEXT), PAGE_READWRITE);
    if (!ctx)
    {
        return;
    }

    // These are from winnt.h (WOW64_CONTEXT_i386, WOW64_CONTEXT_CONTROL):
    const unsigned int k_wow64Context386 = 0x00010000;
    const unsigned int k_wow64ContextControl = (k_wow64Context386 | 0x00000001L); // SS:SP, CS:IP, FLAGS, BP

    ctx->ContextFlags = k_wow64ContextControl;

    const unsigned int currentTid = tid();

    for (const ThreadInfo* thread = proc->Threads; thread != &proc->Threads[proc->NumberOfThreads]; ++thread)
    {
        if ((size_t)thread->ClientId.UniqueThread == currentTid)
        {
            continue;
        }

        HANDLE hThread = nullptr;
        const NTSTATUS openStatus = ObOpenObjectByPointer(thread->u0.thread, OBJ_KERNEL_HANDLE, nullptr, THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, *PsThreadType, KernelMode, &hThread);
        if (!NT_SUCCESS(openStatus))
        {
            continue;
        }

        unsigned long returned = 0;
        const NTSTATUS getCtxStatus = ZwQueryInformationThread(hThread, ThreadWow64Context, ctx, sizeof(*ctx), &returned);
        if (!NT_SUCCESS(getCtxStatus))
        {
            ZwClose(hThread);
            continue;
        }

        const size_t newIp = calcNewInstructionPointer(hooksUnhooks, hooksCount, ctx->Eip, type);
        const bool needToFix = (newIp != ctx->Eip);

        if (needToFix)
        {
            ctx->Eip = (unsigned int)newIp;
            ZwSetInformationThread(hThread, ThreadWow64Context, ctx, sizeof(*ctx));
        }

        ZwClose(hThread);
    }

    freeUser(ctx);
}
#endif // _AMD64_

static void fixupNativeContexts(const ProcInfo* const proc, const HooksUnhooks hooksUnhooks, const size_t hooksCount, const FixupType type)
{
    const ContextFunctions fnCtx = lookupContextFunctions();
    if (!fnCtx.get || !fnCtx.set)
    {
        return;
    }

    const unsigned int currentTid = tid();

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;

    for (const ThreadInfo* thread = proc->Threads; thread != &proc->Threads[proc->NumberOfThreads]; ++thread)
    {
        if ((size_t)thread->ClientId.UniqueThread == currentTid)
        {
            continue;
        }

#ifdef _AMD64_
        size_t* const currentIp = (size_t*)&ctx.Rip;
#else
        size_t* const currentIp = (size_t*)&ctx.Eip;
#endif

        *currentIp = 0;

        const NTSTATUS getCtxStatus = fnCtx.get(thread->u0.thread, &ctx, KernelMode, UserMode, false);
        if (!NT_SUCCESS(getCtxStatus))
        {
            continue;
        }

        const size_t newIp = calcNewInstructionPointer(hooksUnhooks, hooksCount, *currentIp, type);
        const bool needToFix = (newIp != *currentIp);

        if (needToFix)
        {
            *currentIp = newIp;
            fnCtx.set(thread->u0.thread, &ctx, KernelMode, UserMode, false);
        }
    }
}

static void fixupContexts(const ProcInfo* const proc, const HooksUnhooks hooksUnhooks, const size_t hooksCount, const FixupType type)
{
#ifdef _AMD64_
    if (isWow64Process(PsGetCurrentProcess()))
    {
        fixupWow64Contexts(proc, hooksUnhooks, hooksCount, type);
    }
    else
    {
        fixupNativeContexts(proc, hooksUnhooks, hooksCount, type);
    }
#else
    fixupNativeContexts(proc, hooksUnhooks, hooksCount, type);
#endif

    ZwYieldExecution();
}
#endif // _KERNEL_MODE



static size_t applyHooks(Arch arch, Hook* hooks, size_t count)
{
    size_t hookedCount = 0;

    for (size_t i = 0; i < count; ++i)
    {
        Hook* const hook = &hooks[i];
        hook->original = setHook(arch, hook->fn, hook->handler);
        if (hook->original)
        {
#if _KERNEL_MODE
            _mm_clflush(hook->fn);
#endif
            ++hookedCount;
        }
    }

    _mm_sfence();

    return hookedCount;
}

#if _USER_MODE
size_t multihook(Hook* hooks, size_t count)
{
    if (!hooks || !count)
    {
        return 0;
    }

    for (size_t i = 0; i < count; ++i)
    {
        hooks[i].original = nullptr;
    }

    ProcInfo* const snapshot = makeProcSnapshot();
    if (!snapshot)
    {
        return 0;
    }

    ProcInfo* const currentProcess = (ProcInfo*)findCurrentProcess(snapshot);
    if (!currentProcess)
    {
        return 0;
    }

    const bool beginStatus = beginHookSession(currentProcess);
    if (!beginStatus)
    {
        freeProcSnapshot(snapshot);
        return 0;
    }

    const size_t hookedCount = applyHooks(native, hooks, count);

    const HooksUnhooks hooksUnhooks = { .hooks = hooks };
    fixupContexts(currentProcess, hooksUnhooks, count, fixForHook);

    endHookSession(currentProcess);

    freeProcSnapshot(snapshot);
    return hookedCount;
}
#else
size_t multihook(Hook* hooks, size_t count)
{
    if (!hooks || !count)
    {
        return 0;
    }

    bool hasUserHooks = false;
    for (size_t i = 0; i < count; ++i)
    {
        hasUserHooks |= isUserAddress(hooks[i].fn);
        hooks[i].original = nullptr;
    }

    if (hasUserHooks)
    {
        const bool virtualProtectStatus = initVirtualProtect();
        if (!virtualProtectStatus)
        {
            return 0;
        }

        ProcInfo* const snapshot = makeProcSnapshot();
        if (!snapshot)
        {
            return 0;
        }

        ProcInfo* const currentProcess = (ProcInfo*)findCurrentProcess(snapshot);
        if (!currentProcess)
        {
            return 0;
        }

        const bool beginStatus = beginHookSession(currentProcess);
        if (!beginStatus)
        {
            freeProcSnapshot(snapshot);
            return 0;
        }

#ifdef _AMD64_
        const Arch k_arch = isWow64Process(PsGetCurrentProcess()) ? x32 : x64;
#else
        const Arch k_arch = x32;
#endif

        const size_t hookedCount = applyHooks(k_arch, hooks, count);

        const HooksUnhooks hooksUnhooks = { .hooks = hooks };
        fixupContexts(currentProcess, hooksUnhooks, count, fixForHook);

        endHookSession(currentProcess);

        freeProcSnapshot(snapshot);
        return hookedCount;
    }
    else
    {
        beginKernelHookSession();
        const size_t hookedCount = applyHooks(native, hooks, count);
        endKernelHookSession();

        return hookedCount;
    }
}
#endif

void* hook(void* fn, const void* handler)
{
    if (!fn)
    {
        return nullptr;
    }

    Hook hook =
    {
        .fn = fn,
        .handler = handler,
        .original = nullptr
    };
    
    multihook(&hook, 1);
    
    return hook.original;
}

static bool performUnhook(HookData* hook)
{
    if (!hook)
    {
        return false;
    }

    const bool writeStatus = writeToReadonly(hook->fn, hook->original, hook->affectedBytes);
    if (!writeStatus)
    {
        return false;
    }

#if _USER_MODE
    HookPage* const page = releaseHookCell(hook);
    if (isHookPageEmpty(page))
    {
        freeHookPage(page);
    }
#elif _KERNEL_MODE
    if (isKernelAddress(hook))
    {
        freeKernel(hook);
    }
    else
    {
        HookPage* const page = releaseHookCell(hook);
        if (isHookPageEmpty(page))
        {
            freeHookPage(page);
        }
    }
#endif

    return true;
}

#if _USER_MODE
size_t multiunhook(Unhook* originals, size_t count)
{
    if (!originals || !count)
    {
        return 0;
    }

    ProcInfo* const snapshot = makeProcSnapshot();
    if (!snapshot)
    {
        return 0;
    }

    ProcInfo* const currentProcess = (ProcInfo*)findCurrentProcess(snapshot);
    if (!currentProcess)
    {
        return 0;
    }

    const bool beginStatus = beginHookSession(currentProcess);
    if (!beginStatus)
    {
        freeProcSnapshot(snapshot);
        return 0;
    }

    size_t unhookedCount = 0;
   
    const HooksUnhooks hooksUnhooks = { .unhooks = originals };
    fixupContexts(currentProcess, hooksUnhooks, count, fixForUnhook);

    for (size_t i = 0; i < count; ++i)
    {
        if (!originals[i].original)
        {
            continue;
        }

        HookData* const hook = (HookData*)((unsigned char*)originals[i].original - offsetof(HookData, beginning));

        const bool status = performUnhook(hook);
        if (status)
        {
            originals[i].original = nullptr;
            ++unhookedCount;
        }
    }

    _mm_sfence();

    endHookSession(currentProcess);

    freeProcSnapshot(snapshot);

    return unhookedCount;
}
#elif _KERNEL_MODE
size_t multiunhook(Unhook* originals, size_t count)
{
    if (!originals || !count)
    {
        return 0;
    }

    bool hasUserHooks = false;
    for (size_t i = 0; i < count; ++i)
    {
        hasUserHooks |= isUserAddress(originals[i].original);
    }

    size_t unhookedCount = 0;

    if (hasUserHooks)
    {
        const bool virtualProtectStatus = initVirtualProtect();
        if (!virtualProtectStatus)
        {
            return 0;
        }

        ProcInfo* const snapshot = makeProcSnapshot();
        if (!snapshot)
        {
            return 0;
        }

        ProcInfo* const currentProcess = (ProcInfo*)findCurrentProcess(snapshot);
        if (!currentProcess)
        {
            return 0;
        }

        const bool beginStatus = beginHookSession(currentProcess);
        if (!beginStatus)
        {
            freeProcSnapshot(snapshot);
            return 0;
        }

        const HooksUnhooks hooksUnhooks = { .unhooks = originals };
        fixupContexts(currentProcess, hooksUnhooks, count, fixForUnhook);

        for (size_t i = 0; i < count; ++i)
        {
            if (!originals[i].original)
            {
                continue;
            }

            HookData* const hook = (HookData*)((unsigned char*)originals[i].original - offsetof(HookData, beginning));
            const void* const fn = hook->fn;

            const bool status = performUnhook(hook);
            if (status)
            {
                _mm_clflush(fn);
                originals[i].original = nullptr;
                ++unhookedCount;
            }
        }

        _mm_sfence();

        endHookSession(currentProcess);

        freeProcSnapshot(snapshot);
    }
    else
    {
        beginKernelHookSession();

        for (size_t i = 0; i < count; ++i)
        {
            if (!originals[i].original)
            {
                continue;
            }

            HookData* const hook = (HookData*)((unsigned char*)originals[i].original - offsetof(HookData, beginning));
            const void* const fn = hook->fn;

            const bool status = performUnhook(hook);
            if (status)
            {
                _mm_clflush(fn);
                originals[i].original = nullptr;
                ++unhookedCount;
            }
        }

        endKernelHookSession();

        _mm_sfence();
    }

    return unhookedCount;
}
#endif

size_t unhook(void* original)
{
    Unhook fn = { .original = original };
    return multiunhook(&fn, 1);
}
