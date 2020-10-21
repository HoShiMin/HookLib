#ifdef _KERNEL_MODE
#include <ntddk.h>
#include <intrin.h>
#else
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
#pragma comment(lib, "Zydis.lib")

#if !defined offsetof
#define offsetof(s, m) ((size_t)& (((s*)0)->m))
#endif

#ifndef _KERNEL_MODE
#define NtCurrentProcess() ((HANDLE)-1)
#define NtCurrentThread()  ((HANDLE)-2)

static inline void* __teb()
{
#ifdef _AMD64_
    return (void*)__readgsqword(0x30);
#else
    return (void*)__readfsdword(0x18);
#endif
}

static inline void* __peb()
{
#ifdef _AMD64_
    return (void*)__readgsqword(0x60);
#else
    return (void*)__readfsdword(0x30);
#endif
}

static inline unsigned int __pid()
{
    // TEB::ClientId.UniqueProcessId:
#ifdef _AMD64_
    return *(unsigned int*)((unsigned char*)__teb() + 0x40);
#else
    return *(unsigned int*)((unsigned char*)__teb() + 0x20);
#endif
}

static inline unsigned int __tid()
{
    // TEB::ClientId.UniqueThreadId:
#ifdef _AMD64_
    return *(unsigned int*)((unsigned char*)__teb() + 0x48);
#else
    return *(unsigned int*)((unsigned char*)__teb() + 0x24);
#endif
}

// 'WRK' is the custom prefix to bypass these structs redeclaration error:

typedef struct _WRK_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
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
} WRK_SYSTEM_THREAD_INFORMATION, *PWRK_SYSTEM_THREAD_INFORMATION;

typedef struct _WRK_SYSTEM_PROCESS_INFORMATION {
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
    SYSTEM_THREAD_INFORMATION Threads[1];
} WRK_SYSTEM_PROCESS_INFORMATION, *PWRK_SYSTEM_PROCESS_INFORMATION;

typedef enum _WRK_MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} WRK_MEMORY_INFORMATION_CLASS, *PWRK_MEMORY_INFORMATION_CLASS;

NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
);

NTSYSAPI NTSTATUS NTAPI NtProtectVirtualMemory(
    IN HANDLE  ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T NumberOfBytesToProtect,
    IN ULONG NewAccessProtection,
    OUT PULONG OldAccessProtection
);

NTSYSAPI NTSTATUS NTAPI NtQueryVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN WRK_MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID Buffer,
    IN SIZE_T Length,
    OUT OPTIONAL PSIZE_T ResultLength
);

NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType
);

NTSYSAPI NTSTATUS NTAPI NtOpenThread(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN CLIENT_ID* ClientId
);

NTSYSAPI NTSTATUS NTAPI NtSuspendThread(
    IN HANDLE ThreadHandle,
    OUT OPTIONAL PULONG PreviousSuspendCount
);

NTSYSAPI NTSTATUS NTAPI NtResumeThread(
    IN HANDLE ThreadHandle,
    OUT OPTIONAL PULONG SuspendCount
);

NTSYSAPI NTSTATUS NTAPI NtGetContextThread(
    IN HANDLE ThreadHandle,
    OUT PCONTEXT Context
);

NTSYSAPI NTSTATUS NTAPI NtSetContextThread(
    IN HANDLE ThreadHandle,
    IN PCONTEXT Context
);

NTSYSAPI NTSTATUS NTAPI NtFlushInstructionCache(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN SIZE_T NumberOfBytesToFlush
);

NTSYSAPI NTSTATUS NTAPI LdrGetDllHandle(
    IN OPTIONAL PWORD pwPath,
    IN OPTIONAL PVOID Unused,
    IN PUNICODE_STRING ModuleFileName,
    OUT PHANDLE pHModule
);

NTSYSAPI NTSTATUS NTAPI LdrGetProcedureAddress(
    IN HMODULE ModuleHandle,
    IN OPTIONAL PANSI_STRING FunctionName,
    IN OPTIONAL WORD Oridinal,
    OUT PVOID* FunctionAddress
);

HMODULE _GetModuleHandle(LPCWSTR ModuleName)
{
    if (!ModuleName) return NULL;
    UNICODE_STRING Name;
    RtlInitUnicodeString(&Name, ModuleName);
    HMODULE hModule = NULL;
    NTSTATUS Status = LdrGetDllHandle(NULL, NULL, &Name, &hModule);
    return NT_SUCCESS(Status) ? hModule : NULL;
}

PVOID _GetProcAddress(HMODULE hModule, LPCSTR FunctionName)
{
    if (!hModule || !FunctionName) return NULL;
    PVOID Address = NULL;
    ANSI_STRING Name;
    RtlInitAnsiString(&Name, FunctionName);
    NTSTATUS Status = LdrGetProcedureAddress(hModule, &Name, 0, &Address);
    return NT_SUCCESS(Status) ? Address : NULL;
}
#endif

static size_t inline AlignDown(size_t Value, size_t Factor)
{
    return Value & ~(Factor - 1);
}

static size_t inline AlignUp(size_t Value, size_t Factor)
{
    return AlignDown(Value - 1, Factor) + Factor;
}

#ifdef _KERNEL_MODE

#define POOL_TAG 'BLKH'

static PVOID Alloc(SIZE_T Size)
{
    PVOID Buffer = ExAllocatePoolWithTag(NonPagedPool, Size, POOL_TAG); // Always RWX
    if (Buffer) RtlZeroMemory(Buffer, Size);
    return Buffer;
}

static VOID Free(PVOID Base)
{
    ExFreePoolWithTag(Base, POOL_TAG);
}
#else
static PVOID Alloc(OPTIONAL PVOID Base, SIZE_T Size, ULONG Protect)
{
    NTSTATUS Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, Base ? 12 : 0, &Size, MEM_RESERVE | MEM_COMMIT, Protect);
    return NT_SUCCESS(Status) ? Base : NULL;
}

static VOID Free(PVOID Base)
{
    SIZE_T RegionSize = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);
}
#endif

#ifndef _KERNEL_MODE

static NTSTATUS Protect(PVOID Address, SIZE_T Size, ULONG Protect, OUT PULONG OldProtect)
{
    return NtProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, Protect, OldProtect);
}

static BOOLEAN NTAPI EnumProcesses(
    BOOLEAN(*Callback)(
        PWRK_SYSTEM_PROCESS_INFORMATION Process,
        OPTIONAL PVOID Argument
    ),
    OPTIONAL PVOID Argument
) {
    ULONG Length = 0;
    NTSTATUS Status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &Length);

    if (Status != STATUS_INFO_LENGTH_MISMATCH) return FALSE;
    PWRK_SYSTEM_PROCESS_INFORMATION Info = Alloc(NULL, Length, PAGE_READWRITE);
    if (!Info) return FALSE;

    Status = NtQuerySystemInformation(SystemProcessInformation, Info, Length, &Length);
    if (!NT_SUCCESS(Status))
    {
        Free(Info);
        return FALSE;
    }

    do {
        if (!Callback(Info, Argument)) break;
        Info = (PWRK_SYSTEM_PROCESS_INFORMATION)((PBYTE)Info + Info->NextEntryOffset);
    } while (Info->NextEntryOffset);

    Free(Info);
    return TRUE;
}

typedef enum _SUSPEND_RESUME_TYPE {
    srtSuspend,
    srtResume
} SUSPEND_RESUME_TYPE, *PSUSPEND_RESUME_TYPE;

typedef struct _SUSPEND_RESUME_INFO {
    ULONG CurrentPid;
    ULONG CurrentTid;
    SUSPEND_RESUME_TYPE Type;
} SUSPEND_RESUME_INFO, *PSUSPEND_RESUME_INFO;

static BOOLEAN SuspendResumeCallback(PWRK_SYSTEM_PROCESS_INFORMATION Process, PVOID Arg)
{
    if (!Process || !Arg) return FALSE;

    PSUSPEND_RESUME_INFO Info = Arg;
    if ((SIZE_T)Process->UniqueProcessId != (SIZE_T)Info->CurrentPid) return TRUE; // Continue the processes enumeration loop

    for (unsigned int i = 0; i < Process->NumberOfThreads; ++i)
    {
        if ((SIZE_T)Process->Threads[i].ClientId.UniqueThread == (SIZE_T)Info->CurrentTid) continue;
        
        HANDLE hThread = NULL;
        NTSTATUS Status = NtOpenThread(&hThread, THREAD_SUSPEND_RESUME, NULL, &Process->Threads[i].ClientId);
        if (NT_SUCCESS(Status) && hThread)
        {
            ULONG SuspendCount = 0;
            switch (Info->Type)
            {
            case srtSuspend:
                NtSuspendThread(hThread, &SuspendCount);
                break;
            case srtResume:
                NtResumeThread(hThread, &SuspendCount);
                break;
            }
            NtClose(hThread);
        }
    }

    return FALSE; // Stop the processes enumeration loop
}

static BOOLEAN SuspendThreads()
{
    SUSPEND_RESUME_INFO Info;
    Info.CurrentPid = __pid();
    Info.CurrentTid = __tid();
    Info.Type = srtSuspend;
    return EnumProcesses(SuspendResumeCallback, &Info);
}

static BOOLEAN ResumeThreads()
{
    SUSPEND_RESUME_INFO Info;
    Info.CurrentPid = __pid();
    Info.CurrentTid = __tid();
    Info.Type = srtResume;
    return EnumProcesses(SuspendResumeCallback, &Info);
}
#endif

#ifdef _KERNEL_MODE
typedef const void* LPCVOID;
typedef void* PVOID;
typedef PVOID LPVOID;
typedef unsigned char BYTE;
typedef BYTE* PBYTE;
typedef PBYTE LPBYTE;
#endif

static inline BOOLEAN IsGreaterThan(LPCVOID Src, LPCVOID Dest, SIZE_T Delta)
{
    return (Src < Dest ? (SIZE_T)Dest - (SIZE_T)Src : (SIZE_T)Src - (SIZE_T)Dest) > Delta;
}

#ifdef _AMD64_
static inline BOOLEAN IsGreaterThan2Gb(LPCVOID Src, LPCVOID Dest)
{
    return IsGreaterThan(Src, Dest, 2 * 1024 * 1048576UL);
}
#endif

#if defined _AMD64_ && !defined _KERNEL_MODE

#define ALLOCATION_GRANULARITY (64 * 1024)
#define BYTES_IN_2GB (2 * 1024 * 1048576UL)

static PVOID FindEmptyPageInLower2Gb(PVOID From)
{
    PBYTE Base = (PBYTE)AlignDown((size_t)From, ALLOCATION_GRANULARITY);

    MEMORY_BASIC_INFORMATION Info;
    SIZE_T ResultLength = 0;
    while (NT_SUCCESS(NtQueryVirtualMemory(
        NtCurrentProcess(),
        Base,
        MemoryBasicInformation,
        &Info,
        sizeof(Info),
        &ResultLength
    )) && ResultLength) {
        if (Info.State == MEM_FREE) return Base;
        Base = (PBYTE)Info.BaseAddress - 1;
        Base = (PVOID)AlignDown((size_t)Base, ALLOCATION_GRANULARITY);
        if (IsGreaterThan2Gb(From, (PVOID)Info.BaseAddress)) return NULL;
    }
    return NULL;
}

static PVOID FindEmptyPageInUpper2Gb(PVOID From)
{
    return NULL;

    PBYTE Base = (PBYTE)AlignUp((size_t)From, ALLOCATION_GRANULARITY);

    MEMORY_BASIC_INFORMATION Info;
    SIZE_T ResultLength = 0;
    while (NT_SUCCESS(NtQueryVirtualMemory(
        NtCurrentProcess(),
        Base,
        MemoryBasicInformation,
        &Info,
        sizeof(Info),
        &ResultLength
    )) && ResultLength) {
        if (Info.Protect == PAGE_NOACCESS) return Base;
        Base += Info.RegionSize;
        Base = (PVOID)AlignUp((size_t)Base, ALLOCATION_GRANULARITY);
        if (IsGreaterThan2Gb(From, (PVOID)Base)) return NULL;
    }
    return NULL;
}

static PVOID FindEmptyPageIn2Gb(PVOID From)
{
    PVOID Base = FindEmptyPageInUpper2Gb(From);
    return Base ? Base : FindEmptyPageInLower2Gb(From);
}
#endif

#ifdef _KERNEL_MODE
typedef struct _WRITEABLE_MAPPING {
    PVOID MappedPages;
    PMDL Mdl;
} WRITEABLE_MAPPING, *PWRITEABLE_MAPPING;

BOOLEAN MapWriteable(PVOID StartAddress, ULONG Size, OUT PWRITEABLE_MAPPING WriteableMapping)
{
    if (!WriteableMapping) return FALSE;

    memset(WriteableMapping, 0, sizeof(*WriteableMapping));

    PMDL Mdl = IoAllocateMdl(StartAddress, Size, FALSE, FALSE, NULL);
    if (!Mdl) return FALSE;

    __try
    {
        MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        IoFreeMdl(Mdl);
        return FALSE;
    }

    PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, HighPagePriority);
    if (!Mapping)
    {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return FALSE;
    }

    NTSTATUS Status = MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);
    if (!NT_SUCCESS(Status))
    {
        MmUnmapLockedPages(Mapping, Mdl);
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
        return FALSE;
    }

    WriteableMapping->MappedPages = Mapping;
    WriteableMapping->Mdl = Mdl;

    return TRUE;
}

VOID UnmapWriteable(IN PWRITEABLE_MAPPING WriteableMapping)
{
    if (WriteableMapping->MappedPages && WriteableMapping->Mdl)
    {
        MmUnmapLockedPages(WriteableMapping->MappedPages, WriteableMapping->Mdl);
    }

    if (WriteableMapping->Mdl)
    {
        MmUnlockPages(WriteableMapping->Mdl);
        IoFreeMdl(WriteableMapping->Mdl);
    }
}
#endif

#define ABS_TRAMPOLINE_SIZE (14)
#define REL_TRAMPOLINE_SIZE (5)

#ifdef _AMD64_
static VOID WriteAbsoluteTrampoline(LPVOID WriteTo, LPCVOID Dest)
{
    //      * jmp [rip+00h]
    // RIP -> 0x11223344
    *(PUSHORT)((PBYTE)WriteTo) = 0x25FF;
    *(PULONG)((PBYTE)WriteTo + sizeof(USHORT)) = 0x00000000;
    *(LPCVOID*)((PBYTE)WriteTo + sizeof(USHORT) + sizeof(ULONG)) = Dest;
}
#endif

static VOID WriteRelativeTrampoline(LPVOID WriteTo, LPVOID Src, LPCVOID Dest)
{
    // jmp 0x11223344
    *(PBYTE)(WriteTo) = 0xE9;
    *(PULONG)((PBYTE)WriteTo + sizeof(BYTE)) = (ULONG)((PBYTE)Dest - ((PBYTE)Src + 5));
}

static inline BOOLEAN RelocateInstruction(PBYTE DestInstrPtr, INT64 Offset, BYTE PatchOffset, BYTE PatchSize)
{
    switch (PatchSize)
    {
    case 8:
        *(PINT8)(DestInstrPtr + PatchOffset) += (INT8)Offset;
        break;
    case 16:
        *(PINT16)(DestInstrPtr + PatchOffset) += (INT16)Offset;
        break;
    case 32:
        *(PINT32)(DestInstrPtr + PatchOffset) += (INT32)Offset;
        break;
#ifdef _AMD64_
    case 64:
        *(PINT64)(DestInstrPtr + PatchOffset) += (INT64)Offset;
        break;
#endif
    default:
        // We're unable to relocate this instruction:
        return FALSE;
    }
    return TRUE;
}

static BYTE TransitCode(LPCVOID Src, LPVOID Dest, SIZE_T Size)
{
    ZydisDecoder Decoder;
#ifdef _AMD64_
    ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#else
    ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);
#endif

    BYTE WholeInstructionsSize = 0;

    LPCVOID InstructionCounter = Src;
    ZydisDecodedInstruction Instruction;
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&Decoder, InstructionCounter, 16, &Instruction)))
    {
        const unsigned char* SrcInstrPtr = InstructionCounter;
        unsigned char* DestInstrPtr = (PBYTE)Dest + (SrcInstrPtr - (PBYTE)Src);
        memcpy(DestInstrPtr, SrcInstrPtr, Instruction.length);

        if (Instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE)
        {
            SSIZE_T Offset = (SSIZE_T)(SrcInstrPtr - DestInstrPtr);

            if (Instruction.raw.disp.offset)
            {
                if (IsGreaterThan(SrcInstrPtr, DestInstrPtr, (SIZE_T)1UL << (Instruction.raw.disp.size - 1)))
                    return 0; // We're unable to relocate this instruction

                if (!RelocateInstruction(DestInstrPtr, Offset, Instruction.raw.disp.offset, Instruction.raw.disp.size))
                    return 0; // We're unable to relocate this instruction
            }

            for (unsigned i = 0; i < 2; ++i)
            {
                if (Instruction.raw.imm[i].offset && Instruction.raw.imm[i].is_relative)
                {
                    if (IsGreaterThan(SrcInstrPtr, DestInstrPtr, (SIZE_T)1UL << (Instruction.raw.imm[i].size - 1)))
                        return 0; // We're unable to relocate this instruction

                    if (!RelocateInstruction(DestInstrPtr, Offset, Instruction.raw.imm[i].offset, Instruction.raw.imm[i].size))
                        return 0; // We're unable to relocate this instruction
                }
            }
        }

        (LPBYTE)InstructionCounter += Instruction.length;
        WholeInstructionsSize += Instruction.length;
        if (WholeInstructionsSize >= Size) break;
    }

    return WholeInstructionsSize;
}

#ifndef _KERNEL_MODE
typedef struct _FIXUP_CONTEXT_INFO {
    ULONG CurrentPid;
    ULONG CurrentTid;
    PVOID AffectedCode;
    PVOID OriginalCode;
    SIZE_T Size;
} FIXUP_CONTEXT_INFO, *PFIXUP_CONTEXT_INFO;

static BOOLEAN FixupContextsCallback(PWRK_SYSTEM_PROCESS_INFORMATION Process, PVOID Arg)
{
    if (!Process || !Arg) return FALSE;

    PFIXUP_CONTEXT_INFO Info = Arg;
    if ((SIZE_T)Process->UniqueProcessId != (SIZE_T)Info->CurrentPid) return TRUE; // Continue the processes enumeration loop

    for (unsigned int i = 0; i < Process->NumberOfThreads; ++i)
    {
        if ((SIZE_T)Process->Threads[i].ClientId.UniqueThread == (SIZE_T)Info->CurrentTid) continue;

        HANDLE hThread = NULL;
        NTSTATUS Status = NtOpenThread(&hThread, THREAD_SUSPEND_RESUME, NULL, &Process->Threads[i].ClientId);
        if (NT_SUCCESS(Status) && hThread)
        {
            CONTEXT Context;
            Context.ContextFlags = CONTEXT_ALL;
            if (NT_SUCCESS(NtGetContextThread(hThread, &Context)))
            {
#ifdef _AMD64_
                if (Context.Rip >= (DWORD64)Info->AffectedCode && Context.Rip < (DWORD64)Info->AffectedCode + Info->Size)
                    Context.Rip = (DWORD64)Info->OriginalCode + (Context.Rip - (DWORD64)Info->AffectedCode);
#else
                if (Context.Eip >= (DWORD64)Info->AffectedCode && Context.Eip < (DWORD64)Info->AffectedCode + Info->Size)
                    Context.Eip = (DWORD64)Info->OriginalCode + (Context.Eip - (DWORD64)Info->AffectedCode);
#endif
                NtSetContextThread(hThread, &Context);
            }
            NtClose(hThread);
        }
    }

    return FALSE; // Stop the processes enumeration loop
}
#endif

typedef struct _HOOK_DATA {
#if defined _AMD64_ && !defined _KERNEL_MODE
    BYTE LongTrampoline[16]; // jmp [rip+00h] | FF 25 00 00 00 00 NN NN NN NN NN NN NN NN
#endif
    PVOID OriginalFunction;  // Address of hooked function
    ULONG OriginalDataSize;  // Size of saved original beginning
    ULONG AffectedBytes;     // Size of affected bytes of original function
    BYTE OriginalBeginning[32];
    BYTE OriginalBytes[32];
} HOOK_DATA, *PHOOK_DATA;

static VOID SaveOriginalBytes(OUT PHOOK_DATA Hook, LPCVOID Target, ULONG Size)
{
    Hook->AffectedBytes = Size;
    for (unsigned int i = 0; i < Size; ++i)
    {
        Hook->OriginalBytes[i] = *((PBYTE)Target + i);
    }
}

static VOID RestoreOriginalBytes(IN PHOOK_DATA Hook, LPVOID WriteTo)
{
    for (unsigned int i = 0; i < Hook->AffectedBytes; ++i)
    {
        *((PBYTE)WriteTo + i) = Hook->OriginalBytes[i];
    }
}

#ifdef _KERNEL_MODE
static BOOLEAN SetHookKm(LPVOID Target, LPCVOID Interceptor, LPVOID* Original)
{
    if (!Target || !Interceptor) return FALSE;

    PHOOK_DATA Hook = Alloc(sizeof(*Hook));
    if (!Hook) return FALSE;

    Hook->OriginalFunction = Target;
    
#ifdef _AMD64_
    BOOLEAN NeedAbsoluteJump = IsGreaterThan2Gb(Target, Interceptor);
    if (NeedAbsoluteJump)
    {
        SaveOriginalBytes(Hook, Target, ABS_TRAMPOLINE_SIZE);
        Hook->OriginalDataSize = TransitCode(Target, Hook->OriginalBeginning, ABS_TRAMPOLINE_SIZE);
        WriteAbsoluteTrampoline((PBYTE)Hook->OriginalBeginning + Hook->OriginalDataSize, (PBYTE)Target + Hook->OriginalDataSize);
    }
    else
    {
#endif
        SaveOriginalBytes(Hook, Target, REL_TRAMPOLINE_SIZE);
        Hook->OriginalDataSize = TransitCode(Target, Hook->OriginalBeginning, REL_TRAMPOLINE_SIZE);
        PBYTE WriteTo = (PBYTE)Hook->OriginalBeginning + Hook->OriginalDataSize;
        WriteRelativeTrampoline(WriteTo, WriteTo, (PBYTE)Target + Hook->OriginalDataSize);
#ifdef _AMD64_
    }
#endif

    WRITEABLE_MAPPING Writeable;

#ifdef _AMD64_
    BOOLEAN WriteableStatus = MapWriteable(Target, NeedAbsoluteJump ? ABS_TRAMPOLINE_SIZE : REL_TRAMPOLINE_SIZE, &Writeable);
#else
    BOOLEAN WriteableStatus = MapWriteable(Target, REL_TRAMPOLINE_SIZE, &Writeable);
#endif

    if (!WriteableStatus)
    {
        Free(Hook);
        return FALSE;
    }

    KIRQL Irql = KeRaiseIrqlToDpcLevel();

#ifdef _AMD64_
    if (NeedAbsoluteJump)
    {
        WriteAbsoluteTrampoline(Writeable.MappedPages, Interceptor);
    }
    else
    {
#endif
        WriteRelativeTrampoline(Writeable.MappedPages, Target, Interceptor);
#ifdef _AMD64_
    }
#endif

    if (Original) *Original = Hook->OriginalBeginning;

    _mm_sfence();
    KeLowerIrql(Irql);

    UnmapWriteable(&Writeable);

    return TRUE;
}
#else
static BOOLEAN SetHookUm(LPVOID Target, LPCVOID Interceptor, LPVOID* Original)
{
    if (!Target || !Interceptor) return FALSE;

#ifdef _AMD64_
    PVOID EmptyPage = FindEmptyPageIn2Gb(Target);
    
    BOOLEAN NeedAbsoluteJump = FALSE;
    BOOLEAN NeedIntermediateJump = IsGreaterThan2Gb(Target, Interceptor);
    if (NeedIntermediateJump)
    {
        NeedAbsoluteJump = !EmptyPage;
    }

    PHOOK_DATA Hook = Alloc(EmptyPage, sizeof(HOOK_DATA), PAGE_EXECUTE_READWRITE);
#else
    PHOOK_DATA Hook = Alloc(NULL, sizeof(HOOK_DATA), PAGE_EXECUTE_READWRITE);
#endif
    if (!Hook) return FALSE;

    Hook->OriginalFunction = Target;

#ifdef _AMD64_
    ULONG TrampolineSize = NeedAbsoluteJump ? ABS_TRAMPOLINE_SIZE : REL_TRAMPOLINE_SIZE;
    SaveOriginalBytes(Hook, Target, TrampolineSize);
    Hook->OriginalDataSize = TransitCode(Target, Hook->OriginalBeginning, TrampolineSize);
#else
    SaveOriginalBytes(Hook, Target, REL_TRAMPOLINE_SIZE);
    Hook->OriginalDataSize = TransitCode(Target, Hook->OriginalBeginning, REL_TRAMPOLINE_SIZE);
#endif

    if (!Hook->OriginalDataSize)
    {
        Free(Hook);
        return FALSE;
    }

#ifdef _AMD64_
    WriteAbsoluteTrampoline((PBYTE)Hook->OriginalBeginning + Hook->OriginalDataSize, (PBYTE)Target + Hook->OriginalDataSize);
#else
    PBYTE WriteTo = (PBYTE)Hook->OriginalBeginning + Hook->OriginalDataSize;
    WriteRelativeTrampoline(WriteTo, WriteTo, (PBYTE)Target + Hook->OriginalDataSize);
#endif

    ULONG OldProtect = 0;
#ifdef _AMD64_
    if (!NT_SUCCESS(Protect(Target, NeedAbsoluteJump ? ABS_TRAMPOLINE_SIZE : REL_TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect)))
#else
    if (!NT_SUCCESS(Protect(Target, REL_TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect)))
#endif
    {
        Free(Hook);
        return FALSE;
    }

    SuspendThreads();

#ifdef _AMD64_
    if (NeedIntermediateJump)
    {
        if (NeedAbsoluteJump)
        {
            WriteAbsoluteTrampoline(Target, Interceptor);
        }
        else
        {
            WriteRelativeTrampoline(Target, Target, Hook->LongTrampoline);
            WriteAbsoluteTrampoline(Hook->LongTrampoline, Interceptor);
        }
    }
    else {
#endif
        WriteRelativeTrampoline(Target, Target, Interceptor);
#ifdef _AMD64_
    }
#endif

    if (Original) *Original = Hook->OriginalBeginning;

#ifdef _AMD64_
    Protect(Target, NeedAbsoluteJump ? ABS_TRAMPOLINE_SIZE : REL_TRAMPOLINE_SIZE, OldProtect, &OldProtect);
#else
    Protect(Target, REL_TRAMPOLINE_SIZE, OldProtect, &OldProtect);
#endif

    FIXUP_CONTEXT_INFO FixupInfo;
    FixupInfo.CurrentPid = __pid();
    FixupInfo.CurrentTid = __tid();
    FixupInfo.AffectedCode = Target;
    FixupInfo.OriginalCode = Hook->OriginalBeginning;
    FixupInfo.Size = Hook->OriginalDataSize;
    EnumProcesses(FixupContextsCallback, &FixupInfo);

    NtFlushInstructionCache(NtCurrentProcess(), NULL, 0);
    ResumeThreads();

    return TRUE;
}
#endif

BOOLEAN NTAPI SetHook(LPVOID Target, LPCVOID Interceptor, LPVOID* Original)
{
#ifdef _KERNEL_MODE
    return SetHookKm(Target, Interceptor, Original);
#else
    return SetHookUm(Target, Interceptor, Original);
#endif
}

BOOLEAN NTAPI RemoveHook(LPVOID Original)
{
    if (!Original) return FALSE;

    PHOOK_DATA Hook = (PHOOK_DATA)((PBYTE)Original - offsetof(HOOK_DATA, OriginalBeginning));

#ifdef _KERNEL_MODE
    WRITEABLE_MAPPING Writeable;
    BOOLEAN WriteableStatus = MapWriteable(Hook->OriginalFunction, Hook->AffectedBytes, &Writeable);
    if (!WriteableStatus)
    {
        return FALSE;
    }

    KIRQL Irql = KeRaiseIrqlToDpcLevel();

    RestoreOriginalBytes(Hook, Writeable.MappedPages);
    
    _mm_sfence();
    KeLowerIrql(Irql);

    UnmapWriteable(&Writeable);

#else
    ULONG OldProtect = 0;
    if (!NT_SUCCESS(Protect(Hook->OriginalFunction, Hook->OriginalDataSize, PAGE_EXECUTE_READWRITE, &OldProtect)))
    {
        return FALSE;
    }

    SuspendThreads();

    RestoreOriginalBytes(Hook, Hook->OriginalFunction);

    Protect(Hook->OriginalFunction, Hook->OriginalDataSize, OldProtect, &OldProtect);

    FIXUP_CONTEXT_INFO FixupInfo;
    FixupInfo.CurrentPid = __pid();
    FixupInfo.CurrentTid = __tid();
    FixupInfo.AffectedCode = Hook->OriginalBeginning;
    FixupInfo.OriginalCode = Hook->OriginalFunction;
    FixupInfo.Size = Hook->OriginalDataSize;
    EnumProcesses(FixupContextsCallback, &FixupInfo);

    NtFlushInstructionCache(NtCurrentProcess(), NULL, 0);
    ResumeThreads();
#endif

    Free(Hook);

    return TRUE;
}


BOOLEAN CreateTraponlineUm(LPVOID Target, LPCVOID Interceptor, PBYTE TpBuff, BYTE nSize)
{
	if (!Target || !Interceptor || !TpBuff || (nSize < 32)) return FALSE;

#ifdef _AMD64_
	PVOID EmptyPage = FindEmptyPageIn2Gb(Target);

	BOOLEAN NeedAbsoluteJump = FALSE;
	BOOLEAN NeedIntermediateJump = IsGreaterThan2Gb(Target, Interceptor);
	if (NeedIntermediateJump)
	{
		NeedAbsoluteJump = !EmptyPage;
	}

	PHOOK_DATA Hook = Alloc(EmptyPage, sizeof(HOOK_DATA), PAGE_EXECUTE_READWRITE);
#else
	PHOOK_DATA Hook = Alloc(NULL, sizeof(HOOK_DATA), PAGE_EXECUTE_READWRITE);
#endif
	if (!Hook) return FALSE;

	Hook->OriginalFunction = Target;

#ifdef _AMD64_
	ULONG TrampolineSize = NeedAbsoluteJump ? ABS_TRAMPOLINE_SIZE : REL_TRAMPOLINE_SIZE;
	SaveOriginalBytes(Hook, Target, TrampolineSize);
	Hook->OriginalDataSize = TransitCode(Target, Hook->OriginalBeginning, TrampolineSize);
#else
	SaveOriginalBytes(Hook, Target, REL_TRAMPOLINE_SIZE);
	Hook->OriginalDataSize = TransitCode(Target, Hook->OriginalBeginning, REL_TRAMPOLINE_SIZE);
#endif

	if (!Hook->OriginalDataSize)
	{
		Free(Hook);
		return FALSE;
	}

	// backup TransitCode 
	__movsb(TpBuff, Hook->OriginalBeginning, sizeof(Hook->OriginalBeginning));
#ifdef _AMD64_
	WriteAbsoluteTrampoline(TpBuff + Hook->OriginalDataSize, (PBYTE)Target + Hook->OriginalDataSize);
#else
	WriteRelativeTrampoline(TpBuff + Hook->OriginalDataSize, TpBuff + Hook->OriginalDataSize, (PBYTE)Target + Hook->OriginalDataSize);
#endif
	Free(Hook);
	return TRUE;
}
