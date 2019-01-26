#include <cstdio>

#include <Windows.h>

#include <HookLib.h>
#pragma comment(lib, "Zydis.lib")
#pragma comment(lib, "HookLib.lib")

using _ExitProcess = VOID(WINAPI*)(ULONG ExitCode);
_ExitProcess OriginalExitProcess = NULL;
VOID WINAPI ExitProcessHook(ULONG ExitCode)
{
    printf("ExitCode: %ul\r\n", ExitCode);
    RemoveHook(OriginalExitProcess);
    ExitProcess(0);
}

int main()
{
    PVOID Target = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "ExitProcess");
    SetHook(Target, ExitProcessHook, reinterpret_cast<PVOID*>(&OriginalExitProcess));
    ExitProcess(0);
    return 0;
}