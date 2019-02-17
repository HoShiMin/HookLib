#include <cstdio>

#include <Windows.h>

#include <HookLib.h>
#pragma comment(lib, "Zydis.lib")
#pragma comment(lib, "HookLib.lib")

namespace First {
    Hook(VOID, WINAPI, ExitProcess, &ExitProcess, TRUE, UINT ExitCode)
    {
        printf("[Hook] ExitCode: %ul\n", ExitCode);
        CallOriginal(ExitProcess)(ExitCode);
    }
}

namespace Second {
    HookKnown(VOID, WINAPI, ExitProcess, UINT ExitCode)
    {
        printf("[HookKnown] ExitCode: %ul\n", ExitCode);
        CallOriginal(ExitProcess)(ExitCode);
    }
}

namespace Third {
    DeclareHookImport(VOID, WINAPI, "kernel32.dll", ExitProcess, UINT ExitCode)
    {
        printf("[HookImport] ExitCode: %ul\n", ExitCode);
        CallOriginal(ExitProcess)(ExitCode);
    }
}

DeclareHook(VOID, WINAPI, ExitProcess, UINT ExitCode)
{
    printf("[DynamicalTarget] ExitCode: %ul\n", ExitCode);
    CallOriginal(ExitProcess)(ExitCode);
}

int main()
{
    EnableHook(Third::ExitProcess);
    ApplyHook(ExitProcess, QueryProcAddress(L"kernel32.dll", "ExitProcess"));
    ExitProcess(0);
    printf("We shouldn't be here!\r\n");
    return -1;
}