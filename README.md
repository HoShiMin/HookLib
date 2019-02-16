# HookLib
## The Win32 lightweight functions interception library
### ✔ Advantages:
* Written on pure C
* Extremely lightweight
* Based on the fastest and lightweight [Zydis](https://github.com/zyantific/zydis) disassembler
* Uses only NativeAPI functions
* Has no other dependencies
* Kernelmode support
* Supports instructions relocation and thread's contexts fixup
  
### ⚙️ How it works:
```
TargetFunction():                                 ^ ; return
-> jmp Interceptor ------> Interceptor():         |
   ??? ; Broken bytes        ... Handler code ... |
   ... ; Continuation <--+   CallOriginal() ------|--> OriginalBeginning():
   ...         +---------|-> ...                  |      ... Original beginning ...
   ret --------+         |   ret -----------------+      ... of TargetFunction ...
                         +------------------------------ jmp Continuation
   
```
### 🧱 Trampolines:
#### Types:
* `E9 44 33 22 11  |  jmp 0x11223344` - Relative jump to the +-2Gb
* `FF 25 00 00 00 00 88 77 66 55 44 33 22 11  |  jmp [rip+00h]` - Absolute jump to the address stored after the jmp as raw bytes (4 bytes in x32 and 8 bytes in x64)
#### x32:
* `jmp rel Interceptor` only one
#### x64:
* `jmp rel Interceptor` if Abs(Interceptor - Target) <= 2Gb
* `jmp rel Intermediate -> jmp abs Interceptor` if Abs(Interceptor - Target) > 2Gb and we have free space for the intermediate trampoline buffer
* `jmp abs Interceptor` if we have no free space for the intermediate buffer in +- 2Gb interval
### 🧵 Using:
Open the `HookLib.sln` and build it.  
Add `Zydis.lib`, `HookLib.lib` and `HookLib.h` to your project.
```cpp
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
```
