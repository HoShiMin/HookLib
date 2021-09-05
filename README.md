# HookLib²
## The Win32 lightweight functions interception library
### ✔ Advantages:
* Written on pure C
* Extremely lightweight
* Based on the fastest and lightweight [Zydis](https://github.com/zyantific/zydis) disassembler
* Uses only NativeAPI functions
* Has no other dependencies
* Kernelmode support
* Supports instructions relocation and thread's contexts fixup

### 📰 What's new in the 2nd Gen:
* The HookLib was completely rewritten
* Extremely reduced allocations, processes/threads enumerations and handles manipulations count
* Multihook/multiunhook support that hooks/unhooks multiple functions in one session
* Extremely reduced memory consumption for usermode hooks: one hook page (4Kb) can hold 39 cells for nearest hooks that removes the need to allocate one page per each hook
* Support for KM->UM hooks (even with support for contexts fixup directly from kernelmode):
  * KM:Amd64 -> UM:Amd64
  * KM:Amd64 -> UM:Wow64
  * KM:i386 -> UM:i386

### 🔬 How it works:
```
TargetFunction():                                 ^ ; return
-> jmp Interceptor ------> Interceptor():         |
   ??? ; Broken bytes        ... Handler code ... |
   ... ; Continuation <--+   CallOriginal() ------|--> OriginalBeginning():
   ...         +---------|-> ...                  |      ... Original beginning ...
   ret --------+         |   ret -----------------+      ... of TargetFunction ...
                         +------------------------------ jmp Continuation
```
### 🧵 Trampolines:
Supported trampolines:
```assembly
Jump to a relative offset:
E9 44 33 22 11  |  jmp rip+0x11223344 ; Relative jump to ±2Gb only

Jump to an absolute address (x32):
FF 25 44 33 22 11  | jmp ds:[0x11223344]
NN NN NN NN        | <- 0x11223344 is points to

Jump to an absolute address (x64):
FF 25 00 00 00 00        | jmp [rip+00h]
88 77 66 55 44 33 22 11  | <- RIP is points to
```
Trampolines selection logic:
```cpp
if (relative_jumpable(fn, handler))
{
    set_relative_jump(fn, handler);
}
else
{
    /*
        'Intermediate' is an intermediate buffer that allocates
        in the same block with the function beginning:
    */
    if (relative_jumpable(fn, intermediate))
    {
        set_relative_jump(fn, intermediate);
        set_absolute_jump(intermediate, handler); 
    }
    else
    {
        set_absolute_jump(fn, handler);
    }
}
```
### 🪡 Usage:
Add the **HookLib.vcxproj** to your **.sln** and add the reference to the HookLib project into your project references list as described [here](https://docs.microsoft.com/en-us/troubleshoot/cpp/add-references-managed): select project, open the project menu, click **Add -> Reference** and select the HookLib.  
Then add **./HookLib/HookLib/** folder to your header folders list and you're good to go.
```cpp
#include <HookLib.h>

int func(int a, int b)
{
    return a + b;
}

int handler(int a, int b)
{
    return a * b;
}

template <typename Fn>
Fn hookFunc(Fn fn, Fn handler)
{
    return static_cast<Fn>(hook(fn, handler));
}

void testSimpleHook()
{
    const auto orig = hookFunc(func, handler);
    
    assert(func(2, 3) == 6); // Hooked, the 'handler' will be called instead
    assert(orig(2, 3) == 5);
    
    unhook(orig);

    assert(func(2, 3) == 5);
}

void testCppHelpers()
{
    const auto holder = HookFactory::install(func, handler);
    assert(func(2, 3) == 6);
    assert(holder.call(2, 3) == 5);
}

int main()
{
    testSimpleHook();
    testCppHelpers();

    return 0;
}
```
