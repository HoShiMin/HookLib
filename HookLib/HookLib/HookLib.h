#pragma once

#ifdef __cplusplus
#define HOOKLIB_EXPORT extern "C"
#else
#define HOOKLIB_EXPORT
#endif

#ifndef _KERNEL_MODE
HOOKLIB_EXPORT HMODULE _GetModuleHandle(LPCWSTR ModuleName);
HOOKLIB_EXPORT PVOID _GetProcAddress(HMODULE hModule, LPCSTR FunctionName);
#define QueryProcAddress(LibName, FuncName) _GetProcAddress(_GetModuleHandle(LibName), FuncName)
#endif

HOOKLIB_EXPORT BOOLEAN NTAPI SetHook(LPVOID Target, LPCVOID Interceptor, LPVOID* Original);
HOOKLIB_EXPORT BOOLEAN NTAPI RemoveHook(LPVOID Original);

#ifdef __cplusplus
#define Hook(RetType, Convention, FuncName, FuncAddress, InitialStatus, ...) \
typedef RetType (Convention *FuncName##Type)(__VA_ARGS__);\
static RetType Convention FuncName##Handler(__VA_ARGS__); \
static HookStorage<FuncName##Type> FuncName##Hook(FuncAddress, &FuncName##Handler, InitialStatus); \
static RetType Convention FuncName##Handler(__VA_ARGS__)

#define HookKnown(RetType, Convention, Func, ...) \
Hook(RetType, Convention, Func, &Func, TRUE, __VA_ARGS__)

#define HookImport(RetType, Convention, Lib, Func, ...) \
Hook(RetType, Convention, Func, (RetType(Convention*)(__VA_ARGS__))QueryProcAddress(L##Lib, #Func), TRUE, __VA_ARGS__)

#define DeclareHookKnown(RetType, Convention, Func, ...) \
Hook(RetType, Convention, Func, &Func, FALSE, __VA_ARGS__)

#define DeclareHookImport(RetType, Convention, Lib, Func, ...) \
Hook(RetType, Convention, Func, (RetType(Convention*)(__VA_ARGS__))QueryProcAddress(L##Lib, #Func), FALSE, __VA_ARGS__)

#define DeclareHook(RetType, Convention, Func, ...) \
Hook(RetType, Convention, Func, (RetType(Convention*)(__VA_ARGS__))NULL, FALSE, __VA_ARGS__)

#define CallOriginal(Func) (Func##Hook.Original)

#define HookObject(Func) (Func##Hook)
#define EnableHook(Func) HookObject(Func).Enable()
#define DisableHook(Func) HookObject(Func).Disable()
#define IsHookEnabled(Func) HookObject(Func).GetState()
#define SetHookTarget(Func, Target) HookObject(Func).ReinitTarget((Func##Type)Target)
#define ApplyHook(Func, Target) \
SetHookTarget(Func, Target); \
EnableHook(Func)

template<typename T>
class HookStorage {
private:
    T _Target;
    T _Interceptor;
    T _Original;
    BOOLEAN _State;
public:
    inline T GetOriginal() const {
        return _Original;
    }
    __declspec(property(get = GetOriginal)) T Original;
    
    HookStorage() = delete;
    HookStorage(const HookStorage&) = delete;
    HookStorage(HookStorage&&) = delete;
    HookStorage& operator = (const HookStorage&) = delete;
    HookStorage& operator = (HookStorage&&) = delete;

    HookStorage(T Target, T Interceptor, BOOLEAN InitialState)
        : _Target(Target), _Interceptor(Interceptor), _Original(NULL), _State(FALSE)
    {
        if (Target && InitialState) Enable();
    }

    ~HookStorage() {
        Disable();
    }

    BOOLEAN ReinitTarget(T Target) {
        if (!Target) return FALSE;
        if (_State) return FALSE;
        _Target = Target;
        return TRUE;
    }

    BOOLEAN Enable() {
        if (!_Target) return FALSE;
        if (_State) return TRUE;
        return _State = SetHook(_Target, _Interceptor, reinterpret_cast<LPVOID*>(&_Original));
    }

    BOOLEAN Disable() {
        if (!_State) return TRUE;
        return _State = !RemoveHook(_Original);
    }

    inline BOOLEAN GetState() const {
        return _State;
    }
};
#endif