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

HOOKLIB_EXPORT BOOLEAN NTAPI SetHook(void* Target, const void* Interceptor, void** Original);
HOOKLIB_EXPORT BOOLEAN NTAPI RemoveHook(void* Original);

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
    T m_Target;
    T m_Interceptor;
    T m_Original;
    BOOLEAN m_State;
public:
    inline T GetOriginal() const {
        return m_Original;
    }
    __declspec(property(get = GetOriginal)) T Original;
    
    HookStorage() = delete;
    HookStorage(const HookStorage&) = delete;
    HookStorage(HookStorage&&) = delete;
    HookStorage& operator = (const HookStorage&) = delete;
    HookStorage& operator = (HookStorage&&) = delete;

    HookStorage(T Target, T Interceptor, BOOLEAN InitialState)
        : m_Target(Target), m_Interceptor(Interceptor), m_Original(NULL), m_State(FALSE)
    {
        if (Target && InitialState) Enable();
    }

    ~HookStorage() {
        Disable();
    }

    BOOLEAN ReinitTarget(T Target) {
        if (!Target) return FALSE;
        if (m_State) return FALSE;
        m_Target = Target;
        return TRUE;
    }

    BOOLEAN Enable() {
        if (!m_Target) return FALSE;
        if (m_State) return TRUE;
        return m_State = SetHook(m_Target, m_Interceptor, reinterpret_cast<LPVOID*>(&m_Original));
    }

    BOOLEAN Disable() {
        if (!m_State) return TRUE;
        return m_State = !RemoveHook(m_Original);
    }

    inline BOOLEAN GetState() const {
        return m_State;
    }
};
#endif