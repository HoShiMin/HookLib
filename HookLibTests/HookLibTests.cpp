#include <Windows.h>
#include <HookLib.h>

#include <cstdio>

#include <string>

constexpr bool k_testKernelMode = false;

namespace
{

template <unsigned int num>
__declspec(noinline) int func(int arg1, float arg2)
{
    printf("Orig: %u %i %f\n", num, arg1, arg2);
    return 0x1ee7c0de;
}

template <unsigned int num>
__declspec(noinline) int handler(int arg1, float arg2)
{
    printf("Hook: %u %i %f\n", num, arg1, arg2);
    return 1337;
}

template <typename Func>
void hookFunc(Func fn, Func handler, Func* original)
{
    hook(fn, handler, reinterpret_cast<void**>(original));
}

#define begin_test printf("%s:\n", __FUNCTION__)
#define end_test printf("\n")
#define hk_assert(cond) if (!(cond)) { printf("[X] %s\n", #cond); __int2c(); } __assume((cond))
#define log(fmt, ...) printf("[" __FILE__ ":%u]: " fmt "\n", __LINE__, __VA_ARGS__)

void testHookOnce()
{
    begin_test;

    func<0>(0, 0.123f);

    decltype(func<0>)* orig0 = nullptr;
    hookFunc(func<0>, handler<0>, &orig0);

    hk_assert(orig0 != nullptr);

    func<0>(0, 0.0f);
    orig0(0, 0.0f);

    unhook(orig0);
    func<0>(0, 0.0f);

    end_test;
}

void testSerialHooks()
{
    begin_test;

    decltype(func<1>)* orig1 = nullptr;
    decltype(func<2>)* orig2 = nullptr;
    hookFunc(func<1>, handler<1>, &orig1);
    hookFunc(func<2>, handler<2>, &orig2);

    func<1>(1, 0.1f);
    orig1(1, 0.1f);

    func<2>(2, 0.2f);
    orig2(2, 0.2f);

    unhook(orig2);
    func<2>(2, 0.2f);

    unhook(orig1);
    func<1>(1, 0.1f);

    end_test;
}

void testSerialHooksMultiunhook()
{
    begin_test;

    decltype(func<1>)* orig1 = nullptr;
    decltype(func<2>)* orig2 = nullptr;
    hookFunc(func<1>, handler<1>, &orig1);
    hookFunc(func<2>, handler<2>, &orig2);

    func<1>(1, 0.1f);
    orig1(1, 0.1f);

    func<2>(2, 0.2f);
    orig2(2, 0.2f);

    Unhook fns[2]{ orig1, orig2 };
    multiunhook(fns, 2);

    func<1>(1, 0.1f);
    func<2>(2, 0.2f);

    end_test;
}

void testMultihook()
{
    begin_test;

    void* originals[2]{};

    Hook hooks[2]
    {
        {
            .fn = func<1>,
            .handler = handler<1>,
            .original = &originals[0]
        },
        {
            .fn = func<2>,
            .handler = handler<2>,
            .original = &originals[1]
        }
    };

    const auto hooked = multihook(hooks, 2);
    hk_assert(hooked == 2);

    using Fn1 = decltype(func<1>)*;
    using Fn2 = decltype(func<2>)*;

    hk_assert(originals[0] != nullptr);
    hk_assert(originals[1] != nullptr);

    func<1>(1, 0.1f);
    static_cast<Fn1>(originals[0])(1, 0.1f);

    func<2>(2, 0.2f);
    static_cast<Fn2>(originals[1])(2, 0.2f);

    Unhook fns[2]{ originals[0], originals[1] };
    multiunhook(fns, 2);

    func<1>(1, 0.1f);
    func<2>(2, 0.2f);

    end_test;
}

void testContextsFixup()
{
    begin_test;

    const HANDLE hThread = CreateThread(nullptr, 0, [](void* arg) -> unsigned long
    {
        return 0;
    }, nullptr, CREATE_SUSPENDED, nullptr);
    
    hk_assert(hThread != nullptr);

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL;
    const bool getStatus = !!GetThreadContext(hThread, &ctx);
    hk_assert(getStatus);

#ifdef _AMD64_
    const size_t origIp = ctx.Rip;
    ctx.Rip = reinterpret_cast<size_t>(func<0>);
#else
    const size_t origIp = ctx.Eip;
    ctx.Eip = reinterpret_cast<size_t>(func<0>);
#endif

    const bool setStatus = !!SetThreadContext(hThread, &ctx);
    hk_assert(setStatus);

    SwitchToThread();
    const bool ensureStatus = !!GetThreadContext(hThread, &ctx); // Ensure that the context was setted
    hk_assert(ensureStatus);
#ifdef _AMD64_
    hk_assert(ctx.Rip == reinterpret_cast<size_t>(func<0>));
#else
    hk_assert(ctx.Eip == reinterpret_cast<size_t>(func<0>));
#endif

    decltype(func<0>)* orig = nullptr;
    hookFunc(func<0>, handler<0>, &orig);

    const bool secondGetStatus = !!GetThreadContext(hThread, &ctx);
    hk_assert(secondGetStatus);

#ifdef _AMD64_
    hk_assert(ctx.Rip == reinterpret_cast<size_t>(orig));
#else
    hk_assert(ctx.Eip == reinterpret_cast<size_t>(orig));
#endif

    unhook(orig);

    const bool thirdGetStatus = !!GetThreadContext(hThread, &ctx);
    hk_assert(thirdGetStatus);

#ifdef _AMD64_
    hk_assert(ctx.Rip == reinterpret_cast<size_t>(func<0>));
    ctx.Rip = origIp;
#else
    hk_assert(ctx.Eip == reinterpret_cast<size_t>(func<0>));
    ctx.Eip = origIp;
#endif

    const bool restoreOrigIpStatus = !!SetThreadContext(hThread, &ctx);
    hk_assert(restoreOrigIpStatus);

    SwitchToThread();

    ResumeThread(hThread);
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);

    end_test;
}

void driverTestKernelHooks(HANDLE hDev)
{
    begin_test;
    unsigned long returned = 0;
    const bool testStatus = !!DeviceIoControl(hDev, CTL_CODE(0x8000, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS), nullptr, 0, nullptr, 0, &returned, nullptr);
    hk_assert(testStatus);
    end_test;
}

void driverTestUserHooks(HANDLE hDev)
{
    begin_test;

    const HANDLE hThread = CreateThread(nullptr, 0, [](void* arg) -> unsigned long
    {
        return 0;
    }, nullptr, CREATE_SUSPENDED, nullptr);

    hk_assert(hThread != nullptr);

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL;
    const bool getStatus = !!GetThreadContext(hThread, &ctx);
    hk_assert(getStatus);

#ifdef _AMD64_
    const size_t origIp = ctx.Rip;
    ctx.Rip = reinterpret_cast<size_t>(func<0>);
#else
    const size_t origIp = ctx.Eip;
    ctx.Eip = reinterpret_cast<size_t>(func<0>);
#endif

    const bool setStatus = !!SetThreadContext(hThread, &ctx);
    hk_assert(setStatus);

    SwitchToThread();

    struct HookRequest
    {
        struct Input
        {
            unsigned long long fn;
            unsigned long long handler;
        };

        struct Output
        {
            unsigned long long original;
        };
    };
    const HookRequest::Input hookIn{ .fn = reinterpret_cast<unsigned long long>(func<0>), .handler = reinterpret_cast<unsigned long long>(handler<0>) };
    HookRequest::Output hookOut{};
    unsigned long returned = 0;
    const bool hookStatus = !!DeviceIoControl(hDev, CTL_CODE(0x8000, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS), const_cast<HookRequest::Input*>(&hookIn), sizeof(hookIn), &hookOut, sizeof(hookOut), &returned, nullptr);
    hk_assert(hookStatus);

    const auto orig = reinterpret_cast<decltype(func<0>)*>(hookOut.original);

    const bool secondGetStatus = !!GetThreadContext(hThread, &ctx);
    hk_assert(secondGetStatus);

#ifdef _AMD64_
    hk_assert(ctx.Rip == reinterpret_cast<size_t>(orig));
#else
    hk_assert(ctx.Eip == reinterpret_cast<size_t>(orig));
#endif

    struct UnhookRequest
    {
        struct Input
        {
            unsigned long long original;
        };

        struct Output
        {
            bool status;
        };
    };
    const UnhookRequest::Input unhookIn{ .original = hookOut.original };
    UnhookRequest::Output unhookOut{};
    const bool unhookStatus = !!DeviceIoControl(hDev, CTL_CODE(0x8000, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS), const_cast<UnhookRequest::Input*>(&unhookIn), sizeof(unhookIn), &unhookOut, sizeof(unhookOut), &returned, nullptr);
    hk_assert(unhookStatus);
    hk_assert(unhookOut.status);

    const bool thirdGetStatus = !!GetThreadContext(hThread, &ctx);
    hk_assert(thirdGetStatus);

#ifdef _AMD64_
    hk_assert(ctx.Rip == reinterpret_cast<size_t>(func<0>));
    ctx.Rip = origIp;
#else
    hk_assert(ctx.Eip == reinterpret_cast<size_t>(func<0>));
    ctx.Eip = origIp;
#endif

    const bool restoreOrigIpStatus = !!SetThreadContext(hThread, &ctx);
    hk_assert(restoreOrigIpStatus);

    SwitchToThread();

    ResumeThread(hThread);
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);

    end_test;
}

void testCppHelpers()
{
    begin_test;

    auto holder = HookFactory::install(func<0>, handler<0>);
    func<0>(111, 0.222f);
    holder.call(111, 0.222f);

    holder.disable();

    func<0>(111, 0.222f);

    end_test;
}

void runDriverTests()
{
    const auto getExeFolder = []() -> std::wstring
    {
        std::wstring path(MAX_PATH, L'\0');
        const auto len = GetModuleFileNameW(nullptr, path.data(), static_cast<unsigned int>(path.size()));
        if (!len)
        {
            return {};
        }

        const auto lastDelim = path.rfind(L'\\');
        if (lastDelim == std::wstring::npos)
        {
            return {};
        }

        path.resize(lastDelim);
        return path;
    };

    const auto exeFolder = getExeFolder();
    if (exeFolder.empty())
    {
        log("Unable to retrieve the current exe folder");
        return;
    }

    const auto driverPath = exeFolder + L"\\HookLibDrvTests.sys";

    const SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hScm)
    {
        const auto lastError = GetLastError();
        log("Unable to open the SC manager: 0x%X", lastError);
        return;
    }

    const SC_HANDLE hSvc = CreateServiceW(hScm, L"HookLibTestDrv", L"HookLibTestDrv", SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driverPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!hSvc)
    {
        const auto lastError = GetLastError();
        log("Unable to create the service: 0x%X", lastError);
        CloseServiceHandle(hScm);
        return;
    }

    const bool startStatus = !!StartServiceW(hSvc, 0, nullptr);
    if (!startStatus)
    {
        const auto lastError = GetLastError();
        log("Unable to start the service: 0x%X", lastError);
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);
        return;
    }

    const HANDLE hDev = CreateFileW(L"\\\\.\\HookLibTestDrv", FILE_ALL_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDev == INVALID_HANDLE_VALUE)
    {
        const auto lastError = GetLastError();
        log("Unable to open the HookLibDrv device: 0x%X", lastError);
        SERVICE_STATUS svcStatus{};
        ControlService(hSvc, SERVICE_CONTROL_STOP, &svcStatus);
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);
        return;
    }

    driverTestKernelHooks(hDev);
    driverTestUserHooks(hDev);

    CloseHandle(hDev);

    SERVICE_STATUS svcStatus{};
    ControlService(hSvc, SERVICE_CONTROL_STOP, &svcStatus);
    DeleteService(hSvc);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
}

void runTests()
{
    testHookOnce();
    testSerialHooks();
    testSerialHooksMultiunhook();
    testMultihook();
    testContextsFixup();
    testCppHelpers();

    if constexpr (k_testKernelMode)
    {
        runDriverTests();
    }
}

} // namespace

auto g_holder = HookFactory::install(func<0>, handler<0>);

int main()
{
    runTests();
    log("Tests are finished");
    return 0;
}