#include <wdm.h>
#include <HookLib.h>

#define hk_assert(cond) if (!(cond)) { __int2c(); } __assume((cond))

extern "C" NTSTATUS NTAPI ZwYieldExecution();

namespace
{
    template <unsigned int index>
    constexpr inline unsigned int validFunc(int a, int b)
    {
        return 0x1ee7c0de * (a + b + index);
    }

    template <unsigned int index>
    constexpr inline unsigned int validHandler(int a, int b)
    {
        return 0xc0ffee * (a + b + index);
    }

    template <unsigned int index>
    __declspec(noinline) __declspec(dllexport) unsigned int func(int a, int b)
    {
        ZwYieldExecution();
        return validFunc<index>(a, b);
    }

    template <unsigned int index>
    __declspec(noinline) __declspec(dllexport) unsigned int handler(int a, int b)
    {
        ZwYieldExecution();
        return validHandler<index>(a, b);
    }

    void testHookOnce()
    {
        decltype(func<0>)* original = nullptr;
        hook(func<0>, handler<0>, reinterpret_cast<void**>(&original));
        hk_assert(func<0>(11, 22) == validHandler<0>(11, 22));
        hk_assert(original(11, 22) == validFunc<0>(11, 22));
        
        unhook(original);
        
        hk_assert(func<0>(11, 22) == validFunc<0>(11, 22));
    }

    void testMultihook()
    {
        void* originals[2]{};
        Hook hooks[]
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

        const auto hookedCount = multihook(hooks, 2);
        hk_assert(hookedCount == 2);

        hk_assert(originals[0] && originals[1]);

        using Fn1 = decltype(func<1>)*;
        using Fn2 = decltype(func<2>)*;

        const Fn1 orig1 = static_cast<Fn1>(originals[0]);
        const Fn2 orig2 = static_cast<Fn1>(originals[1]);

        hk_assert(func<1>(11, 22) == validHandler<1>(11, 22));
        hk_assert(func<2>(11, 22) == validHandler<2>(11, 22));
        hk_assert(orig1(11, 22) == validFunc<1>(11, 22));
        hk_assert(orig2(11, 22) == validFunc<2>(11, 22));

        Unhook unhooks[]
        {
            { .original = orig1 },
            { .original = orig2 }
        };
        const auto unhookedCount = multiunhook(unhooks, 2);
        hk_assert(unhookedCount == 2);

        hk_assert(func<1>(11, 22) == validFunc<1>(11, 22));
        hk_assert(func<2>(11, 22) == validFunc<2>(11, 22));
    }

    void runTests()
    {
        testHookOnce();
        testMultihook();
    }
} // namespace


namespace
{
    const UNICODE_STRING k_devName = RTL_CONSTANT_STRING(L"\\Device\\HookLibTestDrv");
    const UNICODE_STRING k_symLink = RTL_CONSTANT_STRING(L"\\??\\HookLibTestDrv");
    PDEVICE_OBJECT g_devObj = nullptr;

    _Function_class_(DRIVER_DISPATCH)
    _IRQL_requires_max_(DISPATCH_LEVEL)
    _IRQL_requires_same_
    NTSTATUS NTAPI driverStub(PDEVICE_OBJECT, PIRP irp)
    {
        irp->IoStatus.Information = 0;
        irp->IoStatus.Status = STATUS_SUCCESS;

        IoCompleteRequest(irp, IO_NO_INCREMENT);
        
        return STATUS_SUCCESS;
    }

    _Function_class_(DRIVER_DISPATCH)
    _IRQL_requires_max_(DISPATCH_LEVEL)
    _IRQL_requires_same_
    NTSTATUS NTAPI ioctlHandler(PDEVICE_OBJECT, PIRP irp)
    {
        const PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);

        const auto ctl = irpStack->Parameters.DeviceIoControl.IoControlCode;

        switch (ctl)
        {
        case CTL_CODE(0x8000, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS):
        {
            runTests();
            irp->IoStatus.Information = 0;
            irp->IoStatus.Status = STATUS_SUCCESS;
            break;
        }
        case CTL_CODE(0x8000, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS):
        {
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

            const auto* const in = static_cast<const HookRequest::Input*>(irpStack->Parameters.DeviceIoControl.Type3InputBuffer);
            auto* const out = static_cast<HookRequest::Output*>(irp->UserBuffer);

            hook(reinterpret_cast<void*>(in->fn), reinterpret_cast<const void*>(in->handler), reinterpret_cast<void**>(&out->original));

            irp->IoStatus.Status = out->original ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
            irp->IoStatus.Information = sizeof(HookRequest::Output);
            break;
        }
        case CTL_CODE(0x8000, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS):
        {
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

            const auto* const in = static_cast<const UnhookRequest::Input*>(irpStack->Parameters.DeviceIoControl.Type3InputBuffer);
            auto* const out = static_cast<UnhookRequest::Output*>(irp->UserBuffer);

            out->status = (1 == unhook(reinterpret_cast<void*>(in->original)));

            irp->IoStatus.Status = out->status ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
            irp->IoStatus.Information = sizeof(UnhookRequest::Output);
            break;
        }
        default:
        {
            irp->IoStatus.Information = 0;
            irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        }

        const NTSTATUS status = irp->IoStatus.Status;
        
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return status;
    }
} // namespace


extern "C" NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING)
{
    drv->DriverUnload = [](PDRIVER_OBJECT drv)
    {
        if (drv->DeviceObject)
        {
            IoDeleteSymbolicLink(const_cast<UNICODE_STRING*>(&k_symLink));
            IoDeleteDevice(drv->DeviceObject);
        }
    };

    const NTSTATUS devStatus = IoCreateDevice(drv, 0, const_cast<UNICODE_STRING*>(&k_devName), FILE_DEVICE_UNKNOWN, 0, false, &g_devObj);
    if (!NT_SUCCESS(devStatus))
    {
        return devStatus;
    }

    const NTSTATUS symlinkStatus = IoCreateSymbolicLink(const_cast<UNICODE_STRING*>(&k_symLink), const_cast<UNICODE_STRING*>(&k_devName));
    if (!NT_SUCCESS(symlinkStatus))
    {
        IoDeleteDevice(g_devObj);
        return symlinkStatus;
    }

    drv->MajorFunction[IRP_MJ_CREATE] = driverStub;
    drv->MajorFunction[IRP_MJ_CLEANUP] = driverStub;
    drv->MajorFunction[IRP_MJ_CLOSE] = driverStub;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ioctlHandler;

    return STATUS_SUCCESS;
}