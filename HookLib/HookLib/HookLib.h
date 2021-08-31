#pragma once

#ifdef __cplusplus
    #include <cstddef>
    #define hooklib_export extern "C"
#else
    #include <stddef.h>
    #define hooklib_export
#endif

typedef struct
{
    void* fn;
    const void* handler;
    void* original; // hook() makes it valid callable pointer after successful hook and sets as nullptr otherwise
} Hook;

typedef struct
{
    void* original; // unhook() makes it nullptr after successful unhook and keeps unchanged otherwise
} Unhook;

hooklib_export void* hook(void* fn, const void* handler);
hooklib_export size_t multihook(Hook* hooks, size_t count);

hooklib_export size_t multiunhook(Unhook* originals, size_t count);
hooklib_export size_t unhook(void* original);

#ifndef _KERNEL_MODE
hooklib_export void* lookupModule(const wchar_t* modName); // LdrGetDllHandle
hooklib_export void* lookupFunction(const void* hModule, const char* funcName); // LdrGetProcedureAddress
#endif

#ifdef __cplusplus
template <typename Fn>
class HookHolder
{
private:
    struct tr
    {
        template <class Type, class Other = Type>
        static constexpr Type exchange(Type& val, Other&& newVal)
        {
            const Type oldVal = static_cast<Type&&>(val);
            val = static_cast<Other&&>(newVal);
            return oldVal;
        }
    };

protected:
    Fn m_orig;
    Fn m_fn;
    Fn m_handler;

public:
    HookHolder() = default;

    HookHolder(Fn fn, Fn handler) noexcept : m_orig(nullptr), m_fn(fn), m_handler(handler)
    {
    }

    HookHolder(const HookHolder&) = delete;

    HookHolder(HookHolder&& holder) noexcept
        : m_orig(tr::exchange(holder.m_orig, nullptr))
        , m_fn(tr::exchange(holder.m_fn, nullptr))
        , m_handler(tr::exchange(holder.m_handler, nullptr))
    {
    }

    HookHolder& operator = (const HookHolder&) = delete;

    HookHolder& operator = (HookHolder&& holder) noexcept
    {
        if (&holder == this)
        {
            return *this;
        }

        disable();

        m_orig = tr::exchange(holder.m_orig, nullptr);
        m_fn = tr::exchange(holder.m_fn, nullptr);
        m_handler = tr::exchange(holder.m_handler, nullptr);

        return *this;
    }

    ~HookHolder() noexcept
    {
        if (active())
        {
            disable();
        }
    }

    bool valid() const noexcept
    {
        return m_fn && m_handler;
    }

    bool active() const noexcept
    {
        return m_orig != nullptr;
    }

    bool enable() noexcept
    {
        if (!valid())
        {
            return false;
        }

        if (active())
        {
            return true;
        }

        m_orig = static_cast<Fn>(hook(m_fn, m_handler));

        return m_orig != nullptr;
    }

    bool disable() noexcept
    {
        if (!valid())
        {
            return false;
        }

        if (!active())
        {
            return true;
        }

        const bool unhookStatus = (unhook(m_orig) == 1);
        if (unhookStatus)
        {
            m_orig = nullptr;
        }

        return unhookStatus;
    }

    Fn detach() noexcept
    {
        return tr::exchange(m_orig, nullptr);
    }

    Fn original() const noexcept
    {
        return m_orig;
    }

    Fn fn() const noexcept
    {
        return m_fn;
    }

    Fn handler() const noexcept
    {
        return m_handler;
    }

#ifdef _MSC_VER
    __declspec(property(get = original)) Fn call;
#endif
};

struct HookFactory
{
    template <typename Fn>
    [[nodiscard]] static HookHolder<Fn> install(Fn fn, Fn handler) noexcept
    {
        HookHolder hook(fn, handler);
        hook.enable();
        return hook;
    }

    template <typename Fn>
    [[nodiscard]] static HookHolder<Fn> install(void* fn, Fn handler) noexcept
    {
        return install<Fn>(static_cast<Fn>(fn), handler);
    }

#ifndef _KERNEL_MODE
    template <typename Fn>
    [[nodiscard]] static HookHolder<Fn> install(void* mod, const char* const funcName, Fn handler) noexcept
    {
        if (!mod)
        {
            return HookHolder<Fn>(nullptr, handler);
        }

        void* const fn = lookupFunction(mod, funcName);
        if (!fn)
        {
            return HookHolder<Fn>(nullptr, handler);
        }

        return install<Fn>(static_cast<Fn>(fn), handler);
    }

    template <typename Fn>
    [[nodiscard]] static HookHolder<Fn> install(const wchar_t* const modName, const char* const funcName, Fn handler) noexcept
    {
        const void* const mod = lookupModule(modName);
        return install<Fn>(mod, funcName, handler);
    }
#endif
};
#endif