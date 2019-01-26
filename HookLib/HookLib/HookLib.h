#pragma once

#ifdef __cplusplus
#define HOOKLIB_EXPORT extern "C"
#else
#define HOOKLIB_EXPORT
#endif

HOOKLIB_EXPORT BOOLEAN NTAPI SetHook(LPVOID Target, LPCVOID Interceptor, LPVOID* Original);
HOOKLIB_EXPORT BOOLEAN NTAPI RemoveHook(LPVOID Original);