cmake_minimum_required(VERSION 4.0)

project(HookLib LANGUAGES C)

option(ZYDIS_MINIMAL_MODE ON)
option(ZYDIS_FEATURE_ENCODER OFF)
option(ZYDIS_FEATURE_FORMATTER OFF)
option(ZYDIS_FEATURE_AVX512 OFF)
option(ZYDIS_FEATURE_KNC OFF)
option(ZYDIS_FEATURE_SEGMENT OFF)
option(ZYDIS_BUILD_EXAMPLES OFF)
option(ZYDIS_BUILD_TOOLS OFF)
option(ZYDIS_BUILD_MAN OFF)
option(ZYDIS_BUILD_DOXYGEN OFF)
add_subdirectory(HookLib/Zydis)

add_library(HookLib STATIC)

target_sources(HookLib PRIVATE
    ./HookLib/HookLib/HookLib.c
    ./HookLib/HookLib/HookLib.h
    )

target_include_directories(HookLib PUBLIC
    ./HookLib/HookLib
    )

target_link_libraries(HookLib PUBLIC
    Zydis
    )
