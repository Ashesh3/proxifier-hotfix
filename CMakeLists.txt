cmake_minimum_required(VERSION 3.24)
project(proxifier_hotfix LANGUAGES CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
    add_compile_options(
        $<$<COMPILE_LANGUAGE:CXX>:/W4>
        $<$<COMPILE_LANGUAGE:CXX>:/WX->
        $<$<COMPILE_LANGUAGE:CXX>:/EHsc>
        $<$<COMPILE_LANGUAGE:CXX>:/O2>
        $<$<COMPILE_LANGUAGE:CXX>:/Zi>
        $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
        $<$<COMPILE_LANGUAGE:CXX>:/permissive->
    )
    add_link_options(/DEBUG /PDBALTPATH:%_PDB% /OPT:REF /OPT:ICF)
endif()

add_library(msimg32 SHARED
    src/dllmain.cpp
    src/trampoline.cpp
    src/dns_synthesizer.cpp
    src/winsock_fix.cpp
    src/cache_fix.cpp
    src/wfp_pool.cpp
    src/ui_coalescer.cpp
    src/exports_thunk.asm
    src/exports.def
)

target_include_directories(msimg32 PRIVATE src)
target_compile_definitions(msimg32 PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)
target_link_libraries(msimg32 PRIVATE
    ws2_32
    user32
    gdi32
)

add_executable(hotfix_tests
    tests/test_main.cpp
    src/trampoline.cpp
    src/dns_synthesizer.cpp
    src/winsock_fix.cpp
    src/cache_fix.cpp
    src/wfp_pool.cpp
    src/ui_coalescer.cpp
)
target_include_directories(hotfix_tests PRIVATE src)
target_compile_definitions(hotfix_tests PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)
target_link_libraries(hotfix_tests PRIVATE
    ws2_32
    user32
    gdi32
)
