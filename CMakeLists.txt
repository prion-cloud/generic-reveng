cmake_minimum_required ( VERSION 3.8 )

set ( CMAKE_CXX_STANDARD 17 )

set ( CAPSTONE_BUILD_STATIC  OFF CACHE BOOL "Capstone: Build static library" )
set ( CAPSTONE_BUILD_TESTS   OFF CACHE BOOL "Capstone: Build tests"          )
set ( CAPSTONE_BUILD_CSTOOL  OFF CACHE BOOL "Capstone: Build cstool"         )

set ( CAPSTONE_ARM_SUPPORT   OFF CACHE BOOL "Capstone: ARM support"          )
set ( CAPSTONE_ARM64_SUPPORT OFF CACHE BOOL "Capstone: ARM64 support"        )
set ( CAPSTONE_MIPS_SUPPORT  OFF CACHE BOOL "Capstone: MIPS support"         )
set ( CAPSTONE_PPC_SUPPORT   OFF CACHE BOOL "Capstone: PowerPC support"      )
set ( CAPSTONE_SPARC_SUPPORT OFF CACHE BOOL "Capstone: Sparc support"        )
set ( CAPSTONE_SYSZ_SUPPORT  OFF CACHE BOOL "Capstone: SystemZ support"      )
set ( CAPSTONE_XCORE_SUPPORT OFF CACHE BOOL "Capstone: XCore support"        )

add_subdirectory ( "submodules/capstone/" )

add_subdirectory ( "submodules/unimage/" )

# The "submodules/unicorn/make.sh" script has to be executed first
link_directories ( "submodules/unicorn/" )

find_package ( Threads REQUIRED )

add_library ( scout-api SHARED
    "source/cfg.cpp"
    "source/debugger.cpp"
    "source/debugger_load.cpp"
    "source/instruction.cpp" )

target_include_directories ( scout-api PUBLIC
    "include/"
    "submodules/capstone/include/"
    "submodules/stimpak/include/"
    "submodules/unicorn/include/" )

target_link_libraries ( scout-api
    capstone-shared
    unimage
    "libunicorn.so"
    ${CMAKE_THREAD_LIBS_INIT} )

add_executable ( scout
    "source/scout.cpp" )

target_link_libraries ( scout
    scout-api )

add_executable ( scout-test
    "test/cfg_test.cpp"
    "test/debugger_test.cpp"
    "test/test_main.cpp" )

target_link_libraries ( scout-test
    scout-api )
