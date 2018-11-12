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

set ( BUILD_SHARED_LIBS     ON    CACHE BOOL   "Keystone: Build shared library" )
set ( BUILD_LIBS_ONLY       ON    CACHE BOOL   "Keystone: Skip kstool"          )

set ( LLVM_TARGETS_TO_BUILD "X86" CACHE STRING "Keystone: Support only X86"     )

add_subdirectory ( "submodules/keystone/" )

# The "submodules/unicorn/make.sh" script has to be executed first
link_directories ( "submodules/unicorn/" )

find_package ( Threads REQUIRED )

add_executable ( scout
    "source/control_flow_graph.cpp"
    "source/debugger.cpp"
    "source/debugger_load.cpp"
    "source/instruction.cpp"
    "source/scout.cpp" )

target_include_directories ( scout PRIVATE
    "include/" )
target_link_libraries ( scout
    capstone-shared
    "libunicorn.so"
    ${CMAKE_THREAD_LIBS_INIT} )

add_executable ( scout-test
    "source/control_flow_graph.cpp"
    "source/debugger.cpp"
    "source/debugger_load.cpp"
    "source/instruction.cpp"
    "source/text_canvas.cpp"
    "test/control_flow_graph_test.cpp"
    "test/debugger_test.cpp"
    "test/test_helper.cpp"
    "test/test_main.cpp"
    "test/text_canvas_test.cpp" )

target_include_directories ( scout-test PRIVATE
    "include/" )
target_link_libraries ( scout-test
    capstone-shared
    keystone
    "libunicorn.so"
    ${CMAKE_THREAD_LIBS_INIT} )
