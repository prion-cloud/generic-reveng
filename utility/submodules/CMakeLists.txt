cmake_minimum_required ( VERSION 3.11 )

set ( CAPSTONE_BUILD_STATIC       OFF CACHE BOOL "Capstone: Build static library" )
set ( CAPSTONE_BUILD_TESTS        OFF CACHE BOOL "Capstone: Build tests"          )
set ( CAPSTONE_BUILD_CSTOOL       OFF CACHE BOOL "Capstone: Build cstool"         )

set ( CAPSTONE_ARM_SUPPORT        OFF CACHE BOOL "Capstone: ARM support"          )
set ( CAPSTONE_ARM64_SUPPORT      OFF CACHE BOOL "Capstone: ARM64 support"        )
set ( CAPSTONE_EVM_SUPPORT        OFF CACHE BOOL "Capstone: EVM support"          )
set ( CAPSTONE_M680X_SUPPORT      OFF CACHE BOOL "Capstone: M680X support"        )
set ( CAPSTONE_M68K_SUPPORT       OFF CACHE BOOL "Capstone: M68K support"         )
set ( CAPSTONE_MIPS_SUPPORT       OFF CACHE BOOL "Capstone: MIPS support"         )
set ( CAPSTONE_PPC_SUPPORT        OFF CACHE BOOL "Capstone: PowerPC support"      )
set ( CAPSTONE_SPARC_SUPPORT      OFF CACHE BOOL "Capstone: Sparc support"        )
set ( CAPSTONE_SYSZ_SUPPORT       OFF CACHE BOOL "Capstone: SystemZ support"      )
set ( CAPSTONE_TMS320C64X_SUPPORT OFF CACHE BOOL "Capstone: TMS320C64X support"   )
set ( CAPSTONE_XCORE_SUPPORT      OFF CACHE BOOL "Capstone: XCore support"        )

add_subdirectory ( "capstone" )

# Unicorn has to be built manually

find_package ( Threads REQUIRED )

add_library ( capstone ALIAS capstone-shared )
add_library ( unicorn SHARED IMPORTED GLOBAL )

set_target_properties ( unicorn PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/unicorn/libunicorn.so" )

target_link_libraries ( unicorn INTERFACE
    ${CMAKE_THREAD_LIBS_INIT} )

target_include_directories ( capstone-shared INTERFACE
    "capstone/include" )
target_include_directories ( unicorn INTERFACE
    "unicorn/include" )
