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

add_subdirectory ( "capstone/" )

# The "submodules/unicorn/make.sh" script has to be executed first
find_library ( UNICORN_LIBRARY unicorn PATHS "unicorn/" NO_DEFAULT_PATH )
