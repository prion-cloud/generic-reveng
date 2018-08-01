cmake_minimum_required ( VERSION 3.8 )

add_compile_options ( "/std:c++17" )

add_definitions ( -D_SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING )

add_executable ( symbolizer
  "source/data_monitor.cpp"
  "source/intermediate.cpp"
  "source/json_intermediate.cpp"
  "source/instruction.cpp"
  "source/symbolizer.cpp" )

add_executable ( symbolizer_test
  "source/data_monitor.cpp"
  "source/intermediate.cpp"
  "source/json_intermediate.cpp"
  "test/test.cpp"
  "test/test_capstone.cpp"
  "test/test_data_monitor.cpp"
  "test/test_intermediate.cpp" )

include_directories (
  "thirdparty/capstone/include/"
  "thirdparty/catch2/single_include/"
  "thirdparty/rapidjson/include/" )

set ( CAPSTONE_BUILD_STATIC  OFF CACHE BOOL "Capstone: Build static library" )
set ( CAPSTONE_BUILD_TESTS   OFF CACHE BOOL "Capstone: Build tests" )

set ( CAPSTONE_ARM_SUPPORT   OFF CACHE BOOL "Capstone: ARM support" )
set ( CAPSTONE_ARM64_SUPPORT OFF CACHE BOOL "Capstone: ARM64 support" )
set ( CAPSTONE_MIPS_SUPPORT  OFF CACHE BOOL "Capstone: MIPS support" )
set ( CAPSTONE_PPC_SUPPORT   OFF CACHE BOOL "Capstone: PowerPC support" )
set ( CAPSTONE_SPARC_SUPPORT OFF CACHE BOOL "Capstone: Sparc support" )
set ( CAPSTONE_SYSZ_SUPPORT  OFF CACHE BOOL "Capstone: SystemZ support" )
set ( CAPSTONE_XCORE_SUPPORT OFF CACHE BOOL "Capstone: XCore support" )

add_subdirectory ( "thirdparty/capstone/" )

target_link_libraries ( symbolizer "thirdparty/capstone/capstone_dll" )
target_link_libraries ( symbolizer_test "thirdparty/capstone/capstone_dll" )
