cmake_minimum_required ( VERSION 3.8 )

add_compile_options ( "/std:c++17" )

add_executable ( symbolizer
  "source/data_flow.cpp" "source/data_flow.h"
  "source/symbolizer.cpp" )

add_executable ( symbolizer_test
  "source/data_flow.cpp" "source/data_flow.h"
  "test/helper.h"
  "test/test.cpp"
  "test/test_capstone.cpp"
  "test/test_data_flow.cpp" )

find_library ( CAPSTONE_LIB capstone PATHS "capstone/build/" )

target_link_libraries ( symbolizer "${CAPSTONE_LIB}" )
target_link_libraries ( symbolizer_test "${CAPSTONE_LIB}" )
