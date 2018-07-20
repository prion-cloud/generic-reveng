cmake_minimum_required (VERSION 3.8)

if(MSVC)
  add_compile_options("/std:c++17")
else()
  add_compile_options("-std=c++17")
endif()

add_executable (symbolizer "symbolizer/symbolizer.cpp" "symbolizer/symbolizer.h")
