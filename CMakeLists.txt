cmake_minimum_required (VERSION 3.8)

add_compile_options("/std:c++17")
add_executable (symbolizer "symbolizer/symbolizer.cpp" "symbolizer/symbolizer.h")
