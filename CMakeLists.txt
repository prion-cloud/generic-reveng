cmake_minimum_required(VERSION 3.15)

project(revengine CXX)
set(CMAKE_CXX_STANDARD 17)

add_subdirectory(revengine)
add_subdirectory(revengine-disassembler)

add_subdirectory(test)
