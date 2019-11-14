cmake_minimum_required(VERSION 3.15)

project(generic-reveng CXX)
set(CMAKE_CXX_STANDARD 20)

add_subdirectory(loader)

add_subdirectory(revengine)
add_subdirectory(revengine-disassembler)

add_subdirectory(test)
