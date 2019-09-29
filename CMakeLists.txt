cmake_minimum_required(VERSION 3.15)

project(decompilation CXX)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(submodule)

file(
    GLOB_RECURSE SOURCE_FILES
        source/*.cpp)
add_library(decompilation
    SHARED
        ${SOURCE_FILES})
target_link_libraries(decompilation
    PRIVATE
        openreil
    PUBLIC
        z3)
target_include_directories(decompilation
    PRIVATE
        source
    PUBLIC
        include)

file(
    GLOB_RECURSE TEST_FILES
        test/*.cpp)
add_executable(test_decompilation
        ${TEST_FILES})
target_link_libraries(test_decompilation
    PRIVATE
        decompilation)
