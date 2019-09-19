cmake_minimum_required(VERSION 3.15)

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
        z3)
target_include_directories(decompilation
    PRIVATE
        source
    PUBLIC
        include)

file(
    GLOB_RECURSE TEST_FILES
        test/*.cpp)
add_executable(test
        ${TEST_FILES})
target_link_libraries(test
    PRIVATE
        decompilation)
