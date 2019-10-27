cmake_minimum_required(VERSION 3.15)

add_subdirectory(submodule)

file(
    GLOB_RECURSE SOURCE_FILES
        source/*.cpp)

add_library(revengine
    SHARED
        ${SOURCE_FILES})
target_link_libraries(revengine
    PUBLIC
        z3)
target_include_directories(revengine
    PUBLIC
        include
        template)
