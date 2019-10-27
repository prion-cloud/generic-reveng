cmake_minimum_required(VERSION 3.15)

add_subdirectory(submodule)

file(
    GLOB_RECURSE SOURCE_FILES
        source/*.cpp)

add_library(revengine-disassembler
    SHARED
        ${SOURCE_FILES})
target_link_libraries(revengine-disassembler
    PRIVATE
        openreil)
target_include_directories(revengine-disassembler
    PUBLIC
        include
        $<TARGET_PROPERTY:revengine,INCLUDE_DIRECTORIES>)
