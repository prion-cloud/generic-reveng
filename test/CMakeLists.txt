cmake_minimum_required(VERSION 3.15)

file(
    GLOB_RECURSE SOURCE_FILES
        source/*.cpp)

add_executable(test
        ${SOURCE_FILES})
target_link_libraries(test
    PRIVATE
        revengine
        revengine-disassembler)
