cmake_minimum_required(VERSION 3.15)

file(GLOB_RECURSE SOURCE_FILES
        *.cpp)

add_library(grev-disassembly
    SHARED
        ${SOURCE_FILES})

target_include_directories(grev-disassembly
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/template)
target_link_libraries(grev-disassembly
    PRIVATE
        openreil
    PUBLIC
        z3)
