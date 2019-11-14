cmake_minimum_required(VERSION 3.15)

file(
    GLOB_RECURSE MOCKUP_FILES
        mockup/*.cpp)
file(
    GLOB_RECURSE SOURCE_FILES
        source/*.cpp)

add_executable(test
        ${MOCKUP_FILES}
        ${SOURCE_FILES})
target_link_libraries(test
    PRIVATE
        loader
        revengine
        revengine-disassembler)
target_include_directories(test
    PRIVATE
        mockup
        source)
