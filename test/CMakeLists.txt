cmake_minimum_required(VERSION 3.15)

file(GLOB_RECURSE SOURCE_FILES
        *.cpp)

add_executable(test
        ${SOURCE_FILES})

target_include_directories(test
    PRIVATE
        ${PROJECT_SOURCE_DIR}/test)
target_link_libraries(test
    PRIVATE
        grev-analysis
        grev-analysis-disassembly
        grev-loading)
