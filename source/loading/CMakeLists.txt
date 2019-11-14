cmake_minimum_required(VERSION 3.15)

file(GLOB_RECURSE SOURCE_FILES
        *.cpp)

add_library(grev-loading
    SHARED
        ${SOURCE_FILES})

target_include_directories(grev-loading
    PRIVATE
        ${PROJECT_SOURCE_DIR}/source
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include)
