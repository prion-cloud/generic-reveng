cmake_minimum_required(VERSION 3.15)

file(GLOB_RECURSE SOURCE_FILES
        *.cpp)

add_library(grev-load
    SHARED
        ${SOURCE_FILES})

target_include_directories(grev-load
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include)
