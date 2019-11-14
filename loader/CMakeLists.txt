cmake_minimum_required(VERSION 3.15)

file(
    GLOB_RECURSE SOURCE_FILES
        source/*.cpp)

add_library(loader
    SHARED
        ${SOURCE_FILES})
target_include_directories(loader
    PRIVATE
        source
    PUBLIC
        include)
