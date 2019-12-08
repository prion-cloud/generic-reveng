cmake_minimum_required(VERSION 3.15)

file(GLOB_RECURSE SOURCE_FILES
        *.cpp)

add_executable(test
        ${SOURCE_FILES})

target_include_directories(test
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test
    PRIVATE
        grev
        grev-lift
        grev-load)
