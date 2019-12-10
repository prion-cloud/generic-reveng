cmake_minimum_required(VERSION 3.15)

file(GLOB_RECURSE SOURCE_FILES
        *.cpp)

add_executable(application
        ${SOURCE_FILES})

target_link_libraries(application
    PRIVATE
        grev
        grev-lift
        grev-load)
