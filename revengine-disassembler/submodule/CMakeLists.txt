cmake_minimum_required(VERSION 3.15)

include(ExternalProject)
ExternalProject_Add(openreil-external
    SOURCE_DIR
        ${CMAKE_CURRENT_SOURCE_DIR}/openreil
    BUILD_IN_SOURCE
        TRUE
    CONFIGURE_COMMAND
        sh autogen.sh && sh configure
    INSTALL_COMMAND
        "")

add_library(openreil
    STATIC
    IMPORTED GLOBAL)
add_dependencies(openreil
        openreil-external)
set_target_properties(openreil PROPERTIES
    IMPORTED_LOCATION
        ${CMAKE_CURRENT_SOURCE_DIR}/openreil/libopenreil/src/libopenreil.a)
target_include_directories(openreil
    INTERFACE
        openreil/libopenreil/include)
