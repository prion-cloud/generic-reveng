cmake_minimum_required(VERSION 3.15)

# ./autogen.sh
# ./configure
# make
add_library(openreil
    STATIC
    IMPORTED GLOBAL)
set_target_properties(openreil PROPERTIES
    IMPORTED_LOCATION
        ${CMAKE_CURRENT_SOURCE_DIR}/openreil/libopenreil/src/libopenreil.a)
target_include_directories(openreil
    INTERFACE
        openreil/libopenreil/include)
