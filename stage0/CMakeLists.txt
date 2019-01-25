cmake_minimum_required ( VERSION 3.11 )

set ( CMAKE_CXX_STANDARD 17 )

file ( GLOB SOURCE_FILES "source/*.cpp" )
file ( GLOB TEST_FILES "test/*.cpp" )

add_library ( stage0 SHARED
    ${SOURCE_FILES} )
add_executable ( stage0-test
    ${TEST_FILES} )

set_target_properties ( stage0 PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} )

target_link_libraries ( stage0 PRIVATE
    stimpak
    utility )
target_link_libraries ( stage0-test PRIVATE
    stage0
    stimpak
    utility )

target_include_directories ( stage0
    PRIVATE "include"
    INTERFACE "include" )
