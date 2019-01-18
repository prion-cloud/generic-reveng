cmake_minimum_required ( VERSION 3.11 )

set ( CMAKE_CXX_STANDARD 17 )

add_subdirectory ( "submodules" )

file ( GLOB SOURCE_FILES "source/*.cpp" )

add_library ( utility SHARED
    ${SOURCE_FILES} )

target_link_libraries ( utility PUBLIC
    capstone
    unicorn )

target_include_directories ( utility INTERFACE
    "include" )
