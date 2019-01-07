cmake_minimum_required ( VERSION 3.8 )

set ( CMAKE_CXX_STANDARD 17 )

# UNICORN: The "submodules/unicorn/make.sh" script has to be executed first
find_package ( Threads REQUIRED )
add_library ( unicorn-shared SHARED IMPORTED )
set_target_properties ( unicorn-shared PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/submodules/unicorn/libunicorn.so" )

add_subdirectory ( "scout-api/" )

add_subdirectory ( "submodules/" )

target_include_directories ( scout-api PUBLIC
    "submodules/capstone/include/"
    "submodules/stimpak/include/"
    "submodules/unicorn/include/" )
