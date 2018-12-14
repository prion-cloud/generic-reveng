cmake_minimum_required ( VERSION 3.8 )

set ( CMAKE_CXX_STANDARD 17 )

find_package ( Threads REQUIRED )

add_subdirectory ( "scout/" )
add_subdirectory ( "scout-api/" )

add_subdirectory ( "submodules/" )

target_include_directories ( scout-api PUBLIC
    "submodules/capstone/include/"
    "submodules/stimpak/include/"
    "submodules/unicorn/include/" )
