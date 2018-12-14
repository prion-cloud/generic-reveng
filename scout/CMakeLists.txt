file ( GLOB SCOUT_SOURCES "source/*.cpp" )

add_executable ( scout ${SCOUT_SOURCES} )

target_link_libraries ( scout scout-api )
