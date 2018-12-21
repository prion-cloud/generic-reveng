file ( GLOB SCOUT_API_SOURCES      "source/*.cpp" )
file ( GLOB SCOUT_API_TEST_SOURCES "test/*.cpp"   )

add_library    ( scout-api      SHARED ${SCOUT_API_SOURCES}      )
add_executable ( scout-api-test        ${SCOUT_API_TEST_SOURCES} )

target_link_libraries ( scout-api
    capstone-shared
    unimage
    ${UNICORN_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT} )
target_link_libraries ( scout-api-test
    scout-api )
