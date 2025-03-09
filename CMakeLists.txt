cmake_minimum_required( VERSION 3.14 )
project( "WireGuard Config Generator" CXX )

set( CMAKE_CXX_STANDARD 23 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )
set( CMAKE_CXX_EXTENSIONS OFF )

find_package( PkgConfig REQUIRED )
pkg_check_modules( SODIUM REQUIRED libsodium )

add_executable( wgcg main.cpp )

target_include_directories( wgcg PRIVATE ${SODIUM_INCLUDE_DIRS} )
target_link_libraries( wgcg PRIVATE ${SODIUM_LIBRARIES} )
target_compile_options( wgcg PRIVATE ${SODIUM_CFLAGS_OTHER} )

if ( WIN32 )

    target_link_libraries( wgcg PRIVATE ws2_32 )
    
endif()