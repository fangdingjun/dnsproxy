#cmake_minimum_required(VERSION 2.8)

#project(dnsproxy C)

set(LIBRARY_OUTPUT_PATH ${dnsproxy_SOURCE_DIR}/src)
set(EXECUTABLE_OUTPUT_PATH ${dnsproxy_SOURCE_DIR}/src)

set(CMAKE_C_FLAGS "-Wall -O2")
#set(CMAKE_CXX_FLAGS "-Wall -O2")

add_definitions( -DVERSION="\\"0.1.1\\"")

if(WIN32)
    add_definitions( -DUSE_SELECT)
else()
    add_definitions( -DUSE_EPOLL)
endif()

include_directories( ${dnsproxy_SOURCE_DIR}/third-part/sqlite/)

add_executable(dnsc dnsc.c dnsutil.c)

add_executable(dnsproxy dnsproxy.c dnsutil.c parse_cfg.c dnsproxy.h cache.c
    ${dnsproxy_SOURCE_DIR}/third-part/sqlite/sqlite3.c
    ${dnsproxy_SOURCE_DIR}/third-part/sqlite/sqlite3.h
    )

if(WIN32)
    target_link_libraries(dnsc ws2_32)
    target_link_libraries(dnsproxy ws2_32)
else()
    target_link_libraries(dnsproxy dl pthread)
endif()

add_definitions("-DHAVE_READLINE=1")

add_executable(sqlite
    ${dnsproxy_SOURCE_DIR}/third-part/sqlite/shell.c
    ${dnsproxy_SOURCE_DIR}/third-part/sqlite/sqlite3.c
    ${dnsproxy_SOURCE_DIR}/third-part/sqlite/sqlite3.h
    ${dnsproxy_SOURCE_DIR}/third-part/sqlite/sqlite3ext.h
    )

if(WIN32)
    target_link_libraries(sqlite readline)
else()
    target_link_libraries(sqlite dl pthread readline)
endif()

