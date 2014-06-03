#cmake_minimum_required(VERSION 2.8)

#project(dnsproxy C)

set(LIBRARY_OUTPUT_PATH ${dnsproxy_SOURCE_DIR}/src)
set(EXECUTABLE_OUTPUT_PATH ${dnsproxy_SOURCE_DIR}/src)

set(CMAKE_C_FLAGS "-Wall -O2")
#set(CMAKE_CXX_FLAGS "-Wall -O2")

add_definitions( -DVERSION="\\"0.1.1\\"")

if(WIN32)
    add_definitions( -DUSE_SELECT)
    link_libraries(ws2_32)
else()
    add_definitions( -DUSE_EPOLL)
endif()

add_executable(dnsc dnsc.c dnsutil.c)

add_executable(dnsproxy dnsproxy.c dnsutil.c parse_cfg.c dnsproxy.h)


