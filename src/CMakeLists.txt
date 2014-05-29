cmake_minimum_required(VERSION 2.8)

project(dnsproxy C)

set(CMAKE_C_FLAGS "-Wall -O2")
#set(CMAKE_CXX_FLAGS "-Wall -O2")

find_package(PkgConfig)

pkg_check_modules(GLIB glib-2.0)
pkg_check_modules(GIO gio-2.0)

if(GLIB_FOUND)
    include_directories(${GLIB_INCLUDE_DIRS})
    include_directories(${GIO_INCLUDE_DIRS})
    link_directories(${GLIB_LIBRARY_DIRS})
    link_directories(${GIO_LIBRARY_DIRS})
endif()

add_definitions( -DVERSION="\\"0.1.1\\"")

if(WIN32)
    add_definitions( -DUSE_SELECT)
    link_libraries(ws2_32)
else()
    add_definitions( -DUSE_EPOLL)
endif()

add_executable(dnsc dnsc.c dnsutil.c)

add_executable(dnsproxy dnsproxy.c dnsutil.c parse_cfg.c dnsproxy.h)

if(GLIB_FOUND)
    add_executable(dnsproxy_glib dnsproxy_glib.c dnsutil.c)
    target_link_libraries(dnsproxy_glib ${GLIB_LIBRARIES} ${GIO_LIBRARIES})
endif()

