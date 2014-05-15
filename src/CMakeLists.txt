cmake_minimum_required(VERSION 2.0)

project(dnsproxy)

set(CMAKE_C_FLAGS "-Wall -O2")
set(CMAKE_CXX_FLAGS "-Wall -O2")

find_package(PkgConfig)
pkg_check_modules(GLIB glib-2.0)
pkg_check_modules(GIO gio-2.0)

include_directories(${GLIB_INCLUDE_DIRS})
include_directories(${GIO_INCLUDE_DIRS})
link_directories(${GLIB_LIBRARY_DIRS})
link_directories(${GIO_LIBRARY_DIRS})

add_executable(dnsc dnsc.c dnsutil.c)
#add_library(dnsutil dnsutil.c)
#link_directories(.)
#target_link_libraries(dnsc dnsutil)
#add_executable(dnssrv dnssrv.c)
#target_link_libraries(dnssrv ${GLIB_LIBRARIES} ${GIO_LIBRARIES})

add_executable(dnsproxy dnsproxy.c dnsutil.c)

add_executable(dnsproxy_glib dnsproxy_glib.c dnsutil.c)
target_link_libraries(dnsproxy_glib ${GLIB_LIBRARIES} ${GIO_LIBRARIES})
if(WIN32)
    add_definitions( -DUSE_SELECT)
    target_link_libraries(dnsproxy_glib ws2_32)
    target_link_libraries(dnsc ws2_32)
    target_link_libraries(dnsproxy ws2_32)
else()
    add_definitions( -DUSE_EPOLL)
endif()
