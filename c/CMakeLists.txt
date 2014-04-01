cmake_minimum_required(VERSION 2.8)

project(dnsutil)
find_package(PkgConfig)
pkg_check_modules(GLIB glib-2.0)
pkg_check_modules(GIO gio-2.0)

include_directories(${GLIB_INCLUDE_DIRS})
include_directories(${GIO_INCLUDE_DIRS})
link_directories(${GLIB_LIBRARY_DIRS})
link_directories(${GIO_LIBRARY_DIRS})

add_executable(dnsc dnsc.c)
add_library(dnsutil dnsutil.c)
#link_directories(.)
target_link_libraries(dnsc dnsutil)
add_executable(dnssrv dnssrv.c)
target_link_libraries(dnssrv ${GLIB_LIBRARIES} ${GIO_LIBRARIES})
