#cmake_minimum_required(VERSION 2.8)

#project(dnsproxy C)

set(LIBRARY_OUTPUT_PATH ${dnsproxy_SOURCE_DIR}/src)
set(EXECUTABLE_OUTPUT_PATH ${dnsproxy_SOURCE_DIR}/src)

set(CMAKE_C_FLAGS "-Wall -O2")
#set(CMAKE_CXX_FLAGS "-Wall -O2")

add_definitions("-DHAVE_CONFIG_H")

if (WIN32)
    include_directories( ${dnsproxy_SOURCE_DIR}/third-part/ldns-1.6.17/win)
else()
    include_directories( ${dnsproxy_SOURCE_DIR}/third-part/ldns-1.6.17/linux)
endif()

include_directories( ${dnsproxy_SOURCE_DIR}/third-part/ldns-1.6.17/)

add_library(ldns 
    ../third-part/ldns-1.6.17/buffer.c
    ../third-part/ldns-1.6.17/dane.c
    ../third-part/ldns-1.6.17/dname.c
    ../third-part/ldns-1.6.17/dnssec.c
    ../third-part/ldns-1.6.17/dnssec_sign.c
    ../third-part/ldns-1.6.17/dnssec_verify.c
    ../third-part/ldns-1.6.17/dnssec_zone.c
    ../third-part/ldns-1.6.17/duration.c
    ../third-part/ldns-1.6.17/error.c
    ../third-part/ldns-1.6.17/higher.c
    ../third-part/ldns-1.6.17/host2str.c
    ../third-part/ldns-1.6.17/host2wire.c
    ../third-part/ldns-1.6.17/keys.c
    #../third-part/ldns-1.6.17/linktest.c
    ../third-part/ldns-1.6.17/net.c
    ../third-part/ldns-1.6.17/packet.c
    ../third-part/ldns-1.6.17/parse.c
    ../third-part/ldns-1.6.17/radix.c
    ../third-part/ldns-1.6.17/rbtree.c
    ../third-part/ldns-1.6.17/rdata.c
    ../third-part/ldns-1.6.17/resolver.c
    ../third-part/ldns-1.6.17/rr.c
    ../third-part/ldns-1.6.17/rr_functions.c
    ../third-part/ldns-1.6.17/sha1.c
    ../third-part/ldns-1.6.17/sha2.c
    ../third-part/ldns-1.6.17/str2host.c
    ../third-part/ldns-1.6.17/tsig.c
    ../third-part/ldns-1.6.17/update.c
    ../third-part/ldns-1.6.17/util.c
    ../third-part/ldns-1.6.17/wire2host.c
    ../third-part/ldns-1.6.17/zone.c
    ../third-part/ldns-1.6.17/compat/b64_ntop.c
    ../third-part/ldns-1.6.17/compat/b64_pton.c
    ../third-part/ldns-1.6.17/compat/calloc.c
    ../third-part/ldns-1.6.17/compat/ctime_r.c
    #../third-part/ldns-1.6.17/compat/fake-rfc2553.c
    ../third-part/ldns-1.6.17/compat/gmtime_r.c
    ../third-part/ldns-1.6.17/compat/inet_aton.c
    ../third-part/ldns-1.6.17/compat/inet_ntop.c
    ../third-part/ldns-1.6.17/compat/inet_pton.c
    #../third-part/ldns-1.6.17/compat/isascii.c
    ../third-part/ldns-1.6.17/compat/isblank.c
    ../third-part/ldns-1.6.17/compat/localtime_r.c
    ../third-part/ldns-1.6.17/compat/malloc.c
    ../third-part/ldns-1.6.17/compat/memmove.c
    ../third-part/ldns-1.6.17/compat/realloc.c
    #../third-part/ldns-1.6.17/compat/snprintf.c
    ../third-part/ldns-1.6.17/compat/strlcpy.c
    ../third-part/ldns-1.6.17/compat/timegm.c
)

add_definitions( -DVERSION="\\"0.1.1\\"")
add_library(sqlite
    ${dnsproxy_SOURCE_DIR}/third-part/sqlite/sqlite3.c
    ${dnsproxy_SOURCE_DIR}/third-part/sqlite/sqlite3.h
)

if(WIN32)
    add_definitions( -DUSE_SELECT)
else()
    add_definitions( -DUSE_EPOLL)
endif()

include_directories( ${dnsproxy_SOURCE_DIR}/third-part/sqlite/)

add_executable(dnsc dnsc.c)

#add_executable(dnsproxy dnsproxy.c dnsutil.c parse_cfg.c dnsproxy.h cache.c)

#target_link_libraries(dnsproxy ldns sqlite)
target_link_libraries(dnsc ldns)
if(WIN32)
    target_link_libraries(dnsc ws2_32)
    #target_link_libraries(dnsproxy ws2_32)
else()
    #target_link_libraries(dnsproxy dl pthread)
endif()

add_definitions("-DHAVE_READLINE=1")

add_executable(sqlite3
    ${dnsproxy_SOURCE_DIR}/third-part/sqlite/shell.c
    ${dnsproxy_SOURCE_DIR}/third-part/sqlite/sqlite3ext.h
    )
target_link_libraries(sqlite3 sqlite)

if(WIN32)
    target_link_libraries(sqlite readline)
else()
    target_link_libraries(sqlite dl pthread readline)
endif()

add_executable(dnsproxy 
    dnsproxy_ldns.c
    parse_cfg.c
    cache2.c
)

target_link_libraries(dnsproxy ldns sqlite)

if(WIN32)
    target_link_libraries(dnsproxy ws2_32)
endif()
