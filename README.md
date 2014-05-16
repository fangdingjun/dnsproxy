dnsutil
=======

this is a dns proxy server writen by C

the serve have some features:
  1. speedup the dns query

    forward the client dns request to more than one dns servers and get the fastest response
  2. have a ip blacklist
  
    don't forward the response to the client when the response ip is in the ip blacklist
  
for DNS cache pollution, refer to
<link>http://zh.wikipedia.org/wiki/%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93</link>

##requirement

there are two versions:

 dnsproxy.c is a pure c version, it does not depend the other libraries
 
 dnsproxy_glib is a glib version, need glib2


to compile the dnsproxy_glib, you need

    glib2 runtime files
    glib2 development files
    

on redhat, you can install glib2 by

    sudo yum install glib2 glib2-devel

on windows, you can download glib2 from
  <link>http://www.gtk.org/download/win32.php</link>

 

##compile
on Linux

    ./gen.sh
     make

on Windows, install MinGW/MSYS and cmake, compile with MSYS

    cd src
    cmake -G "MSYS makefiles"
    make
    
or compile with MinGW

    cd src
    cmake -G "MinGW Makefiles"
    mingw32-make
    
##dns server

### dnsproxy

To run dnsproxy, you need superuser privilege to listen on port 53

    sudo ./dnsproxy 

test the server with this command on linux

    dig @127.0.0.1 twitter.com
or this command on windows

    nslookup twitter.com 127.0.0.1
            
you can set your system dns to 127.0.0.1

###dnsclient

there is a dns test client, named dnsc

Usage:

    ./dnsc [-t type] [-s dnsserver] domain

Example:

    ./dnsc www.google.com
    ./dnsc -t AAAA www.google.com
    ./dnsc -t A www.google.com
    ./dnsc -s 8.8.8.8 www.google.com
    ./dnsc -s 4.2.2.2 www.google.com
    ./dnsc -t MX gmail.com
