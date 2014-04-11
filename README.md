dnsutil
=======

this is a dns proxy server writen by c with glib

the serve have some features:
  1. forward the request to more than one upstream dns servers and get the fastest response
  2. use the ip blacklist to avoid DNS cache pollution

##requirement
 glib runtime and glib development files

on Linux
 yum install glib2 glib2-devel

on windows
download gtk+-bundle_xxxxxx_win32.zip
http://ftp.gnome.org/pub/gnome/binaries/win32/gtk+/2.24/

##compile
Linux
   
   ./gen.sh
    make

Windows

    cd src
    cmake -G "MSYS makefiles"
    make

##dns server

### dnsproxy

    sudo ./dnsproxy 

test the server with this command:

    dig @127.0.0.1 twitter.com
            
you can set your system dns to 127.0.0.1

###dnsclient

Usage:

    ./dnsc [-t type] [-s dnsserver] domain

Example:

    ./dnsc www.google.com
    ./dnsc -t AAAA www.google.com
    ./dnsc -t A www.google.com
    ./dnsc -s 8.8.8.8 www.google.com
    ./dnsc -s 4.2.2.2 www.google.com
    ./dnsc -t MX gmail.com
