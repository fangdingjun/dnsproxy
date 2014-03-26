dnsutil
=======

a dns util support RFC1035

Compile:
  make

Usage:
    ./dnsc [-t type] [-s dnsserver] domain

Example
    ./dnsc www.google.com
    ./dnsc -t AAAA www.google.com
    ./dnsc -t A www.google.com
    ./dnsc -s 8.8.8.8 www.google.com
    ./dnsc -s 4.2.2.2 www.google.com
    ./dnsc -t MX gmail.com
