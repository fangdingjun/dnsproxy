dnsutil
=======

a dns util

dns server

dnsproxy.py

    sudo python dnsproxy.py

    test  with this command
        dig @127.0.0.1 twitter.com
    
    set your dns to 127.0.0.

Compile:

    make

dnsclient

Usage:

    ./dnsc [-t type] [-s dnsserver] domain

Example:

    ./dnsc www.google.com
    ./dnsc -t AAAA www.google.com
    ./dnsc -t A www.google.com
    ./dnsc -s 8.8.8.8 www.google.com
    ./dnsc -s 4.2.2.2 www.google.com
    ./dnsc -t MX gmail.com
