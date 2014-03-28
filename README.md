dnsutil
=======

there a two part, a dns client write by c, a dns proxy server write by python

the dns proxy server forward the dns query to the upstream dns server by tcp

##dns server

###dnsproxy.py
    cd python
    sudo python dnsproxy.py
        
test the server with this command:

    dig @127.0.0.1 twitter.com
            
you can set your system dns to 127.0.0.1

###dnsclient


Compile:

    cd c/
    make


Usage:

    ./dnsc [-t type] [-s dnsserver] domain

Example:

    ./dnsc www.google.com
    ./dnsc -t AAAA www.google.com
    ./dnsc -t A www.google.com
    ./dnsc -s 8.8.8.8 www.google.com
    ./dnsc -s 4.2.2.2 www.google.com
    ./dnsc -t MX gmail.com
