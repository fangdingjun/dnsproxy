#Dnsproxy#

----------

This is a dns proxy server written by C.

It has some features:

1. speedup the dns query     
       forward the client dns request to more than one dns servers and get the fastest response.
2. have a ip blacklist    
        don't forward the response to the client when the response ip is in the ip blacklist.

When use blacklist, you can drop the fake ip and ISP's ad ip, the blacklist is under your control.

For DNS cache pollution, refer to
[this link](http://zh.wikipedia.org/wiki/%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93).


##Requirement
 dnsproxy does not depend on the other libraries

##Compile

###Linux
on Linux, you can compile it with cmake or GNU automake

To use GNU automake, run command:

```bash
./gen.sh
 make
```

To use cmake, run command:

```bash
mkdir build
cd build
cmake ..
make
```
 
###Windows
on Windows, you can compile it to use mingw with cmake, MSVC is not support.

 run follow command to compile:

```bash
mkdir build
cd build
cmake -G "MinGW Makefiles" ..
mingw32-make
```
    
##Dns server

### dnsproxy

To run dnsproxy server, you need superuser privilege to listen on port 53

you can simple run

```bash
sudo ./dnsproxy
```

or sudo `./dnsproxy -c dnsproxy.cfg` to special a configure file

use `./dnsproxy -h` to show more options
    
test the server with this command on linux
```bash
dig @127.0.0.1 twitter.com
```    
or this command on windows
```bash
nslookup twitter.com 127.0.0.1
```            
you can set your system dns to 127.0.0.1

###Config file

the default configure is `dnsproxy.cfg` at current director, or you can use `-c` to special a other configure file

this is a sample configure file
```conf
listen_ip = 127.0.0.1
listen_port = 53
servers = 192.168.1.1,8.8.8.8,202.180.160.1,202.45.84.59,202.45.84.67
blacklist= iplist.txt
daemon = 1
logfile = dnsproxy.log
loglevel = 3
```    
##Dns client

There is a dns test client, named `dnsc`

Usage:
```bash
./dnsc [-t type] [-s dnsserver] domain
```
Example:
```bash
./dnsc www.google.com
./dnsc -t AAAA www.google.com
./dnsc -t A www.google.com
./dnsc -s 8.8.8.8 www.google.com
./dnsc -s 4.2.2.2 www.google.com
./dnsc -t MX gmail.com
```