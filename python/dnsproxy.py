import dnslib
import select
import socket
import Queue
import struct
import threading
import traceback
import time

class DnsProxy:
    def __init__(self):
        self.sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM,0)
        self.sock.bind(("127.0.0.1",53))
        self.servers=["8.8.8.8", "4.2.2.2", "8.8.4.4", "182.16.230.98",
                "111.68.8.179","208.67.222.222","208.67.220.220" ,
                ]
        self.num_servers=len(self.servers)
        self.recv_q=Queue.Queue(100)
        self.recv_q2=Queue.Queue(100)
        self.pending=[]
    def start(self):
        threads=[]
        for func in [self.recv, self.send_to_client]:
            t=threading.Thread(target=func)
            t.daemon=True
            t.start()
            threads.append(t)
        for s in self.servers:
            t=threading.Thread(target=self.forward_to_server,
                    args=(s,))
            t.daemon=True
            t.start()
        for t in threads:
            t.join()
    def recv(self):
        while True:
            rds,_,_=select.select([self.sock],[],[])
            for r in rds:
                buf,addr=r.recvfrom(1024)
                for i in range(self.num_servers):
                    self.recv_q.put((buf,addr))
                self.pending.append((buf,addr,time.time()))
    def forward_to_server(self,srv):
        print "create thread for", srv
        sock=None
        while True:
            buf,addr=self.recv_q.get() 
            try:
                l=struct.pack("!H",len(buf))
                #print repr(l)
                buf1=l+buf
                #print repr(buf1),len(buf1)
                if not sock:
                    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM,0)
                    sock.settimeout(2)
                    sock.connect((srv,53))
                sock.send(buf1)
                rds,_,_=select.select([sock],[],[],2)
                if rds:
                    buf2=sock.recv(4096)
                    if not buf2:
                        raise OSError("connection is closed")

                    # make sure dns header is contained
                    if len(buf2) >= 14:
                        self.recv_q2.put(buf2[2:])
                    else:
                        print "receive len",len(buf2)
                else:
                    raise OSError("connection is timeout")
            except:
                traceback.print_exc()
                try:
                    sock.close()
                except:
                    pass
                sock=None
    def send_to_client(self):
        while True:
            buf=self.recv_q2.get()
            try:
                msg1=dnslib.DNSRecord().parse(buf)
            except:
                traceback.print_exc()
                print len(self.pending)
                continue
            try:
                t1=time.time()
                for b,addr,t in self.pending:
                    if (t1-t) > 2:
                        self.pending.remove((b,addr,t))
                        continue
                    msg2=dnslib.DNSRecord().parse(b)
                    if msg1.header.id == msg1.header.id:
                        self.sock.sendto(buf,addr)
                        self.pending.remove((b,addr,t))
            except:
                traceback.print_exc()

if __name__ == "__main__":
    d=DnsProxy()
    d.start()
