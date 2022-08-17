
import sys
from scapy.all import *
from scapy.layers.dns import DNSQR, DNSRR, DNS, DNS
from scapy.layers.inet import IP, UDP
from collections import deque
from scapy.all import *
import datetime
from scapy.layers.inet6 import IPv6
import getopt


pkt_queue = deque(maxlen=50)
OgIP = ""
file = open("attack_log.txt","w")

def DnsDetect(pkt):
    global OgIP
    if not pkt.haslayer(DNSRR): 
        OgIP = pkt[1].src
        return

    if(pkt.haslayer(IP)):
        ip = IP
    else:
         ip = IPv6

    if len(pkt_queue):
        for op in pkt_queue:
            
            if op[ip].dst == pkt[ip].src and op[ip].dport == pkt[ip].sport and op[ip].sport == pkt[ip].dport and op[ip].payload != pkt[ip].payload and op[DNSRR].rdata != pkt[DNSRR].rdata and op[DNS].id == pkt[DNS].id and op[DNS].qd.qname == pkt[DNS].qd.qname:
                request = op[DNS].qd.qname.decode(encoding='UTF-8')
                request = request[:-1] if request.endswith('.') else request
                if(op[ip].src ==OgIP):
                    date = datetime.datetime.fromtimestamp(round(op.time))
                    date = date.strftime("%B %d %Y %H:%M:%S")
                    file.write( "-" + date+"\n" )
                    file.write("-TXID"+ hex(op[DNS].id)+"Request"+request+"\n" )
                    file.write("-Answer1 [{}]".format(pkt[DNSRR].rdata)+"\n" )
                    file.write("-Answer2 [{}]".format(op[DNSRR].rdata)+"\n\n" )
                else:
                    date = datetime.datetime.fromtimestamp(round(pkt.time))
                    date = date.strftime("%B %d %Y %H:%M:%S")
                    file.write( "-"+date +"\n" )
                    file.write("-TXID"+hex(op[DNS].id)+"Request"+request+"\n" )
                    file.write("-Answer1 [{}]".format(op[DNSRR].rdata)+"\n" )
                    file.write("-Answer2 [{}]".format(pkt[DNSRR].rdata)+"\n\n" )
    pkt_queue.append(pkt)
    

if __name__ == '__main__':
    
    defaultif = 'en0'
    interface = None
    try:
        opt,ex = getopt.getopt(sys.argv[1:], "i:r:", ["interface", "tracefile"])

    except getopt.GetoptError as err:
        print (err)
        sys.exit()

    for opts, arg in opt:
        if opts in ("-i", "--interface"):
            interface = arg
        elif opts in ("-r", "--tracefile"):
            tracefile = arg
        else:
            assert False, "wrong"
     

    if interface and tracefile:
        sys.exit()
  
    if interface: 
        sniff(filter='port 53', iface=interface, prn=DnsDetect)
    elif tracefile: 
        sniff(filter='port 53', offline=tracefile, prn=DnsDetect)
    else: 
        sniff(filter='port 53', iface=defaultif, prn=DnsDetect)
    