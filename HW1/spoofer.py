from scapy.all import *
from scapy.layers.inet import *


def send_packet(src_ip,dst_ip,dst_port,payload):
    if(len(payload)>150):
        exit()
    if(dst_port.isnumeric() == False):
        exit() 
    if(valid_ip(src_ip)== False or valid_ip(dst_ip)== False):
        exit()                 
    send(IP(src = src_ip, dst = dst_ip)/UDP(dport = RawVal(dst_port))/Raw(load=payload))



  
    