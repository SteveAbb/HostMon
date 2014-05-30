#! /usr/bin/env python
from scapy.all import *
import threading,os,sys,signal

conf.verb=0
hosts={}
lock=threading.Lock()
stillRun=True
timeout=1

def main():
	global timeout
	if (len(sys.argv) > 1):
		timeout=sys.argv[1]
	signal.signal(signal.SIGINT, signal_handler)
	HostMon().start()
	sniff(prn=arp_monitor_callback, filter="arp", store=0)
		
def hostOnline(host):
	packet = IP(dst=host, ttl=20)/ICMP()
	reply = sr1(packet, timeout=int(timeout))
	if not (reply is None):
		return True
	else:
		return False
	
class HostMon(threading.Thread):
	def run(self):
		while stillRun:
			lock.acquire()
			hostsToRemove=[]
			for mac in hosts:
				if not hostOnline(hosts[mac]):
					hostsToRemove.append(mac)
			for mac in hostsToRemove:
				del hosts[mac]
			os.system('clear');
			printTitle()
			for mac in hosts:
				print mac+"\t"+hosts[mac]
			lock.release()
			time.sleep(1)

def printTitle():
	print "[Starting HostMon]"
	print "ICMP Timeout: "+str(timeout)
	print "============================="
	print "MAC\t\t\tHOST"
	print "---\t\t\t----"

def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2):
    	mac=pkt.sprintf("%ARP.hwsrc%")
    	ip=pkt.sprintf("%ARP.psrc%")
    	if (mac not in hosts):
    		lock.acquire()
    		hosts[mac]=ip
    		lock.release()
    		
def signal_handler(signal, frame):
	global stillRun
	print "[+] Exiting"
	stillRun=False;
	sys.exit(0)

if __name__ == "__main__":
	main()