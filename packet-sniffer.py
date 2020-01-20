from sys import *
from socket import *
from struct import *

#TCP Header Control Flags
FIN = 128	# 10000000
SYN = 64	# 01000000
RST = 32	# 00100000
PSH = 16	# 00010000
ACK = 8		# 00001000
URG = 4		# 00000100
ECE = 2		# 00000010
CWR = 1		# 00000001

class EthHdr(object):
	def __init__(self):
		pass

	def parse_hdr(self, packet):
		self.dest_mac, self.src_mac, self.protocol = unpack("! 6s 6s H", packet[:14])
		self.dest_mac = self.get_mac_addr(self.dest_mac)
		self.src_mac = self.get_mac_addr(self.src_mac)
		self.protocol = ntohs(self.protocol)
		return packet[14:]

	def get_mac_addr(self, byte_addr):
		octets = map("{:02x}".format, byte_addr)
		return ":".join(octets).upper()

	def display(self):
		print("\n[+] Ethernet Header:")
		print("    - Destination MAC\t\t: {}".format(self.dest_mac))
		print("    - Source MAC\t\t: {}".format(self.src_mac))
		print("    - Protocol\t\t\t: {}".format(self.protocol))

class IpHdr(object):
	def __init__(self):
		pass

	def parse_hdr(self, packet):
		ver_ihl, self.tos, self.tot_len, self.id, self.ttl, self.protocol, self.saddr, self.daddr = \
			unpack("! BBHH 2x BB 2x 4s 4s", packet[:20])

		self.version = (ver_ihl >> 4)
		self.ihl = (ver_ihl & 0xF) # 0xF = 15 = 00001111
		return packet[(self.ihl*4):]

	def display(self):
		print("\n[+] IP Header:")
		print("    - Version\t\t\t: {}".format(self.version))
		print("    - IHL\t\t\t: {}".format(self.ihl))
		print("    - TOS\t\t\t: {}".format(self.tos))
		print("    - Tot Len\t\t\t: {}".format(self.tot_len))
		print("    - ID\t\t\t: {}".format(self.id))
		print("    - TTL\t\t\t: {}".format(self.ttl))
		print("    - Protocol\t\t\t: {}".format(self.protocol))
		print("    - Source IP\t\t\t: {}".format(inet_ntoa(self.saddr)))
		print("    - Destination IP\t\t: {}".format(inet_ntoa(self.daddr)))

class TcpHdr(object):
	def __init__(self):
		pass

	def parse_hdr(self, packet):
		self.src_port, self.dest_port, self.seq, self.ack, offset_resv, self.flags = \
			unpack("! HHLLBB", packet[:14])

		offset = (offset_resv >> 4) * 4
		return packet[offset:]

	def display(self):
		print("\n[+] TCP Header:")
		print("    - Source Port\t\t: {}".format(self.src_port))
		print("    - Destination Port\t\t: {}".format(self.dest_port))
		print("    - Seq #\t\t\t: {}".format(self.seq))
		print("    - Ack #\t\t\t: {}".format(self.ack))
		print("    - Flags\t\t\t:", end='')

		if (self.flags):
			if (self.flags & FIN == FIN):
				print(" FIN", end='')
			if (self.flags & SYN == SYN):
				print(" SYN", end='')
			if (self.flags & RST == RST):
				print(" RST", end='')
			if (self.flags & PSH == PSH):
				print(" PSH", end='')
			if (self.flags & ACK == ACK):
				print(" ACK", end='')
			if (self.flags & URG == URG):
				print(" URG", end='')
			if (self.flags & ECE == ECE):
				print(" ECE", end='')
			if (self.flags & CWR == CWR):
				print(" CWR", end='')
			print()
		else:
			print(" No flags")

class IcmpHdr(object):
	def __init__(self):
		pass

	def parse_hdr(self, packet):
		self.type, self.code, self.checksum = unpack("! B B H", packet[:4])
		return packet[4:]

	def display(self):
		print("\n[+] ICMP Header:")
		print("    - Type\t\t\t: {}".format(self.type))
		print("    - Code\t\t\t: {}".format(self.code))
		print("    - Checksum\t\t\t: {}".format(self.checksum))

class UdpHdr(object):
	def __init__(self):
		pass

	def parse_hdr(self, packet):
		self.src_port, self.dest_port, self.length, self.checksum = \
			unpack("!HHHH", packet[:8])
		return packet[8:]

	def display(self):
		print("\n[+] UDP Header:")
		print("    - Source Port\t\t: {}".format(self.src_port))
		print("    - Destination Port\t\t: {}".format(self.dest_port))
		print("    - Length\t\t\t: {}".format(self.length))
		print("    - Checksum\t\t\t: {}".format(self.checksum))

def dump(packet):
	count = 0
	print("\n[+] Hex Dump:")
	hex = list(map("{:02x}".format, packet))

	for i in range(len(hex)):
		print(str(hex[i]).upper() + " ", end='')
		if ((i%16) == 15 or i == (len(hex)-1)):
			for j in range(15-(i%16)):
				print("   ", end='')
			print("| ", end='')

			for j in range(count*16, i+1):
				n = int(hex[j], 16)
				if (n > 31 and n < 127):
					print(chr(n), end='')
				else:
					print(".", end='')
			count += 1
			print()

def main():
	if (len(argv) < 3):
		print("Usage: {} <# of packets to sniff> <icmp/tcp/udp/any>".format(argv[0]))
		return

	sockfd = socket(AF_PACKET, SOCK_RAW, htons(0x0800))
	iter = int(argv[1])
	protocol = str(argv[2])
	ethhdr = EthHdr()
	iphdr = IpHdr()

	while (iter):
		packet, addr = sockfd.recvfrom(65535)
		size = len(packet)
		packet = ethhdr.parse_hdr(packet)

		if (ethhdr.protocol == 8):
			packet = iphdr.parse_hdr(packet)

			# ICMP header
			if ((iphdr.protocol == 1 and protocol == "icmp") or (iphdr.protocol == 1 and protocol == "any")):
				icmphdr = IcmpHdr()
				packet = icmphdr.parse_hdr(packet)

				if (len(packet)):
					print("\n[+] Got a {} byte packet...".format(size))
					ethhdr.display()
					iphdr.display()
					icmphdr.display()
					dump(packet)
					iter -= 1
					print("\n\t\t\t*** END ***")
			# TCP header
			elif ((iphdr.protocol == 6 and protocol == "tcp") or (iphdr.protocol == 6 and protocol == "any")):
				tcphdr = TcpHdr()
				packet = tcphdr.parse_hdr(packet)

				if (len(packet)):
					print("\n[+] Got a {} byte packet...".format(size))
					ethhdr.display()
					iphdr.display()
					tcphdr.display()
					dump(packet)
					iter -= 1
					print("\n\t\t\t*** END ***")
			# UDP header
			elif ((iphdr.protocol == 17 and protocol == "udp") or (iphdr.protocol == 17 and protocol == "any")):
				udphdr = UdpHdr()
				packet = udphdr.parse_hdr(packet)

				if (len(packet)):
					print("\n[+] Got a {} byte packet...".format(size))
					ethhdr.display()
					iphdr.display()
					udphdr.display()
					dump(packet)
					iter -= 1
					print("\n\t\t\t*** END ***")

if __name__ == "__main__":
	main()
















