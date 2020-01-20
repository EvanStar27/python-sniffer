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
CWR	= 1		# 00000001

def get_mac_addr(byte_addr):
	octets = map("{:02x}".format, byte_addr)
	return ":".join(octets).upper()

def parse_ethhdr(packet):
	dmac, smac, proto = unpack("! 6s 6s H", packet[:14])
	dmac = get_mac_addr(dmac)
	smac = get_mac_addr(smac)

	print("[+] Ethernet Layer:")
	print("    - Destination MAC\t: %s" %dmac)
	print("    - Source MAC\t: %s" %smac)
	print("    - Protocol\t\t: %s" %ntohs(proto))
	return packet[14:]

def parse_iphdr(packet):
	ver_ihl, tos, tot_len, id, flag_frag, ttl, proto, check, src, dest = unpack("! BBHHHBBH4s4s", packet[:20])

	version = (ver_ihl >> 4)
	ihl = (ver_ihl & 0xF) # 0xF is 1111 binary

	print("\n[+] IP Layer:")
	print("    - Version\t\t: IPv%d" %version)
	print("    - IHL\t\t: %d" %ihl)
	print("    - TOS\t\t: %d" %tos)
	print("    - TOT LEN\t\t: %d" %tot_len)
	print("    - ID\t\t: %d" %id)
	print("    - TTL\t\t: %d" %ttl)
	print("    - Protocol\t\t: %d" %proto)
	print("    - Source IP\t\t: %s" %inet_ntoa(src))
	print("    - Destination IP\t: %s" %inet_ntoa(dest))
	return packet[(ihl*4):]

def parse_tcphdr(packet):
	sport, dport, seq, ack, data_off_resv, flags  = \
		unpack("!HHLLBB", packet[:14])

	offset = (data_off_resv >> 4) * 4

	print("\n[+] TCP Layer:")
	print("    - Source Port\t: %d" %ntohs(sport))
	print("    - Destination Port\t: %d" %ntohs(dport))
	print("    - Seq #\t\t: %s" %str(seq))
	print("    - Ack #\t\t: %s" %str(ack))
	print("    - Flags\t\t:", end='')

	if (flags):
		if (flags & FIN == FIN):
			print(" FIN", end='')
		if (flags & SYN == SYN):
			print(" SYN", end='')
		if (flags & RST == RST):
			print(" RST", end='')
		if (flags & PSH == PSH):
			print(" PSH", end='')
		if (flags & ACK == ACK):
			print(" ACK", end='')
		if (flags & URG == URG):
			print(" URG", end='')
		if (flags & ECE == ECE):
			print(" ECE", end='')
		if (flags & CWR == CWR):
			print(" CWR", end='')
	else:
		print(" No Flags", end='')
	print()
	return packet[offset:]

def main():
	fd = socket(AF_PACKET, SOCK_RAW, htons(0x0800))
	for i in range(10):
		packet, addr = fd.recvfrom(65536)
		print("\n[+] Got a %d byte packet:" %len(packet))
		packet = parse_ethhdr(packet)
		packet = parse_iphdr(packet)
		packet = parse_tcphdr(packet)
		print("\n\t\t*** END ***")

if __name__ == "__main__":
	main()
