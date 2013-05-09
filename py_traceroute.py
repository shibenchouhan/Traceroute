'''
Created on Jan 21, 2013

@author: Shiben
'''
#!/usr/bin/python

import socket
from configobj import ConfigObj

def write(msg):
#	global fp_log,console
	if console == 0:
		fp_log.write(msg)
		fp_log.flush()
	elif console == 1:
		fp_log.write(msg)
		fp_log.flush()
		print msg
	else:
		print msg
		
def main(dest_name,PortList,timeout):
#	dest_addr = socket.gethostbyname(dest_name)
	dest_addr = dest_name
	write("Diagnostic Details ........\n")
	for port in PortList:
		port = int(port)
		write("#"*50+ "\n")
		write("Destination Address=%s \nDestination Port=%d\n"%(dest_addr,port))
		max_hops = 30
		icmp = socket.getprotobyname('icmp')
		udp = socket.getprotobyname('udp')
		ttl = 1
		prev_addr = None
		curr_addr = None

		while True:
			recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
			send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
			send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
			recv_socket.bind(("", port))
			send_socket.sendto("", (dest_name, port))
			prev_addr = curr_addr
			curr_addr = None
			curr_name = None
			try:
				recv_socket.settimeout(timeout)
				_, curr_addr = recv_socket.recvfrom(512)
				curr_addr = curr_addr[0]
				if prev_addr == curr_addr:
					write("RESULT:Port %d from %s is Unreachable.\n" %(port,curr_addr))
					write("#"*50 + "\n")
					break
				try:
					curr_name = socket.gethostbyaddr(curr_addr)[0]
				except socket.error:
					curr_name = curr_addr
			except socket.error,e:
				recv_socket.close()
				write("RESULT:" + str(e)+ ":Port %d from %s is Unreachable.\n" %(port,curr_addr))
				write("#"*50 + "\n")
				break
			finally:
				send_socket.close()
				recv_socket.close()
			
			if curr_addr is not None:
				curr_host = "%s (%s)" % (curr_name, curr_addr)
			else:
				curr_host = "*"
			write("%d\t%s\n" % (ttl, curr_host))

			ttl += 1
			if curr_addr == dest_addr or ttl >= max_hops:
				if curr_addr == dest_addr:
					write("RESULT:Port %d from %s is reachable.\n" %(port,curr_addr))
					write("#"*50 + "\n" )
					break
				else:
					break
			
if __name__ == "__main__":
	config = ConfigObj("config.ini")
	console = int(config['default']['LogOption'])
	dest_addr = config['default']['DestinationAddress']
	PortList = config['default']['Ports']
	log_file = config['default']['LogFileName']
	timeout = int(config['default']['TimeOut'])
	fp_log = open(log_file,'w+')
	main(dest_addr,PortList,timeout)
