'''
Created on Jan 21, 2013

@author: Shiben
'''
#!/usr/bin/python

import socket
from configobj import ConfigObj
import logging

log = logging.getLogger(__name__)

		
def main(dest_name, port_ist, timeout):
#	dest_addr = socket.gethostbyname(dest_name)
	dest_addr = dest_name
	log.info("Diagnostic Details ........\n")
	for port in port_list:
		port = int(port)
		log.info("#" * 50 + "\n")
		log.info("Destination Address=%s \nDestination Port=%d\n", dest_addr, port)
		max_hops = 30
		icmp = socket.getprotobyname("icmp")
		udp = socket.getprotobyname("udp")
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
					log.info("RESULT:Port %d from %s is Unreachable.\n", port, curr_addr)
					write("#"*50 + "\n")
					break
				try:
					curr_name = socket.gethostbyaddr(curr_addr)[0]
				except socket.error:
					curr_name = curr_addr
			except socket.error,e:
				recv_socket.close()
				log.info("RESULT:" + str(e)+ ":Port %d from %s is Unreachable.\n", port, curr_addr)
				log.info("#" * 50 + "\n")
				break
			finally:
				send_socket.close()
				recv_socket.close()
			
			if curr_addr is not None:
				curr_host = "%s (%s)" % (curr_name, curr_addr)
			else:
				curr_host = "*"
			log.info("%d\t%s\n",  ttl, curr_host)

			ttl += 1
			if curr_addr == dest_addr or ttl >= max_hops:
				if curr_addr == dest_addr:
					log.info("RESULT:Port %d from %s is reachable.\n", port, curr_addr)
					log.info("#" * 50 + "\n")
					break
				else:
					break
			
if __name__ == "__main__":
	config = ConfigObj("config.ini")
	console = int(config['default']['LogOption'])
	dest_addr = config['default']['DestinationAddress']
	port_list = config['default']['Ports']
	log_file = config['default']['LogFileName']
	timeout = int(config['default']['TimeOut'])
	fp_log = open(log_file,'w+')
	main(dest_addr, port_list, timeout)
