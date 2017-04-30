/*
 * -----------------------------------------------------------------------------
 * Notes:
 *    - And you must prevent Linux kernel to send RST:
 *         # sudo /sbin/iptables -I OUTPUT 1 -p tcp --tcp-flags RST RST -j DROP
 *    - Block outgoing traffic:
 *         # sudo /sbin/iptables -A FORWARD -p tcp -d 0.0.0.0/0 --destination-port ssh -j ACCEPT
 *         # sudo /sbin/iptables -A FORWARD -p tcp -d 0.0.0.0/0 --source-port ssh -j ACCEPT
 *         # sudo /sbin/iptables -A FORWARD -d 192.168.10.0/255.255.255.0 -j ACCEPT
 *         # sudo /sbin/iptables -P FORWARD DROP
 *    - How to run this:
 *         $ ./compile.sh; sudo ./vclient
 * -----------------------------------------------------------------------------
 */

#include "common.h"

apr_uint32_t					vserver_ip_address;
apr_uint32_t					vclient_private_ip_address;
apr_uint32_t					vclient_private_subnet_mask;
apr_uint16_t					vclient_private_udp_port_number;
BOOL							is_authenticated = FALSE;




/*
 * -----------------------------------------------------------------------------
 * WIRE LISTENER
 * -----------------------------------------------------------------------------
 */
apr_thread_t*					thread_listening;
apr_threadattr_t*				thread_listening_attr;
void* APR_THREAD_FUNC wire_listener (apr_thread_t* thread, void* thread_data)
{
	/*
	 * To capture IP packets (layer 3) traffic.
	 * Ref:
	 *    - Alternatives of packet capture in Linux: http://www.cse.wustl.edu/~jain/cse567-11/ftp/pkt_recp/
	 */
	int							sd_incoming;
	apr_byte_t					buffer[IP_MAXPACKET];

#ifndef AF_PACKET
	#define AF_PACKET			17												/* From: linux/socket.h */
#endif
#ifndef PF_PACKET
	#define PF_PACKET			AF_PACKET
#endif
#ifndef SOCK_RAW
	#define SOCK_RAW			3												/* From: bits/socket.h */
#endif
#ifndef ETH_P_ALL
	#define ETH_P_ALL			0x0003											/* From: linux/if_ether.h */
#endif

	sd_incoming = (int) socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
	if (sd_incoming == -1) {
		log_handler (LOG_LEVEL_SEVERE, "wire_listener:  socket() error %d: %s", errno, strerror (errno));
		apr_thread_exit (thread, APR_ENOSOCKET); 
		return NULL;
	}

	log_handler (LOG_LEVEL_INFO, "Listening on the wire...");
	while (TRUE) {
		struct iphdr*				iph;
		socklen_t					size;

		{
			struct sockaddr_in		from;
			socklen_t				fromlen = sizeof (from);
			size = recvfrom (sd_incoming, (char*) buffer, sizeof (buffer), 0, (struct sockaddr*) &from, &fromlen);
		}

		// There are two possible cases:
		//    1. In Hostgator, we receive IP packets (layer 3).
		//    2. In Linux box, we receive DataLink packets (layer 2).
		// So it is better to use IP packets since it works everywhere (iph and its size).
		{
			// Case Hostgator
			// iph = (struct iphdr*) buffer;

			// Case Linux
			iph = (struct iphdr*) (buffer + sizeof (struct ethhdr));
			size -= sizeof (struct ethhdr);
		}

		// Note: "continue" here means go to the next while loop

		// Ignore non IPv4 packet
		if (iph->version != 4) {
			// log_handler (LOG_LEVEL_WARNING, "Unknown IP version %d on the wire", iph->version);
			continue;
		}

		// Ignore packets we've just sent from VClient to VServer
		if (iph->saddr == vclient_private_ip_address) {
			continue;
		}

		// Ignore packets we've just sent from VClient (spoofed IP) to other hosts in the network
		if (iph->daddr == vclient_private_ip_address) {
			// Traffic from VServer to VClient is allowed
		} else {
			// Other traffic destination to other hosts in the network must be coming from us, so ignore it
			if (is_in_network (iph->daddr, vclient_private_ip_address, vclient_private_subnet_mask)) {
				continue;
			}
		}

		switch (iph->protocol) {
			case IPPROTO_TCP:
				{
					struct tcphdr* tcph = (struct tcphdr*) ((apr_byte_t*) iph + iph->ihl*4);
					// Ignore SSH packet
					if ((ntohs (tcph->dest) == 22) || (ntohs (tcph->source) == 22)) {
						continue;
					}
				}

				// Process other incoming TCP packets from the wire...
				break;

			case IPPROTO_UDP:
				{
					struct udphdr* udph = (struct udphdr*) ((apr_byte_t*) iph + iph->ihl*4);
					if (ntohs (udph->source) == VSERVER_PORT_NUMBER) {
						// Note that our VProtocol is after Layer 3 (IP) and Layer 4 (UDP) header
						VProtocolPktHdr*	pkthdr = (VProtocolPktHdr*) ((apr_byte_t*) iph + iph->ihl*4 + sizeof (struct udphdr));
						if (pkthdr->ph_magic == VPROTOCOL_MAGIC) {
							// -----------------------------
							// Incoming traffic from VClient
							// -----------------------------
							switch (pkthdr->mh_type) {
								case VPROTOCOL_MH_TYPE_NOP:
									log_handler (LOG_LEVEL_FINEST, "Received keep-alive packet from VServer");
									break;

								case VPROTOCOL_MH_TYPE_WELCOME:
									{
										VProtocolMsgHdrWelcome*	msghdr = (VProtocolMsgHdrWelcome*) ((apr_byte_t*) pkthdr + VPROTOCOL_PH_SIZE);
										log_handler (LOG_LEVEL_INFO, "VClient Public IP Address: %d.%d.%d.%d udp port %d",
											(apr_byte_t) *(((apr_byte_t*) &(msghdr->vclient_public_ip_address)) + 0),
											(apr_byte_t) *(((apr_byte_t*) &(msghdr->vclient_public_ip_address)) + 1),
											(apr_byte_t) *(((apr_byte_t*) &(msghdr->vclient_public_ip_address)) + 2),
											(apr_byte_t) *(((apr_byte_t*) &(msghdr->vclient_public_ip_address)) + 3),
											msghdr->vclient_public_udp_port_number);
										is_authenticated = TRUE;
									}
									break;

								case VPROTOCOL_MH_TYPE_S2C:
									{
										VProtocolMsgHdrS2C*	msghdr = (VProtocolMsgHdrS2C*) ((apr_byte_t*) pkthdr + VPROTOCOL_PH_SIZE);
										apr_byte_t*			msg = (apr_byte_t*) ((apr_byte_t*) pkthdr + VPROTOCOL_PH_SIZE + VPROTOCOL_MH_S2C_SIZE);

										// Decrypt payload
										xor_decrypt (msg, msghdr->len);

										// Is it in fragmented mode?
										if (msghdr->frag_id != 0) {
											static int last_frag_id = 0;
											static apr_byte_t assembled_packet[IP_MAXPACKET];

											// Assembling the packet
											memcpy (assembled_packet + (msghdr->frag_no * 1000), msg, msghdr->len);
											if (msghdr->frag_id != last_frag_id) {
												// First fragmented_packet
												last_frag_id = msghdr->frag_id;
												continue;
											}
											if (msghdr->frag_no < 1) {
												// We haven't fully assembled everything
												continue;
											}

											// Fragmented packets has been fully assembled
											log_handler (LOG_LEVEL_FINEST, "Fragmented packet %d bytes has been fully assembled!", (1 * 1000) + msghdr->len);
											// print_layer3_packet (assembled_packet, (1 * 1000) + msghdr->len);
											memcpy (msg, assembled_packet, (1 * 1000) + msghdr->len);
											msghdr->len = (1 * 1000) + msghdr->len;
										}

										// Send it over the wire...
										log_handler (LOG_LEVEL_FINEST, "Received %d bytes of S2C data from VServer. Sending it over the wire...", msghdr->len);
										// print_layer3_packet (msg, msghdr->len);
										send_ip_packet_to_world (msg, msghdr->len);
									}
									break;

								default:
									log_handler (LOG_LEVEL_WARNING, "Received unknown message type %d from VServer", pkthdr->mh_type);
									break;
							}
							continue;
						}
					}
				}

				// Process other incoming UDP packets from the wire...
				break;

			case IPPROTO_ICMP:
				// Process incoming ICMP packets from the wire...
				break;

			default:
				// Ignore non TCP, UDP or ICMP data
				// log_handler (LOG_LEVEL_FINEST, "Ignoring unknown IP protocol %d on the wire", iph->protocol);
				continue;
		}




		// ------------------------------
		// Incoming traffic from the wire
		// ------------------------------

		// Send the packet (iph) to VServer...
		log_handler (LOG_LEVEL_FINEST, "Received %d bytes of data from the wire. Sending it to VServer...", size);
		// print_layer3_packet ((void*) iph, size);
		{
			apr_byte_t			data[IP_MAXPACKET];
			VProtocolPktHdr*	pkthdr = (VProtocolPktHdr*) data;
			VProtocolMsgHdrC2S*	msghdr = (VProtocolMsgHdrC2S*) ((apr_byte_t*) pkthdr + VPROTOCOL_PH_SIZE);
			apr_byte_t*			msg = (apr_byte_t*) ((apr_byte_t*) pkthdr + VPROTOCOL_PH_SIZE + VPROTOCOL_MH_C2S_SIZE);

			if ((int) sizeof (struct iphdr) + (int) sizeof (struct udphdr) + VPROTOCOL_PH_SIZE + VPROTOCOL_MH_C2S_SIZE + size <= 1500) {
				// No, it can be send in one packet
				pkthdr->ph_magic = VPROTOCOL_MAGIC;
				pkthdr->mh_type = VPROTOCOL_MH_TYPE_C2S;
				pkthdr->ph_bytes = VPROTOCOL_PH_SIZE + VPROTOCOL_MH_C2S_SIZE + size;
				msghdr->len = size;
				msghdr->frag_id = 0;
				msghdr->frag_no = 0;
				memcpy (msg, (apr_byte_t*) iph, msghdr->len);
				xor_encrypt (msg, msghdr->len);
				send_vpacket_via_udp (vclient_private_ip_address, vclient_private_udp_port_number, vserver_ip_address, VSERVER_PORT_NUMBER, pkthdr);
			} else {
				// Yes, packet size is more than 1500 bytes. We need to split it.
				pkthdr->ph_magic = VPROTOCOL_MAGIC;
				pkthdr->mh_type = VPROTOCOL_MH_TYPE_C2S;
				pkthdr->ph_bytes = VPROTOCOL_PH_SIZE + VPROTOCOL_MH_C2S_SIZE + 1000;
				msghdr->len = 1000;
				msghdr->frag_id = (rand() % (USHRT_MAX - 1)) + 1;
				msghdr->frag_no = 0;
				memcpy (msg, (apr_byte_t*) iph, 1000);
				xor_encrypt (msg, msghdr->len);
				send_vpacket_via_udp (vclient_private_ip_address, vclient_private_udp_port_number, vserver_ip_address, VSERVER_PORT_NUMBER, pkthdr);

				pkthdr->ph_magic = VPROTOCOL_MAGIC;
				pkthdr->mh_type = VPROTOCOL_MH_TYPE_C2S;
				pkthdr->ph_bytes =  VPROTOCOL_PH_SIZE + VPROTOCOL_MH_C2S_SIZE + size - 1000;
				msghdr->len = size - 1000;
				msghdr->frag_id = msghdr->frag_id;
				msghdr->frag_no = 1;
				memcpy (msg, (apr_byte_t*) iph + 1000, size - 1000);
				xor_encrypt (msg, msghdr->len);
				send_vpacket_via_udp (vclient_private_ip_address, vclient_private_udp_port_number, vserver_ip_address, VSERVER_PORT_NUMBER, pkthdr);
			}
		}
	}

	closesocket (sd_incoming);
	apr_thread_exit (thread, APR_SUCCESS);
	return NULL;
}




int main (int argc, char **argv)
{
	// APR Initialization
	apr_initialize();
	apr_pool_create (&resources, NULL);

	// Randomness
	srand ((unsigned int) time (NULL));

	// Initialize global variables
	vserver_ip_address = inet_addr (VSERVER_IP_ADDRESS);
	vclient_private_ip_address = inet_addr ("192.168.10.129");
	vclient_private_subnet_mask = inet_addr ("255.255.255.0");
	vclient_private_udp_port_number = 10000;

	// Create a thread to capture incoming packets
	{
		apr_status_t			rv;
		apr_threadattr_create (&thread_listening_attr, resources);
		rv = apr_thread_create (&thread_listening, thread_listening_attr, wire_listener, NULL, resources);
		if (rv != APR_SUCCESS) {
			log_handler (LOG_LEVEL_SEVERE, "Unable to spawn Wire Listener thread!");
			return EXIT_FAILURE;
		}
	}

	while (! is_authenticated) {
		apr_byte_t				buffer[IP_MAXPACKET];
		VProtocolPktHdr*		pkthdr = (VProtocolPktHdr*) buffer;
		VProtocolMsgHdrHello*	msghdr = (VProtocolMsgHdrHello*) (buffer + VPROTOCOL_PH_SIZE);
		log_handler (LOG_LEVEL_INFO, "Sending Hello packet to VServer %s UDP port %d...", VSERVER_IP_ADDRESS, VSERVER_PORT_NUMBER);
		memset (buffer, 0, sizeof (buffer));
		pkthdr->ph_magic = VPROTOCOL_MAGIC;
		pkthdr->mh_type = VPROTOCOL_MH_TYPE_HELLO;
		pkthdr->ph_bytes = VPROTOCOL_PH_SIZE + VPROTOCOL_MH_HELLO_SIZE;
		msghdr->unused = 0;
		send_vpacket_via_udp (vclient_private_ip_address, vclient_private_udp_port_number, vserver_ip_address, VSERVER_PORT_NUMBER, pkthdr);
		apr_sleep (1000 * APR_USEC_PER_MSEC);
	}

	// Sleep forever
	while (TRUE) {
		apr_sleep (1000 * APR_USEC_PER_MSEC);
	}

	// APR Termination
	apr_terminate();

	return EXIT_SUCCESS;
}

