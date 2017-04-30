/*
 * -----------------------------------------------------------------------------
 * Notes:
 *    - To allow incoming udp on port 6113 do:
 *         # /sbin/iptables -I INPUT 1 -p udp --dport 6113 -j ACCEPT
 *      To prevent Linux kernel to send ICMP destination unreachable (because we do not really do UDP Server):
 *         # /sbin/iptables -I OUTPUT 1 -p icmp --icmp-type destination-unreachable -j DROP
 *    - And you must prevent Linux kernel to send RST:
 *         # /sbin/iptables -I OUTPUT 1 -p tcp --tcp-flags RST RST -j DROP
 *      Ref: Book "Linux Firewalls: Attack Detection and Response with Iptables, Psad, and Fwsnort" on chapter "TCP SYN or Half-Open Scans":
 *              "Using a raw socket to craft a TCP SYN packet toward a remote system instead of using the connect() system call brings up an interesting issue.
 *              If the remote host responds with a SYN/ACK, then the local TCP stack on the scanning system receives the SYN/ACK, but the outbound SYN packet
 *              did not come from the local stack (because we manually crafted it via the raw socket), so the SYN/ACK is not part of a legitimate TCP handshake
 *              as far as the stack is concerned. Hence, the scanner's local stack sends a RST back to the target system, because the SYN/ACK appears to be
 *              unsolicited. You can stop this behavior on the scanning system by adding the following iptables rule to the OUTPUT chain before starting a scan
 *              with the command: [ext_scanner]# iptables -I OUTPUT 1 -d target -p tcp --tcp-flags RST RST -j DROP
 *    - How to run this:
 *         $ su
 *         # ./compile.sh; ./vserver
 *    - Failsafe: # crontab -e
 *                0 4 * * * /sbin/shutdown -r +5
 *    - To cancel shutdown: # /sbin/shutdown -c
 * -----------------------------------------------------------------------------
 */

#include "common.h"

apr_uint32_t					vserver_ip_address;
apr_uint32_t					vclient_public_ip_address;
apr_uint16_t					vclient_public_udp_port_number;




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
			iph = (struct iphdr*) buffer;

			// Case Linux
			// iph = (struct iphdr*) (buffer + sizeof (struct ethhdr));
			// size -= sizeof (struct ethhdr);
		}

		// Note: "continue" here means go to the next while loop

		// Ignore non IPv4 packet
		if (iph->version != 4) {
			// log_handler (LOG_LEVEL_WARNING, "Unknown IP version %d on the wire", iph->version);
			continue;
		}

		// Ignore outgoing traffic
		if (iph->saddr == vserver_ip_address) {
			continue;
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
					if (ntohs (udph->dest) == VSERVER_PORT_NUMBER) {
						// Note that our VProtocol is after Layer 3 (IP) and Layer 4 (UDP) header
						VProtocolPktHdr*	pkthdr = (VProtocolPktHdr*) ((apr_byte_t*) iph + iph->ihl*4 + sizeof (struct udphdr));
						if (pkthdr->ph_magic == VPROTOCOL_MAGIC) {
							// -----------------------------
							// Incoming traffic from VClient
							// -----------------------------
							switch (pkthdr->mh_type) {
								case VPROTOCOL_MH_TYPE_NOP:
									log_handler (LOG_LEVEL_FINEST, "Received keep-alive packet from VClient");
									break;

								case VPROTOCOL_MH_TYPE_HELLO:
									log_handler (LOG_LEVEL_INFO, "VClient Public IP Address: %d.%d.%d.%d udp port %d",
										(apr_byte_t) *(((apr_byte_t*) &(iph->saddr)) + 0),
										(apr_byte_t) *(((apr_byte_t*) &(iph->saddr)) + 1),
										(apr_byte_t) *(((apr_byte_t*) &(iph->saddr)) + 2),
										(apr_byte_t) *(((apr_byte_t*) &(iph->saddr)) + 3),
										ntohs (udph->source));

									// Register client
									{
										// VProtocolMsgHdrHello* msghdr = (VProtocolMsgHdrHello*) ((apr_byte_t*) pkthdr + VPROTOCOL_PH_SIZE);
										vclient_public_ip_address = iph->saddr;
										vclient_public_udp_port_number = ntohs (udph->source);
									}

									// Send reply back
									{
										apr_byte_t			data[IP_MAXPACKET];
										VProtocolPktHdr*	pkthdr = (VProtocolPktHdr*) data;
										VProtocolMsgHdrWelcome*		msghdr = (VProtocolMsgHdrWelcome*) ((apr_byte_t*) pkthdr + VPROTOCOL_PH_SIZE);
										log_handler (LOG_LEVEL_FINEST, "Sending Welcome data to VClient...");
										pkthdr->ph_magic = VPROTOCOL_MAGIC;
										pkthdr->mh_type = VPROTOCOL_MH_TYPE_WELCOME;
										pkthdr->ph_bytes = VPROTOCOL_PH_SIZE + VPROTOCOL_MH_WELCOME_SIZE;
										msghdr->vclient_public_ip_address = vclient_public_ip_address;
										msghdr->vclient_public_udp_port_number = vclient_public_udp_port_number;
										send_vpacket_via_udp (vserver_ip_address, VSERVER_PORT_NUMBER, vclient_public_ip_address, vclient_public_udp_port_number, pkthdr);
									}
									break;

								case VPROTOCOL_MH_TYPE_C2S:
									{
										VProtocolMsgHdrC2S*	msghdr = (VProtocolMsgHdrC2S*) ((apr_byte_t*) pkthdr + VPROTOCOL_PH_SIZE);
										apr_byte_t*			msg = (apr_byte_t*) ((apr_byte_t*) pkthdr + VPROTOCOL_PH_SIZE + VPROTOCOL_MH_C2S_SIZE);

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

										// Replace IP header
										{
											struct iphdr* iph_payload = (struct iphdr*) msg;
											if (iph_payload->saddr == inet_addr ("192.168.10.141")) {
												iph_payload->saddr = vserver_ip_address;
											} else {
												log_handler (LOG_LEVEL_FINEST, "Ignoring outgoing %d bytes not coming from 192.168.10.141 (broadcast?)", msghdr->len);
												continue;
											}

											// Recalculate checksum
											iph_payload->check = 0;
											iph_payload->check = checksum_ip4 (iph_payload, iph_payload->ihl*4);
											switch (iph_payload->protocol) {
												case IPPROTO_TCP:
													{
														struct tcphdr* tcph_payload = (struct tcphdr*) ((apr_byte_t*) iph_payload + iph_payload->ihl*4);
														tcph_payload->check = 0;
														tcph_payload->check = checksum_tcp4 (tcph_payload, ntohs (iph_payload->tot_len) - iph_payload->ihl*4, iph_payload->saddr, iph_payload->daddr);
													}
													break;
												case IPPROTO_UDP:
													{
														struct udphdr* udph_payload = (struct udphdr*) ((apr_byte_t*) iph_payload + iph_payload->ihl*4);
														udph_payload->check = 0;
														udph_payload->check = checksum_udp4 (udph_payload, ntohs (iph_payload->tot_len) - iph_payload->ihl*4, iph_payload->saddr, iph_payload->daddr);
													}
													break;
												case IPPROTO_ICMP:
													{
														struct icmphdr* icmph_payload = (struct icmphdr*) ((apr_byte_t*) iph_payload + iph_payload->ihl*4);
														icmph_payload->checksum = 0;
														icmph_payload->checksum = checksum_ip4 (icmph_payload, ntohs (iph_payload->tot_len) - iph_payload->ihl*4);
													}
													break;
											}
										}

										// Send it over the wire...
										log_handler (LOG_LEVEL_FINEST, "Received %d bytes of C2S data from VClient. Sending it to the world...", msghdr->len);
										// print_layer3_packet (msg, msghdr->len);
										send_ip_packet_to_world (msg, msghdr->len);
									}
									break;

								default:
									log_handler (LOG_LEVEL_WARNING, "Received unknown message type %d from VClient", pkthdr->mh_type);
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
				log_handler (LOG_LEVEL_FINEST, "Ignoring unknown IP protocol %d on the wire", iph->protocol);
				continue;
		}




		// ------------------------------
		// Incoming traffic from the wire
		// ------------------------------

		// Determine which client owns this packet...

		// Replace IP header so VClient could have just send it without any processing...
		{
			if (iph->daddr == vserver_ip_address) {
				iph->daddr = inet_addr ("192.168.10.141");
			} else {
				log_handler (LOG_LEVEL_FINEST, "Ignoring incoming %d bytes not destined to VSERVER ip address (broadcast?)", size);
				continue;
			}

			// Recalculate checksum
			iph->check = 0;
			iph->check = checksum_ip4 (iph, iph->ihl*4);
			switch (iph->protocol) {
				case IPPROTO_TCP:
					{
						struct tcphdr* tcph_payload = (struct tcphdr*) ((apr_byte_t*) iph + iph->ihl*4);
						tcph_payload->check = 0;
						tcph_payload->check = checksum_tcp4 (tcph_payload, ntohs (iph->tot_len) - iph->ihl*4, iph->saddr, iph->daddr);
					}
					break;
				case IPPROTO_UDP:
					{
						struct udphdr* udph_payload = (struct udphdr*) ((apr_byte_t*) iph + iph->ihl*4);
						udph_payload->check = 0;
						udph_payload->check = checksum_udp4 (udph_payload, ntohs (iph->tot_len) - iph->ihl*4, iph->saddr, iph->daddr);
					}
					break;
				case IPPROTO_ICMP:
					{
						struct icmphdr* icmph_payload = (struct icmphdr*) ((apr_byte_t*) iph + iph->ihl*4);
						icmph_payload->checksum = 0;
						icmph_payload->checksum = checksum_ip4 (icmph_payload, ntohs (iph->tot_len) - iph->ihl*4);
					}
					break;
			}
		}

		// Send the packet (iph) to VClient...
		log_handler (LOG_LEVEL_FINEST, "Received %d bytes of data from the world. Sending it to VClient...", size);
		// print_layer3_packet ((void*) iph, size);
		{
			apr_byte_t			data[IP_MAXPACKET];
			VProtocolPktHdr*	pkthdr = (VProtocolPktHdr*) data;
			VProtocolMsgHdrS2C*	msghdr = (VProtocolMsgHdrS2C*) ((apr_byte_t*) pkthdr + VPROTOCOL_PH_SIZE);
			apr_byte_t*			msg = (apr_byte_t*) ((apr_byte_t*) pkthdr + VPROTOCOL_PH_SIZE + VPROTOCOL_MH_S2C_SIZE);

			if ((int) sizeof (struct iphdr) + (int) sizeof (struct udphdr) + VPROTOCOL_PH_SIZE + VPROTOCOL_MH_S2C_SIZE + size <= 1500) {
				// No, it can be send in one packet
				pkthdr->ph_magic = VPROTOCOL_MAGIC;
				pkthdr->mh_type = VPROTOCOL_MH_TYPE_S2C;
				pkthdr->ph_bytes = VPROTOCOL_PH_SIZE + VPROTOCOL_MH_S2C_SIZE + size;
				msghdr->len = size;
				msghdr->frag_id = 0;
				msghdr->frag_no = 0;
				memcpy (msg, (apr_byte_t*) iph, msghdr->len);
				xor_encrypt (msg, msghdr->len);
				send_vpacket_via_udp (vserver_ip_address, VSERVER_PORT_NUMBER, vclient_public_ip_address, vclient_public_udp_port_number, pkthdr);
			} else {
				// Yes, packet size is more than 1500 bytes. We need to split it.
				pkthdr->ph_magic = VPROTOCOL_MAGIC;
				pkthdr->mh_type = VPROTOCOL_MH_TYPE_S2C;
				pkthdr->ph_bytes = VPROTOCOL_PH_SIZE + VPROTOCOL_MH_S2C_SIZE + 1000;
				msghdr->len = 1000;
				msghdr->frag_id = (rand() % (USHRT_MAX - 1)) + 1;
				msghdr->frag_no = 0;
				memcpy (msg, (apr_byte_t*) iph, 1000);
				xor_encrypt (msg, msghdr->len);
				send_vpacket_via_udp (vserver_ip_address, VSERVER_PORT_NUMBER, vclient_public_ip_address, vclient_public_udp_port_number, pkthdr);

				pkthdr->ph_magic = VPROTOCOL_MAGIC;
				pkthdr->mh_type = VPROTOCOL_MH_TYPE_S2C;
				pkthdr->ph_bytes =  VPROTOCOL_PH_SIZE + VPROTOCOL_MH_S2C_SIZE + size - 1000;
				msghdr->len = size - 1000;
				msghdr->frag_id = msghdr->frag_id;
				msghdr->frag_no = 1;
				memcpy (msg, (apr_byte_t*) iph + 1000, size - 1000);
				xor_encrypt (msg, msghdr->len);
				send_vpacket_via_udp (vserver_ip_address, VSERVER_PORT_NUMBER, vclient_public_ip_address, vclient_public_udp_port_number, pkthdr);
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

	// Sleep forever
	while (TRUE) {
		apr_sleep (1000 * APR_USEC_PER_MSEC);
	}

	// APR Termination
	apr_terminate();

	return EXIT_SUCCESS;
}

