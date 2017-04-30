#include "common.h"




/*
 * -----------------------------------------------------------------------------
 * APR
 * -----------------------------------------------------------------------------
 */
apr_pool_t*						resources;




/*
 * -----------------------------------------------------------------------------
 * Useful definitions and functions
 * -----------------------------------------------------------------------------
 */

/* Log Handler */
void log_handler (
int level,
...
)
{
	va_list		args;
	char*		fmt;
	char		buffer[4096];

	va_start (args, level);
	fmt = va_arg (args, char*);
	apr_vsnprintf (buffer, sizeof (buffer), fmt, args);
	va_end (args);

	switch (level) {
		case LOG_LEVEL_SEVERE:
			printf ("Error:  %s\n", buffer);
			exit (EXIT_FAILURE);
			break;

		case LOG_LEVEL_WARNING:
			printf ("Warning:  %s\n", buffer);
			break;

		case LOG_LEVEL_INFO:
			printf ("Info:  %s\n", buffer);
			break;

		case LOG_LEVEL_FINER:
			printf ("Debug:  %s\n", buffer);
			break;

		case LOG_LEVEL_FINEST:
			printf ("Extd Debug:  %s\n", buffer);
			break;

		default:
			break;
	}
}




/*
 * -----------------------------------------------------------------------------
 * TCP/IP Protocol
 * -----------------------------------------------------------------------------
 */
apr_uint16_t checksum_ip4 (const void* ip4_addr, int len)
{
	// Ref: http://www.pdbuchan.com/rawsock/tcp4.c
	// Note: Please set iph->check to 0 before calling this function
	const apr_uint16_t* w = (apr_uint16_t*) ip4_addr;
	int nleft = len;
	apr_uint32_t sum = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= sizeof (apr_uint16_t);
	}

	if (nleft == 1) {
		apr_uint16_t temp;
		*(apr_byte_t*) (&temp) = *(apr_byte_t*) w;
		sum += temp;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);

	// Return the one's complement of sum
	return ((apr_uint16_t) (~sum));
}

apr_uint16_t checksum_tcp4 (const void* tcp4_addr, int len, apr_uint32_t src_addr, apr_uint32_t dest_addr)
{
	// Ref: http://minirighi.sourceforge.net/html/tcp_8c-source.html
	const apr_uint16_t* w = (apr_uint16_t*) tcp4_addr;
	apr_uint16_t* ip_src = (apr_uint16_t*) &src_addr;
	apr_uint16_t* ip_dst = (apr_uint16_t*) &dest_addr;
	apr_uint32_t sum = 0;
	int nleft = len;

	// Calculate the sum
	while (nleft > 1) {
		sum += *w++;
		if (sum & 0x80000000) {
			sum = (sum & 0xFFFF) + (sum >> 16);
		}
		nleft -= 2;
	}
	if (nleft & 1) {
		// Add the padding if the packet length is odd
		sum += *((apr_byte_t*) w);
	}

	// Add the pseudo-header
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons (IPPROTO_TCP);
	sum += htons (len);

	// Add the carries
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	// Return the one's complement of sum
	return ((apr_uint16_t) (~sum));
}

apr_uint16_t checksum_udp4 (const void* udp4_addr, int len, apr_uint32_t src_addr, apr_uint32_t dest_addr)
{
	// Ref: http://minirighi.sourceforge.net/html/udp_8c-source.html
	const apr_uint16_t* w = (apr_uint16_t*) udp4_addr;
	apr_uint16_t* ip_src = (apr_uint16_t*) &src_addr;
	apr_uint16_t* ip_dst = (apr_uint16_t*) &dest_addr;
	apr_uint32_t sum = 0;
	int nleft = len;

	// Calculate the sum
	while (nleft > 1) {
		sum += *w++;
		if (sum & 0x80000000) {
			sum = (sum & 0xFFFF) + (sum >> 16);
		}
		nleft -= 2;
	}
	if (nleft & 1) {
		// Add the padding if the packet length is odd
		sum += *((apr_byte_t*) w);
	}

	// Add the pseudo-header
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons (IPPROTO_UDP);
	sum += htons (len);

	// Add the carries
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	// Return the one's complement of sum
	return ((apr_uint16_t) (~sum));
}




/*
 * -----------------------------------------------------------------------------
 * TCP/IP Functions
 * -----------------------------------------------------------------------------
 */

void print_ethernet_header (const void* buffer, int size)
{
	struct ethhdr* eth = (struct ethhdr*) buffer;

	log_handler (LOG_LEVEL_FINEST, "Ethernet Header");
	log_handler (LOG_LEVEL_FINEST, "   |-Destination Address  : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	log_handler (LOG_LEVEL_FINEST, "   |-Source Address       : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	log_handler (LOG_LEVEL_FINEST, "   |-Protocol             : %u", (apr_uint16_t) eth->h_proto);
}

void print_ip_header (const void* buffer, int size)
{
	/* Note: "buffer" should not include Ethernet header */
	struct iphdr* iph = (struct iphdr*) buffer;

	log_handler (LOG_LEVEL_FINEST, "IP Header");
	log_handler (LOG_LEVEL_FINEST, "   |-IP Version           : %d", (apr_uint32_t) iph->version);
	log_handler (LOG_LEVEL_FINEST, "   |-IP Header Length     : %d dwords or %d bytes", (apr_uint32_t) iph->ihl, (apr_uint32_t) iph->ihl*4);
	if (iph->ihl != 5) {
		log_handler (LOG_LEVEL_FINEST, "                            (IHL > 5: IP Options exists)");
	}
	log_handler (LOG_LEVEL_FINEST, "   |-Type Of Service      : %d", (apr_uint32_t) iph->tos);
	log_handler (LOG_LEVEL_FINEST, "   |-IP Total Length      : %d bytes (Size of Packet)", ntohs (iph->tot_len));
	log_handler (LOG_LEVEL_FINEST, "   |-Identification       : %d", ntohs (iph->id));
	log_handler (LOG_LEVEL_FINEST, "   |-TTL                  : %d", (apr_uint32_t) iph->ttl);
	log_handler (LOG_LEVEL_FINEST, "   |-Protocol             : %d", (apr_uint32_t) iph->protocol);
	log_handler (LOG_LEVEL_FINEST, "   |-Checksum             : %d", ntohs (iph->check));
	log_handler (LOG_LEVEL_FINEST, "   |-Source IP            : %d.%d.%d.%d",
		(apr_byte_t) *(((apr_byte_t*) &(iph->saddr)) + 0),
		(apr_byte_t) *(((apr_byte_t*) &(iph->saddr)) + 1),
		(apr_byte_t) *(((apr_byte_t*) &(iph->saddr)) + 2),
		(apr_byte_t) *(((apr_byte_t*) &(iph->saddr)) + 3));
	log_handler (LOG_LEVEL_FINEST, "   |-Destination IP       : %d.%d.%d.%d",
		(apr_byte_t) *(((apr_byte_t*) &(iph->daddr)) + 0),
		(apr_byte_t) *(((apr_byte_t*) &(iph->daddr)) + 1),
		(apr_byte_t) *(((apr_byte_t*) &(iph->daddr)) + 2),
		(apr_byte_t) *(((apr_byte_t*) &(iph->daddr)) + 3));

#if 0
	// Verify that our IP Checksum algorithm is correct
	{
		apr_uint16_t original_iph_check = iph->check;
		log_handler (LOG_LEVEL_FINEST, "Recalculate IP checksum");
		iph->check = 0;
		iph->check = checksum_ip4 (iph, iph->ihl*4);
		if ((iph->check == original_iph_check) || (original_iph_check == 0)) {
		} else {
			log_handler (LOG_LEVEL_WARNING, "Invalid IP checksum calculation %d != %d", original_iph_check, iph->check);
			exit (EXIT_FAILURE);
		}
		iph->check = original_iph_check;
	}
#endif
}

void print_tcp_header (const void* buffer, int size)
{
	struct iphdr* iph = (struct iphdr*) buffer;
	struct tcphdr* tcph = (struct tcphdr*) ((apr_byte_t*) buffer + iph->ihl*4);

	log_handler (LOG_LEVEL_FINEST, "TCP Header");
	log_handler (LOG_LEVEL_FINEST, "   |-Source Port          : %u", ntohs (tcph->source));
	log_handler (LOG_LEVEL_FINEST, "   |-Destination Port     : %u", ntohs (tcph->dest));
	log_handler (LOG_LEVEL_FINEST, "   |-Sequence Number      : %u", ntohl (tcph->seq));
	log_handler (LOG_LEVEL_FINEST, "   |-Acknowledge Number   : %u", ntohl (tcph->ack_seq));
	log_handler (LOG_LEVEL_FINEST, "   |-Header Length        : %d dwords or %d bytes", (unsigned int) tcph->doff, (unsigned int) tcph->doff*4);
	if (tcph->doff != 5) {
		log_handler (LOG_LEVEL_FINEST, "                            (Data offset > 5: TCP Options exists)");
	}
	log_handler (LOG_LEVEL_FINEST, "   |-Reserved             : %d", (unsigned int) tcph->res1);
	log_handler (LOG_LEVEL_FINEST, "   |-CWR Flag             : %d", (unsigned int) tcph->cwr);
	log_handler (LOG_LEVEL_FINEST, "   |-ECN Flag             : %d", (unsigned int) tcph->ece);
	log_handler (LOG_LEVEL_FINEST, "   |-Urgent Flag          : %d", (unsigned int) tcph->urg);
	log_handler (LOG_LEVEL_FINEST, "   |-Acknowledgement Flag : %d", (unsigned int) tcph->ack);
	log_handler (LOG_LEVEL_FINEST, "   |-Push Flag            : %d", (unsigned int) tcph->psh);
	log_handler (LOG_LEVEL_FINEST, "   |-Reset Flag           : %d", (unsigned int) tcph->rst);
	log_handler (LOG_LEVEL_FINEST, "   |-Synchronise Flag     : %d", (unsigned int) tcph->syn);
	log_handler (LOG_LEVEL_FINEST, "   |-Finish Flag          : %d", (unsigned int) tcph->fin);
	log_handler (LOG_LEVEL_FINEST, "   |-Window               : %d", ntohs (tcph->window));
	log_handler (LOG_LEVEL_FINEST, "   |-Checksum             : %d", ntohs (tcph->check));
	log_handler (LOG_LEVEL_FINEST, "   |-Urgent Pointer       : %d", tcph->urg_ptr);

#if 0
	// Verify that our TCP Checksum algorithm is correct
	{
		apr_uint16_t original_tcph_check = tcph->check;
		log_handler (LOG_LEVEL_FINEST, "Recalculate TCP checksum");
		tcph->check = 0;
		tcph->check = checksum_tcp4 (tcph, ntohs (iph->tot_len) - iph->ihl*4, iph->saddr, iph->daddr);
		if (tcph->check == original_tcph_check) {
		} else {
			log_handler (LOG_LEVEL_WARNING, "Invalid TCP checksum calculation %d != %d", original_tcph_check, tcph->check);
			exit (EXIT_FAILURE);
		}
		tcph->check = original_tcph_check;
	}
#endif
}

void print_udp_header (const void* buffer, int size)
{
	struct iphdr* iph = (struct iphdr*) buffer;
	struct udphdr* udph = (struct udphdr*) ((apr_byte_t*) buffer + iph->ihl*4);

	log_handler (LOG_LEVEL_FINEST, "UDP Header");
	log_handler (LOG_LEVEL_FINEST, "   |-Source Port          : %d", ntohs (udph->source));
	log_handler (LOG_LEVEL_FINEST, "   |-Destination Port     : %d", ntohs (udph->dest));
	log_handler (LOG_LEVEL_FINEST, "   |-UDP Length           : %d", ntohs (udph->len));
	log_handler (LOG_LEVEL_FINEST, "   |-UDP Checksum         : %d", ntohs (udph->check));

#if 0
	// Verify that our UDP Checksum algorithm is correct
	{
		apr_uint16_t original_udph_check = udph->check;
		log_handler (LOG_LEVEL_FINEST, "Recalculate UDP checksum");
		udph->check = 0;
		udph->check = checksum_udp4 (udph, ntohs (iph->tot_len) - iph->ihl*4, iph->saddr, iph->daddr);
		if (udph->check == original_udph_check) {
		} else {
			log_handler (LOG_LEVEL_WARNING, "Invalid UDP checksum calculation %d != %d", original_udph_check, udph->check);
			// exit (EXIT_FAILURE);
		}
		udph->check = original_udph_check;
	}
#endif
}

void print_icmp_header (const void* buffer, int size)
{
	struct iphdr* iph = (struct iphdr*) buffer;
	struct icmphdr* icmph = (struct icmphdr*) ((apr_byte_t*) buffer + iph->ihl*4);

	log_handler (LOG_LEVEL_FINEST, "ICMP Header");
	log_handler (LOG_LEVEL_FINEST, "   |-Type                 : %d", (unsigned int) (icmph->type));
	if (icmph->type == ICMP_TIME_EXCEEDED) {
		log_handler (LOG_LEVEL_FINEST, "                            (TTL Expired)");
	} else if (icmph->type == ICMP_ECHOREPLY) {
		log_handler (LOG_LEVEL_FINEST, "                            (ICMP Echo Reply)");
	}
	log_handler (LOG_LEVEL_FINEST, "   |-Code                 : %d", (unsigned int) (icmph->code));
	log_handler (LOG_LEVEL_FINEST, "   |-Checksum             : %d", ntohs (icmph->checksum));

#if 0
	// Verify that our ICMP Checksum algorithm is correct
	{
		apr_uint16_t original_icmph_checksum = icmph->checksum;
		log_handler (LOG_LEVEL_FINEST, "Recalculate ICMP checksum");
		icmph->checksum = 0;
		icmph->checksum = checksum_ip4 (icmph, ntohs (iph->tot_len) - iph->ihl*4);
		if (icmph->checksum == original_icmph_checksum) {
		} else {
			log_handler (LOG_LEVEL_WARNING, "Invalid ICMP checksum calculation %d != %d", original_icmph_checksum, icmph->checksum);
			// exit (EXIT_FAILURE);
		}
		icmph->checksum = original_icmph_checksum;
	}
#endif
}

void print_layer2_packet (const void* buffer, int size)
{
	struct ethhdr* eth = (struct ethhdr*) buffer;

	print_ethernet_header (buffer, size);

	switch (ntohs (eth->h_proto)) {
		case ETH_P_IP:
			{
				struct iphdr* iph = (struct iphdr*) ((apr_byte_t*) buffer + sizeof (struct ethhdr));

				print_ip_header ((apr_byte_t*) buffer + sizeof (struct ethhdr), size - sizeof (struct ethhdr));

				switch (iph->protocol) {
					case IPPROTO_TCP:
						print_tcp_header ((apr_byte_t*) buffer + sizeof (struct ethhdr), size - sizeof (struct ethhdr));
						break;

					case IPPROTO_UDP:
						print_udp_header ((apr_byte_t*) buffer + sizeof (struct ethhdr), size - sizeof (struct ethhdr));
						break;

					case IPPROTO_ICMP:
						print_icmp_header ((apr_byte_t*) buffer + sizeof (struct ethhdr), size - sizeof (struct ethhdr));
						break;

					default:
						break;
				}
			}
			break;

		default:
			// Some other Ethernet-like Protocols like ARP, Frame Relay, MPLS, etc.
			break;
	}

	// Display raw data
	{
		char* buffer_str = (char*) buffer;
		int i;
		for (i = 0; i < size; i++) {
			if (isprint (buffer_str[i])) {
				printf ("%c", buffer_str[i]);
			} else {
				printf (".");
			}
		}
		printf ("\n");
	}

	log_handler (LOG_LEVEL_FINEST, "=====================================================");
}

void print_layer3_packet (const void* buffer, int size)
{
	struct iphdr* iph = (struct iphdr*) buffer;

	print_ip_header (buffer, size);

	switch (iph->protocol) {
		case IPPROTO_TCP:
			print_tcp_header (buffer, size);
			break;

		case IPPROTO_UDP:
			print_udp_header (buffer, size);
			break;

		case IPPROTO_ICMP:
			print_icmp_header (buffer, size);
			break;

		default:
			break;
	}

	// Display raw data
	{
		char* buffer_str = (char*) buffer;
		int i;
		for (i = 0; i < size; i++) {
			if (isprint (buffer_str[i])) {
				printf ("%c", buffer_str[i]);
			} else {
				printf (".");
			}
		}
		printf ("\n");
	}

	log_handler (LOG_LEVEL_FINEST, "=====================================================");
}

BOOL is_in_network (apr_uint32_t ip_address_to_be_tested, apr_uint32_t ip_address, apr_uint32_t subnet_mask)
{
	apr_uint32_t network = ip_address & subnet_mask;
	// apr_uint32_t broadcast = ip_address | (~ subnet_mask);
	if ((ip_address_to_be_tested & subnet_mask) == network) {
		return TRUE;
	} else {
		return FALSE;
	}
}

void send_ip_packet_to_world (const void* buffer, int size)
{
	// This function sends IP packet to the world
	static int					sd = INT_MIN;
	struct iphdr*				iph = (struct iphdr*) buffer;
	struct sockaddr_in			sin;

	if (sd == INT_MIN) {
		// Initialize raw ip socket
#ifndef AF_INET
	#define AF_INET				2												/* From: linux/socket.h */
#endif
#ifndef PF_INET
	#define PF_INET				AF_INET
#endif
#ifndef SOCK_RAW
	#define SOCK_RAW			3												/* From: bits/socket.h */
#endif
#ifndef IPPROTO_RAW
	#define IPPROTO_RAW			255												/* From: linux/in.h */
#endif

		int temp_sd = (int) socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
		if (temp_sd == -1) {
			log_handler (LOG_LEVEL_WARNING, "send_ip_packet_to_world:  socket() error %d: %s", errno, strerror (errno));
			return;
		}

		/* Inform the kernel do not fill up the packet structure. We will build our own... */
		{
			int on = 1;
#if defined _WIN32
			if (setsockopt (temp_sd, IPPROTO_IP, IP_HDRINCL, (const char*) &on, sizeof (on)) == -1) {
#elif defined __linux__
			if (setsockopt (temp_sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) == -1) {
#else
	#error Unsupported OS
#endif
				log_handler (LOG_LEVEL_WARNING, "send_ip_packet_to_world:  setsockopt() error %d: %s", errno, strerror (errno));
				return;
			}
		}

		sd = temp_sd;
	}

	switch (iph->protocol) {
		case IPPROTO_TCP:
			{
				struct tcphdr* tcph = (struct tcphdr*) ((apr_byte_t*) buffer + iph->ihl*4);
				sin.sin_port = tcph->dest;
			}
			break;

		case IPPROTO_UDP:
			{
				struct udphdr* udph = (struct udphdr*) ((apr_byte_t*) buffer + iph->ihl*4);
				sin.sin_port = udph->dest;
			}
			break;

		case IPPROTO_ICMP:
			{
				sin.sin_port = 0;
			}
			break;

		default:
			log_handler (LOG_LEVEL_WARNING, "send_ip_packet_to_world:  Refusing to inject %d bytes of unknown protocol %d to the world", size, iph->protocol);
			return;
	}

	// Send IP packet to the world
	sin.sin_family = AF_INET;
	memcpy (&(sin.sin_addr.s_addr), &(iph->daddr), 4);

#if defined _WIN32
	if (sendto (sd, (const char*) buffer, ntohs (iph->tot_len), 0, (struct sockaddr*) &sin, sizeof (sin)) == -1) {
#elif defined __linux__
	if (sendto (sd, (const void*) buffer, ntohs (iph->tot_len), 0, (struct sockaddr*) &sin, sizeof (sin)) == -1) {
#else
	#error Unsupported OS
#endif
		log_handler (LOG_LEVEL_WARNING, "send_ip_packet_to_world:  sendto() error %d: %s", errno, strerror (errno));
	}
}




/*
 * -----------------------------------------------------------------------------
 * Encryption / Decryption
 * -----------------------------------------------------------------------------
 */
void xor_encrypt (apr_byte_t* buffer, int size)
{
	apr_byte_t *cp, *ep;
	for (cp = buffer, ep = buffer + size; cp < ep; cp++) {
		*cp ^= 'K';
	}
}

void xor_decrypt (apr_byte_t* buffer, int size)
{
	apr_byte_t *cp, *ep;
	for (cp = buffer, ep = buffer + size; cp < ep; cp++) {
		*cp ^= 'K';
	}
}




/*
 * -----------------------------------------------------------------------------
 * V Protocol
 * -----------------------------------------------------------------------------
 */
void send_vpacket_via_udp (apr_uint32_t ip_address_source, apr_uint16_t udp_port_source, apr_uint32_t ip_address_dest, apr_uint16_t udp_port_dest, const VProtocolPktHdr* vpacket)
{
	apr_byte_t					data[IP_MAXPACKET];
	struct iphdr*				iph_payload = (struct iphdr*) data;
	struct udphdr*				udph_payload = (struct udphdr*) (data + sizeof (struct iphdr));
	VProtocolPktHdr*			pkthdr = (VProtocolPktHdr*) (data + sizeof (struct iphdr) + sizeof (struct udphdr));

	// We must send it on top of UDP packet
	memset (data, 0, sizeof (struct iphdr) + sizeof (struct udphdr));
	iph_payload->version = 4;
	iph_payload->ihl = sizeof (struct iphdr) / 4;								/* 5 */
	iph_payload->tos = 0;
	iph_payload->tot_len = htons (iph_payload->ihl*4 + (int) sizeof (struct udphdr) + vpacket->ph_bytes);
	iph_payload->id = htons (0);												/* htons (rand()); */
	iph_payload->ttl = 128;
	iph_payload->protocol = IPPROTO_UDP;
	iph_payload->saddr = ip_address_source;
	iph_payload->daddr = ip_address_dest;
	iph_payload->check = 0;
	iph_payload->check = checksum_ip4 (iph_payload, iph_payload->ihl*4);
	udph_payload->source = htons (udp_port_source);
	udph_payload->dest = htons (udp_port_dest);
	udph_payload->len = htons (ntohs (iph_payload->tot_len) - iph_payload->ihl*4);

	// Copy the VPacket
	memcpy (pkthdr, vpacket, vpacket->ph_bytes);

	// Send it!
	udph_payload->check = 0;
	udph_payload->check = checksum_udp4 (udph_payload, ntohs (udph_payload->len), iph_payload->saddr, iph_payload->daddr);
	send_ip_packet_to_world (data, ntohs (iph_payload->tot_len));
}

