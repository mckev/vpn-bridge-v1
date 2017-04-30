/*
 * General Wisdoms:
 *    - Use apr_cpystrn() instead of strcpy() or strncpy()
 *    - Use apr_snprintf() instead of sprintf() or snprintf()
 *    - Use apr_vsnprintf() instead of vsprintf() or vsnprintf()
 *    - Use apr_uint32_t instead of unsigned int when you want to be precise about its size
 *    - Naming convention: http://www.kernel.org/doc/Documentation/CodingStyle
 *    - Memory leak detector
 *      Ref: Memory Leak Detection Enabling: http://msdn.microsoft.com/en-us/library/e5ewb1h3%28v=vs.80%29.aspx
 *      How to: Toggle Breakpoint on "_CrtDumpMemoryLeaks()", and see "Output" window in Visual Studio
 */




/*
 * -----------------------------------------------------------------------------
 * APR
 * -----------------------------------------------------------------------------
 */
#if defined _WIN32
	#define WIN32
#elif defined __linux__
	#include <sys/types.h>														/* APR: to solve: syntax error before "apr_off_t" */
	typedef __off64_t			off64_t;										/* APR: to solve: syntax error before "apr_off_t" */
	#include <ctype.h>															/* for isprint() */
	#include <stdio.h>															/* for printf() */
	#include <stdlib.h>															/* for exit() */
	#include <time.h>															/* for time() */
	#include <unistd.h>															/* for close() */
	#define closesocket close
#else
	#error Unsupported OS
#endif
#define APR_DECLARE_STATIC
#define APU_DECLARE_STATIC
#include "apr.h"
#include "apr_strings.h"
#include "apr_network_io.h"
#include "apr_thread_proc.h"
#define APR_WANT_BYTEFUNC
#include "apr_want.h"
#define APR_USEC_PER_MSEC APR_TIME_C(1000)
#include <stdio.h>

extern apr_pool_t*				resources;




/*
 * -----------------------------------------------------------------------------
 * Useful definitions and functions
 * -----------------------------------------------------------------------------
 */

/* Boolean types */
typedef int						BOOL;
#ifndef FALSE
	#define FALSE				0
#endif
#ifndef TRUE
	#define TRUE				1
#endif

/* Exit values */
#ifndef EXIT_SUCCESS
	#define EXIT_SUCCESS		0
#endif
#ifndef EXIT_FAILURE
	#define EXIT_FAILURE		1
#endif

/* Log Handler */
/* Ref: http://docs.oracle.com/javase/1.4.2/docs/api/java/util/logging/Level.html */
#define LOG_LEVEL_SEVERE		0
#define LOG_LEVEL_WARNING		1
#define LOG_LEVEL_INFO			2
#define LOG_LEVEL_CONFIG		3
#define LOG_LEVEL_FINE			4
#define LOG_LEVEL_FINER			5
#define LOG_LEVEL_FINEST		6
void log_handler (
int level,
...
);




/*
 * -----------------------------------------------------------------------------
 * TCP/IP Protocol
 * -----------------------------------------------------------------------------
 */

#define IP_MAXPACKET			0xFFFF

/* From: linux/types.h */
typedef apr_byte_t				__u8;
typedef char					__s8;
typedef apr_uint16_t			__u16;
typedef apr_int16_t				__s16;
typedef apr_uint16_t			__le16;
typedef apr_uint16_t			__be16;
typedef apr_uint32_t			__u32;
typedef apr_int32_t				__s32;
typedef apr_uint32_t			__le32;
typedef apr_uint32_t			__be32;
typedef apr_uint64_t			__le64;
typedef apr_uint64_t			__be64;

/* ETHERNET PROTOCOL */
/* From: linux/if_ether.h */
#define ETH_ALEN				6												/* Octets in one ethernet addr   */
#define ETH_P_IP				0x0800											/* Internet Protocol packet     */
struct ethhdr {
	apr_byte_t					h_dest[ETH_ALEN];								/* destination eth addr */
	apr_byte_t					h_source[ETH_ALEN];								/* source ether addr    */
	__be16						h_proto;										/* packet type ID field */
} __attribute__((packed));

/* IP PROTOCOL */
/* From: linux/ip.h */
#define __LITTLE_ENDIAN_BITFIELD												/* Kevin: Linux for Intel is using Little Endian Bitfield */
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8						ihl:4,
								version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8						version:4,
								ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	__u8						tos;
	__be16						tot_len;
	__be16						id;
	__be16						frag_off;
	__u8						ttl;
	__u8						protocol;
	__u16						check;
	__be32						saddr;
	__be32						daddr;
};
/* From: linux/in.h */
#ifndef IPPROTO_ICMP
	#define IPPROTO_ICMP		1											/* Internet Control Message Protocol    */
#endif
#ifndef IPPROTO_TCP
	#define IPPROTO_TCP			6											/* Transmission Control Protocol        */
#endif
#ifndef IPPROTO_UDP
	#define IPPROTO_UDP			17											/* User Datagram Protocol               */
#endif

/* TCP PROTOCOL */
/* From: linux/tcp.h */
struct tcphdr {
	__u16						source;
	__u16						dest;
	__u32						seq;
	__u32						ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16						res1:4,
								doff:4,
								fin:1,
								syn:1,
								rst:1,
								psh:1,
								ack:1,
								urg:1,
								ece:1,
								cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16						doff:4,
								res1:4,
								cwr:1,
								ece:1,
								urg:1,                                                                                                                                                                                       ack:1,
								psh:1,
								rst:1,
								syn:1,
								fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
	__u16						window;
	__u16						check;
	__u16						urg_ptr;
};

/* UDP PROTOCOL */
/* From: linux/udp.h */
struct udphdr {
	__u16						source;
	__u16						dest;
	__u16						len;
	__u16						check;
};

/* ICMP PROTOCOL */
/* From: linux/icmp.h */
struct icmphdr {
	__u8						type;
	__u8						code;
	__u16						checksum;
	union {
		struct {
			__u16				id;
			__u16				sequence;
		} echo;
		__u32   gateway;
		struct {
			__u16				__unused;
			__u16				mtu;
		} frag;
	} un;
};
#define ICMP_ECHOREPLY			0												/* Echo Reply                   */
#define ICMP_TIME_EXCEEDED		11												/* Time Exceeded                */

apr_uint16_t checksum_ip4 (const void* ip4_addr, int len);
apr_uint16_t checksum_tcp4 (const void* tcp4_addr, int len, apr_uint32_t src_addr, apr_uint32_t dest_addr);
apr_uint16_t checksum_udp4 (const void* udp4_addr, int len, apr_uint32_t src_addr, apr_uint32_t dest_addr);




/*
 * -----------------------------------------------------------------------------
 * TCP/IP Functions
 * -----------------------------------------------------------------------------
 */
void print_layer2_packet (const void* buffer, int size);
void print_layer3_packet (const void* buffer, int size);
BOOL is_in_network (apr_uint32_t ip_address_to_be_tested, apr_uint32_t ip_address, apr_uint32_t subnet_mask);
void send_ip_packet_to_world (const void* buffer, int size);




/*
 * -----------------------------------------------------------------------------
 * Encryption / Decryption
 * -----------------------------------------------------------------------------
 */
void xor_encrypt (apr_byte_t* buffer, int size);
void xor_decrypt (apr_byte_t* buffer, int size);




/*
 * -----------------------------------------------------------------------------
 * V Protocol
 * Packet Header + Message Header + Message
 * -----------------------------------------------------------------------------
 */
#define VSERVER_IP_ADDRESS					"100.100.100.100"
#define VSERVER_PORT_NUMBER					6113

#define VPROTOCOL_MAGIC						0x484B
typedef struct {
	apr_uint16_t							ph_magic;
	apr_uint16_t							mh_type;
	apr_uint32_t							ph_bytes;
} VProtocolPktHdr;
#define VPROTOCOL_PH_SIZE					8

#define VPROTOCOL_MH_TYPE_NOP				1
#define VPROTOCOL_MH_TYPE_HELLO				10
#define VPROTOCOL_MH_TYPE_WELCOME			11
#define VPROTOCOL_MH_TYPE_C2S				30
#define VPROTOCOL_MH_TYPE_S2C				31

typedef struct {
	apr_int32_t								unused;
} VProtocolMsgHdrHello;
#define VPROTOCOL_MH_HELLO_SIZE				4

typedef struct {
	apr_uint32_t							vclient_public_ip_address;
	apr_uint16_t							vclient_public_udp_port_number;
} VProtocolMsgHdrWelcome;
#define VPROTOCOL_MH_WELCOME_SIZE			6

typedef struct {
	apr_int32_t								len;
	apr_uint16_t							frag_id;
	apr_uint16_t							frag_no;
} VProtocolMsgHdrC2S;
#define VPROTOCOL_MH_C2S_SIZE				8

typedef struct {
	apr_int32_t								len;
	apr_uint16_t							frag_id;
	apr_uint16_t							frag_no;
} VProtocolMsgHdrS2C;
#define VPROTOCOL_MH_S2C_SIZE				8

void send_vpacket_via_udp (apr_uint32_t ip_address_source, apr_uint16_t udp_port_source, apr_uint32_t ip_address_dest, apr_uint16_t udp_port_dest, const VProtocolPktHdr* vpacket);

