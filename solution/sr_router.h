/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/*self-defined helper functions in sr_router.c*/
int validIPPacket(struct sr_ip_hdr*);
struct sr_rt* getBestRtEntry(struct sr_rt*, struct sr_ip_hdr*);
int packetIsToSelf(struct sr_instance*, uint8_t*, int, char*);

/*self-defined helper functions in sr_router.c for preparing packets to send*/
void prepIPPacket(struct sr_ip_hdr*);
void prepARPPacket(uint8_t*, unsigned char*);
void prepICMPPacket();
void prepEthePacketFwd(uint8_t*, uint8_t*);
void prepEthePacket(uint8_t*);

/*self-defined helper functions in sr_router.c for making new packets*/
void makeAndSendICMP(int len, uint8_t* packet, struct sr_instance* sr, const char* iface, 
	uint8_t icmp_type, uint8_t icmp_code);
void populateICMP(struct sr_icmp_hdr* icmp_head);
void populateType3ICMP(struct sr_icmp_t3_hdr* icmp3_head);
void populateIP(struct sr_ip_hdr* ip_head, struct sr_ip_hdr* ip_buf);

void sendARPReq(int len, unsigned char* dest_mac_addr, uint32_t next_hop_ip, 
	struct sr_instance* sr, const char* iface);
void populateARP(struct sr_arp_hdr*, unsigned char*, uint32_t, unsigned char*, uint32_t);
void populateMAC(sr_ethernet_hdr_t*, unsigned char*, unsigned char*);

enum icmp_type {
  is_icmp3 = 3,
};

enum pac_len {
  arp_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr),
  icmp_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t3_hdr),
  icmp3_len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_hdr),
};

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
