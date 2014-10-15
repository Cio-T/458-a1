/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

#define LINE_SIZE 1024

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

	FILE * fp;
	unsigned long ip_addr;
	char if_name[30];
	char *token;
	char buf[LINE_SIZE];

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

	/* Initialize struct sr_if* sr->if_list*/
/*	fp = fopen("IP_CONFIG", "r");

	if (fp == NULL){
		printf ("Error opening IP_CONFIG\n\n'");
	} else {
		while (fgets(buf, LINE_SIZE, fp)){
			printf("Interface %s\n", buf);
			sscanf(buf, "%s %lu", if_name, &ip_addr);
			printf("Interface has name %s and IP address %lu\n",
                                (const char*)if_name, ip_addr);
			sr_add_interface(sr, (const char *)if_name);
			sr_set_ether_ip(sr, (uint32_t)ip_addr);
		}
		fclose(fp);
	}

*/
	/*debug sr_init*/
	sr_print_if_list(sr);
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
	uint8_t *buf, *mac_src, *mac_dest;

	buf = malloc(len); /*allocate new memory for buf*/
	memcpy(buf, packet, len); /*let buf be a deep copy of the ethernet packet received*/
	mac_src = buf->ether_shost;
	mac_dest = buf->ether_dhost;

    if (packetIsToSelf(sr, buf, interface)){

    } else if (ethertype(buf) == ethertype_ip){/*If the ethernet packet received has protocol IP*/
        uint8_t *ip_buf = buf + sizeof(struct sr_ethernet_hdr);
        if (validIPPacket(ip_buf)){
            /*Determine if packet should be forwarded*/
            struct sr_rt * best_rt_entry = getBestRtEntry(sr->routing_table, ip_buf);

            if (!best_rt_entry){/*no matching entry in routing table*/
                /*send ICMP Destination net unreachable (type 3, code 0)*/

            }else{
                /*find next hop ip address based on longest prefix match entry in rtable*/
                uint32_t next_hop_ip = best_rt_entry->gw; /*need type cast from in_addr to uint32_t*/

                /*deal with ARP*/
                struct sr_arpentry *next_hop_ip_lookup;
                if ((next_hop_ip_lookup = sr_arpcache_lookup(sr->cache, next_hop_ip))){
                    --ip_buf->ip_ttl;
                    ip_buf->ip_sum = cksum ((const void *)ip_buf, ip_buf->ip_hl);
                    /*Forward packet*/

                } else {
                    next_hop_ip_lookup = sr_arpcache_queuereq(sr->cache, next_hop_ip, buf,
                                                              len, best_if_entry->name);
                    sr_handle_arpreq(sr->cache, next_hop_ip_lookup);
                }
                free(next_hop_ip_lookup);

            }
        }

	} else {
	    printf("Error: undefined ethernet type. Dropping packet.");
	}

	free(buf);

}/* end sr_ForwardPacket */


int validIPPacket(uint8_t *ip_buf){
    uint16_t calc_sum = cksum ((const void *)ip_buf, ip_buf->ip_hl);
    if (ip_buf->ip_v != 4) {
        printf("IP version is not 4\n");
        return 0;
    }
    if (ip_buf->ip_hl < 5) {
        printf("IP header length is %d\n", ip_buf->ip_hl);
        return 0;
    }
    if (ip_buf->ip_len < ip_buf->ip_hl*2) {
        printf("ERROR: Total length is less than header length");
        return 0;
    }
    if (ip_buf->ip_sum != calc_sum){
        /*Drop packet*/
        printf("checksum_ip=%d, checksum_calc = %d\n", ip_buf->ip_sum, calc_sum);
        return 0;
    }
    if (ip_buf->ip_ttl == 0){
        printf("ERROR: Time to live is 0\n");
        /*send ICMP Time exceeded (type 11, code 0)*/
        return 0;
    }
    retun 1;
}

struct sr_rt * getBestRtEntry(struct sr_rt* routing_table, uint8_t *ip_buf){
    struct sr_rt * rt_walker = routing_table;
    struct sr_rt * best_rt_entry = NULL;
    int longest_prefix_match = 0;
    int count = 32;
    uint32_t cmp_dest = ip_buf->ip_dst;
    struct in_addr cmp_entry;

    /*find longest prefix match entry in routing table*/
    while (rt_walker){
        /*find longest bit match length*/
        cmp_entry = rt_walker->dest & rt_walker->mask;
        while (count > longest_prefix_match){
            if ((cmp_entry ^ cmp_dest) == 0){
                longest_prefix_match = count;
                best_rt_entry = rt_walker;
            } else {
                cmp_dest = cmp_dest >> 1;
                cmp_entry = cmp_entry >> 1;
                --count;
            }
        }
        rt_walker = rt_walker->next;
        count = 32;
    }
    return best_rt_entry;
}

int * packetIsToSelf(struct sr_instance* sr, uint8_t * buf, char* if_name){
	uint8_t *new_buf = NULL;	
	int self_flag = 0;

    	if (ethertype(buf) == ethertype_ip){/*If the ethernet packet received has protocol IP*/
        	new_buf = buf + sizeof(struct sr_ethernet_hdr);

            if (new_buf->ip_p == ip_protocol_icmp){

            	uint8_t *icmp_buf = new_buf + new_buf->ip_hl;
             	if (icmp_buf->icmp_type == 8){ /*if message is an echo request*/
                	/*send ICMP Echo reply (type 0)*/

                } else {
					/*drop packet*/

				}
            } else { /*IP packet contains a UDP or TCP payload*/
                /*send ICMP Port unreachable (type 3, code 3)*/

            }

		} else if (ethertype(buf) == ethertype_arp){/*If the ethernet packet received is type ARP*/
    	    new_buf = buf + sizeof(struct sr_ethernet_hdr);
        	if (new_buf->ar_op == arp_op_reply){/*If the ARP packet is ARP reply*/
            	/*call sr_process_arpreply(struct sr_arpcache *cache,
                                    unsigned char *mac,
                                    uint32_t ip);*/
            	sr_process_arpreply(sr->cache, new_buf->ar_sha, new_buf->ar_sip);
  	   		} else if (new_buf->ar_op == arp_op_request){/*If the ARP packet is ARP request*/
    	        /*Send ARP reply packet to the sender*/

	     	} else {
    	        printf("Error: undefined ARPtype. Dropping packet.");
				/*drop packet*/

	        }
		} else {
	    	printf("Error: unrecognized ethernet type to router interface. Dropping packet.");
			/*drop packet*/

		}

    return self_flag;
}
