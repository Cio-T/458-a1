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
	uint8_t * copy = packet;

}/* end sr_ForwardPacket */

