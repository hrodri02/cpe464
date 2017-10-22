/*
 * ============================================================================
 *
 *       Filename:  fish_l2.c
 *
 *    Description:  fish net layer 2 functions
 *
 *        Version:  1.0
 *        Created:  10/14/2017 06:47:30 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Heriberto Rodriguez (HR), hrodri02@calpoly.edu
 *          Class:  
 *
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <assert.h>
#include <signal.h>
#include "fish.h"
#include "fishnode.h"



#define DEBUG

static int noprompt = 0;

void sigint_handler(int sig)
{
   if (SIGINT == sig)
	   fish_main_exit();
}

static void keyboard_callback(char *line)
{
   if (0 == strcasecmp("show neighbors", line))
      fish_print_neighbor_table();
   else if (0 == strcasecmp("show arp", line))
      fish_print_arp_table();
   else if (0 == strcasecmp("show route", line))
      fish_print_forwarding_table();
   else if (0 == strcasecmp("show dv", line))
      fish_print_dv_state();
   else if (0 == strcasecmp("quit", line) || 0 == strcasecmp("exit", line))
      fish_main_exit();
   else if (0 == strcasecmp("show topo", line))
      fish_print_lsa_topo();
   else if (0 == strcasecmp("help", line) || 0 == strcasecmp("?", line)) {
      printf("Available commands are:\n"
             "    exit                         Quit the fishnode\n"
             "    help                         Display this message\n"
             "    quit                         Quit the fishnode\n"
             "    show arp                     Display the ARP table\n"
             "    show dv                      Display the dv routing state\n"
             "    show neighbors               Display the neighbor table\n"
             "    show route                   Display the forwarding table\n"
             "    show topo                    Display the link-state routing\n"
             "                                 algorithm's view of the network\n"
             "                                 topology\n"
             "    ?                            Display this message\n"
            );
   }
   else if (line[0] != 0)
      printf("Type 'help' or '?' for a list of available commands.  "
             "Unknown command: %s\n", line);

   if (!noprompt)
      printf("> ");

   fflush(stdout);
}

int main(int argc, char **argv)
{
	struct sigaction sa;
   int arg_offset = 1;

   /* Verify and parse the command line parameters */
	if (argc != 2 && argc != 3 && argc != 4)
	{
		printf("Usage: %s [-noprompt] <fishhead address> [<fn address>]\n", argv[0]);
		return 1;
	}

   if (0 == strcasecmp(argv[arg_offset], "-noprompt")) {
      noprompt = 1;
      arg_offset++;
   }

   /* Install the signal handler */
	sa.sa_handler = sigint_handler;
	sigfillset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (-1 == sigaction(SIGINT, &sa, NULL))
	{
		perror("Couldn't set signal handler for SIGINT");
		return 2;
	}

   /* Set up debugging output */
#ifdef DEBUG
	fish_setdebuglevel(FISH_DEBUG_ALL);
#else
	fish_setdebuglevel(FISH_DEBUG_NONE);
#endif
	fish_setdebugfile(stderr);

   /* Join the fishnet */
	if (argc-arg_offset == 1)
   {
		fish_joinnetwork(argv[arg_offset]);
   }
	else
   {
		fish_joinnetwork_addr(argv[arg_offset], fn_aton(argv[arg_offset+1]));
   }

   /* Install the command line parsing callback */
   fish_keybhook(keyboard_callback);
   if (!noprompt)
      printf("> ");
   fflush(stdout);

   /* Enable the built-in neighbor protocol implementation.  This will discover
    * one-hop routes in your fishnet.  The link-state routing protocol requires
    * the neighbor protocol to be working, whereas it is redundant with DV.
    * Running them both doesn't break the fishnode, but will cause extra routing
    * overhead */
   fish_enable_neighbor_builtin( 0
         | NEIGHBOR_USE_LIBFISH_NEIGHBOR_DOWN
      );

   /* Enable the link-state routing protocol.  This requires the neighbor
    * protocol to be enabled. */
   fish_enable_lsarouting_builtin(0);

   /* Full-featured DV routing.  I suggest NOT using this until you have some
    * reasonable expectation that your code works.  This generates a lot of
    * routing traffic in fishnet */

   fish_enable_dvrouting_builtin( 0
         | DVROUTING_WITHDRAW_ROUTES
         // | DVROUTING_TRIGGERED_UPDATES
         | RVROUTING_USE_LIBFISH_NEIGHBOR_DOWN
         | DVROUTING_SPLIT_HOR_POISON_REV
         | DVROUTING_KEEP_ROUTE_HISTORY
    );

   fish_l2.fishnode_l2_receive = my_fishnode_l2_receive;
   fish_arp.send_arp_request = my_send_arp_request;

   /* Execute the libfish event loop */
	fish_main();

   /* Clean up and exit */
   if (!noprompt)
      printf("\n");

	printf("Fishnode exiting cleanly.\n");

	return 0;
}



void print_mac_addr(void *addr)
{
   int i;
   unsigned short *ptr = (unsigned short*) addr;
   for (i = 0; i < 3; i++, ptr++)
   {
      int j;
      char *byte;
      unsigned short addr_ntohs = ntohs(*ptr);

      byte = (char*) &addr_ntohs;
      byte++;

      for (j = 0; j < 2; j++, byte--)
      {
         if (i < 2 || (i == 2 && j == 0))
            printf("%02x:", *byte & 0xff);
         else
            printf("%02x\n", *byte & 0xff);
      }
   }
}

int verify_chksum(void *l2frame)
{
   unsigned int checksum = 0, i = 0;
   uint16_t *two_bytes = (uint16_t*) l2frame;
   uint16_t carry_bits = 0;
   uint16_t checksum_correct = 0;
   struct l2_frame* ptr_l2_frame = (struct l2_frame*) l2frame;
   uint16_t l2frame_len = ntohs(ptr_l2_frame->l2_frame_len);

   //printf("l2frame_len/2: %d\n", l2frame_len/2);

   for (i = 0; i < l2frame_len/2; two_bytes++, i++)
   {
      checksum += ntohs(*two_bytes);
      //checksum += *two_bytes;
      //printf("current two bytes: %x\n", *two_bytes);
   }

   //printf("checksum before shift: %x\n", checksum);

   carry_bits = checksum >> 16;
   checksum = (checksum & 0x0ffff) + carry_bits;
   checksum = checksum ^ 0xffff;

   //printf("final value of checksum: %x\n", checksum);

   if (checksum == 0)
      checksum_correct = 1;
   
   return checksum_correct;
}

int verify_dst_addr(void* l2frame)
{
   struct l2_frame* ptr_l2_frame = (struct l2_frame*) l2frame;
   fn_l2addr_t node_addr = fish_getl2address(); 

   //printf("node address: %s\n", fnl2_ntoa(node_addr));
   //printf("dst address: %s\n", fnl2_ntoa(ptr_l2_frame->mac_dst));

   return (FNL2_EQ(node_addr, ptr_l2_frame->mac_dst) ||
      FNL2_EQ(ALL_L2_NEIGHBORS, ptr_l2_frame->mac_dst));   
}


/* 
 * ===  FUNCTION  =============================================================
 *         Name:  cb
 *  Description:  This function is called when resolve_fnaddr has successfully
 *  mapped the l3 address to a l2 address or when the mapping is unsuccessful.
 *  If the mappping was unsuccessful then the l2 address is invalid. 
 *
 *  This function is responsible for freeing param before it returns.
 * ============================================================================
 */
void cb(fn_l2addr_t addr, void *l2frame)
{
   struct l2_frame *ptr_l2frame = (struct l2_frame*) l2frame;
   
   /* check if mapping was completed successfully */
   if (FNL2_VALID(addr))
   {
      ptr_l2frame->mac_dst = addr; 

      /* calculate checksum */
      ptr_l2frame->checksum = in_cksum(l2frame, ptr_l2frame->l2_frame_len);

      /* send packet */
      if (fish_l1_send(l2frame) == -1)
      {
         printf("cb: frame could not be sent\n");
      }
   }
   else
      printf("invalid address detected\n");

   free(l2frame);
}

/* 
 * ===  FUNCTION  =============================================================
 *         Name:  my_fish_l2_send
 *  Description:  Receives a new L3 frame to be sent over the network
 *
 *  - l3frame is a pointer to the L3 frame. The original frame memory must not
 *    be modified. The caller is responsible for freeing any memory after this
 *    function has completed.
 *  - next_hop The L3 address of the neighbor this frame should be sent to.
 *  - len The length of the L3 frame
 *
 *  Returns:
 *    false if the send is known to have failed and true otherwise
 *
 *    This function takes the following steps to transmit l3frame:
 *  - Adds an L2 header to the frame
 *  - Uses the ARP cache to resolve the L3 address to L2
 *  - Calls fish_l1_send() to transmit the frame
 * ============================================================================
 */
int my_fish_l2_send(void *l3frame, fnaddr_t next_hop, int len)
{
   struct l2_frame *ptr_l2frame;
   //struct l3_frame *ptr_l3frame = (struct l3_frame*) l3frame;

   /* add l2 header to the frame */
   void *l2frame = malloc(sizeof(struct l2_frame) + len);

   /* check malloc return value */
   if (l2frame == NULL)
      return FALSE;

   ptr_l2frame = (struct l2_frame*) l2frame;

   /* copy l3 frame to new frame */
   memcpy(l2frame + sizeof(struct l2_frame), l3frame, sizeof(struct l3_frame));

   /* get source mac address */
   ptr_l2frame->mac_src = fish_getl2address();

   /* calculate the frame length (dependent on protocol) */
   ptr_l2frame->l2_frame_len = sizeof(struct l2_frame) + len; 

   /* resolving the l3 address to l2 */
  // fish_arp tmp_fish_arp;

   /* no code after this function is called */
   fish_arp.resolve_fnaddr(next_hop, cb, l2frame);

   return TRUE;
}

/* 
 * ===  FUNCTION  =============================================================
 *         Name:  my_fishnode_l2_receive
 *  Description:  
 *  
 *  l2frame a pointer to the received L2 frame. The frame must not be modified.
 *  The caller will free the memory for the frame as necessary.
 *
 *  Returns:
 *    false if the receive is known to have failed and true otherwise.
 *
 *  Responsible for correctly directing valid packets to the
 *  higher network layers. This requires following general steps:
 *  -Dropping fameswith invalid checksums
 *  -Dropping frames that are not destined for this node (verifies the L2
 *  address. doesn't consider the L3 address).
 *  -Decapsulating frame and passing up the stack (fish_l3::fish_l3_recieve).
 *
 *  This is also the function that calls your implementation of the fishnet L2
 *  protocols, such as ARP.
 * ============================================================================
 */
int my_fishnode_l2_receive(void *l2frame)
{
   struct l3_frame* ptr_l3_frame;
   struct l2_frame* ptr_l2_frame;
   void *l3frame, *l4frame;
   fish_debugframe(FISH_DEBUG_ALL, "calling fish_debugframe\n", l2frame, 2, 32, 
      9);

   /* drop frames with invalid checksums or not destined for this node */
   if ((verify_chksum(l2frame) ==  0) || (verify_dst_addr(l2frame) == 0))
      return FALSE;
  
   /* decapsulate l2 frame */
   l3frame = l2frame + sizeof(struct l2_frame);

   /* pass the frame up the networking stack */
   ptr_l2_frame = (struct l2_frame*) l2frame;

   printf("l2 frame len: %d\n", ptr_l2_frame->l2_frame_len);
   printf("l2 frame len (ntohs): %d\n", ntohs(ptr_l2_frame->l2_frame_len));

   fish_l3.fish_l3_receive(l3frame, ntohs(ptr_l2_frame->l2_frame_len) - 
      sizeof(struct l2_frame));

   /* check protocol field of l3 frame to see if we need to call arp funcs */
   ptr_l3_frame = (struct l3_frame*) l3frame;
   l4frame = l3frame + sizeof(struct l3_frame);
   
   if (ptr_l3_frame->protocol == FISHNET_ARP_PROTOCOL)
   {
      struct arp_frame* ptr_arp_frame = (struct arp_frame *) l4frame;

      printf("l4 protocol is arp\n");

      /* check the query type */
      if (ptr_arp_frame->query_type == ARP_REQUEST)
         my_arp_received(l2frame);
      else
         printf("unknown query\n");

      /* 
      else if (ptr_arp_frame->query_type == ARP_RESPONSE)
         my_send_arp_request(l2frame);
      */
   }
   else if (ptr_l3_frame->protocol == NEIGHBOR_PROTOCOL)
   {
      printf("l4 protocol is neighbor: \n");
   }

   else if (ptr_l3_frame->protocol == DISTANCE_VECTOR_ROUTING_PROTOCOL)
   {
      printf("l4 protocol is distance\n");
   }
   else
      printf("unknown l4 protocol\n");

   return TRUE;
}

/* 
 * ===  FUNCTION  =============================================================
 *         Name:  my_arp_received
 *  Description:  Gets called when ARP frame arrives at the node for processing.
 *
 *  l2frame is a pointer to the L2 frame containing the ARP packet
 *
 *  The function is responsible for generating and proessing ARP responses. It
 *  is necessary to call add_arp_entry as part of processing an ARP response.
 *  There is a built-in L2 handler that calls this function for every ARP packet
 *  destined to this fishnode. The built-in handler AUTOMATICALLY DISABLES
 *  ITSELF when you provide a pointer to your own arp_received implementation.
 *  You must add code to fish_l2::fishnode_l2_recieve to call this function if
 *  you override this function.
 * ============================================================================
 */
void my_arp_received(void *l2frame)
{
   struct l2_frame *ptr_l2_frame = (struct l2_frame*) l2frame;
   struct l3_frame *ptr_l3_frame = (struct l3_frame*) 
      (l2frame + sizeof(struct l2_frame));
   struct arp_frame *ptr_arp_frame = (struct arp_frame*) (l2frame +
      sizeof(struct l2_frame) + sizeof(struct l3_frame));

   /* we need to add <IP_sender, MAC_sender> to the arp table */
   fish_arp.add_arp_entry(ptr_l2_frame->mac_src, ptr_l3_frame->src_addr, 180);

   /* check if the requested MAC address corresponds to our IP address */
   if (ptr_arp_frame->l3_addr == fish_getaddress())
   {
      /* build frame containing arp response */
      void *frame = malloc(sizeof(struct l2_frame) + sizeof(struct l3_frame) + 
         sizeof(struct arp_frame));
      
      struct l2_frame *ptr_l2frame = (struct l2_frame*) frame;
      struct l3_frame *ptr_l3frame = (struct l3_frame*) 
         (frame + sizeof(struct l2_frame));
      struct arp_frame *ptr_arpframe = (struct arp_frame*) (frame +
         sizeof(struct l2_frame) + sizeof(struct l3_frame));

      /* build l2 frame */
      ptr_l2frame->mac_dst = ptr_l2_frame->mac_src;
      ptr_l2frame->mac_src = fish_getl2address(); 
      ptr_l2frame->l2_frame_len = sizeof(struct l2_frame) + 
         sizeof(struct l3_frame) + sizeof(struct arp_frame);

      printf("arp packet len: %x\n", ptr_l2frame->l2_frame_len);

      /* build l3 frame */
      ptr_l3frame->ttl = 1;   /* to prevent the pack from leaving LAN */
      ptr_l3frame->protocol = FISHNET_ARP_PROTOCOL;
      ptr_l3frame->packet_id = fish_next_pktid();
      ptr_l3frame->src_addr = fish_getaddress();
      ptr_l3frame->dst_addr = ptr_l3_frame->src_addr;

      /* build arp frame */
      ptr_arpframe->query_type = ARP_RESPONSE;
      ptr_arpframe->l3_addr = ptr_l3frame->src_addr;
      ptr_arpframe->l2_addr = ptr_l2frame->mac_src;

      /* calc checksum */
      ptr_l2frame->checksum = in_cksum(frame, ptr_l2frame->l2_frame_len);

      /* send arp response through the fishnet overlay */   
      if (fish_l1_send(frame) == 0)
         printf("packet sent successfully\n");
      else
         printf("packet was not sent\n");
   }
}

/* 
 * ===  FUNCTION  =============================================================
 *         Name:  my_send_arp_request
 *  Description:  This function creates and sends an ARP request for the given
 *  L3 address.
 *
 *  l3addr is the L3 address to send an ARP request for.
 *
 *  This function is called as part of fish_arp_resolve_fnaddr when no entry is
 *  present in the ARP cache. It must create and send an appropriate ARP request
 *  frame.
 * ============================================================================
 */
void my_send_arp_request(fnaddr_t l3addr)
{
   /* sending an arp request frame involves 
    * 1. setting the L2 and L3 address to broadcast addresses
    * 2. setting the TTL to 1 so that the packet doesn't leave the LAN
    * 3. In the ARP header set the query type to request and the ip address
    *    to the address that was passed to this function
    */

   printf("using my arpt request function\n");

   /* build frame containing arp response */
   void *frame = malloc(sizeof(struct l2_frame) + sizeof(struct l3_frame) + 
      sizeof(struct arp_frame));
      
   struct l2_frame *ptr_l2frame = (struct l2_frame*) frame;
   struct l3_frame *ptr_l3frame = (struct l3_frame*) 
      (frame + sizeof(struct l2_frame));
   struct arp_frame *ptr_arpframe = (struct arp_frame*) (frame +
      sizeof(struct l2_frame) + sizeof(struct l3_frame));

   /* build l2 frame */
   ptr_l2frame->mac_dst = ALL_L2_NEIGHBORS;
   ptr_l2frame->mac_src = fish_getl2address(); 
   ptr_l2frame->l2_frame_len = htons(sizeof(struct l2_frame) + 
      sizeof(struct l3_frame) + sizeof(struct arp_frame));

   /* build l3 frame */
   ptr_l3frame->ttl = 1;   /* to prevent the pack from leaving LAN */
   ptr_l3frame->protocol = FISHNET_ARP_PROTOCOL;
   ptr_l3frame->packet_id = fish_next_pktid();
   ptr_l3frame->src_addr = fish_getaddress();
   ptr_l3frame->dst_addr = ALL_NEIGHBORS;

   /* build arp frame */
   ptr_arpframe->query_type = ARP_REQUEST;
   ptr_arpframe->l3_addr = l3addr;

   /* calc checksum */
   ptr_l2frame->checksum = in_cksum(frame, ntohs(ptr_l2frame->l2_frame_len));

   /* send arp response through the fishnet overlay */   
   if (fish_l1_send(frame) == 0)
      printf("packet sent successfully\n");
   else
      printf("packet was not sent\n");
}
