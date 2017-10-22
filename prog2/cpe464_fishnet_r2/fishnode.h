/*
 * ============================================================================
 *
 *       Filename:  fish_l2.h
 *
 *    Description:  prototypes for layer funcitons
 *
 *        Version:  1.0
 *        Created:  10/14/2017 06:40:35 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Heriberto Rodriguez (HR), hrodri02@calpoly.edu
 *          Class:  
 *
 * ============================================================================
 */

#ifndef FISH_L2_H
#define FISH_L2_H

enum PROTOCOL {ECHO_PROTOCOL = 2, NEIGHBOR_PROTOCOL, NAMING_PROTOCOL,
   DISTANCE_VECTOR_ROUTING_PROTOCOL = 7, FISHNET_CONTROL_MESSAGE_PROTOCOL,
   FISHNET_ARP_PROTOCOL};

enum ARP_QUERY {ARP_REQUEST = 1, ARP_RESPONSE};

enum NAMING_PACKET_TYPE {DISCOVERY_REQUEST = 1, DISCOVERY_RESPONSE};

struct l2_frame
{
   fn_l2addr_t mac_dst;
   fn_l2addr_t mac_src;
   uint16_t checksum;
   uint16_t l2_frame_len;
}__attribute__((packed));

struct l3_frame
{
   uint8_t ttl;
   uint8_t protocol;
   uint32_t packet_id;
   fnaddr_t src_addr;
   fnaddr_t dst_addr;
}__attribute__((packed));

struct neighbor_frame
{
   uint16_t packet_type;
}__attribute__((packed));

struct arp_frame
{
   uint32_t query_type;
   fnaddr_t l3_addr;
   fn_l2addr_t l2_addr;
}__attribute__((packed));

int my_fishnode_l2_receive(void *l2frame);
int my_fish_l2_send(void *l3frame, fnaddr_t next_hop, int len);
void my_arp_received(void *l2frame);
void my_send_arp_request(fnaddr_t l3addr);

#endif
