#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <stdint.h>
#include <net/ethernet.h>
#include "checksum.h"

void parse_udp(const unsigned char *pkt);
void print_mac_addr(char *addr);
void parse_packet(pcap_t *pcap, const unsigned char *pkt, struct timeval ts, unsigned int cap_len);
void parse_ethernet(const unsigned char *pkt, unsigned int cap_len);
void parse_ip(const unsigned char *pkt, unsigned int cap_len);
void parse_tcp(const unsigned char *pkt, uint32_t tot_len, uint16_t ihl);
void parse_arp(const unsigned char *pkt);
void parse_icmp(const unsigned char *pkt);

enum IP_TYPE {IP_TYPE_ICMP = 1, IP_TYPE_TCP = 6, IP_TYPE_UDP = 17};
enum ARP_TYPE {ARP_RESERVED, ARP_REQUEST, ARP_REPLY};
enum ICMP_TYPE {ICMP_REPLY, ICMP_REQUEST = 8};
enum TCP_PORT {TCP_PORT_HTTP = 80};

struct ethernet_header
{
	char ether_dst[6];
	char ether_src[6];
	uint16_t ether_type;
};

struct ip_header
{
	uint32_t ip_line1;
	uint32_t ip_line2;
	uint32_t ip_line3;
	uint32_t ip_src;
	uint32_t ip_dst;
};

struct udp_header
{
	uint16_t udp_src_port;
	uint16_t udp_dst_port;
};

struct tcp_header
{
	uint16_t tcp_src_port;
	uint16_t tcp_dst_port;
	uint32_t tcp_sequence;
	uint32_t tcp_ack;
	uint32_t tcp_line4;
	uint16_t tcp_checksum;
};

struct arp_header
{
	uint32_t arp_line1;
	uint32_t arp_line2;
	uint32_t arp_line3;
	uint32_t arp_line4;
	uint32_t arp_line5;
	uint32_t arp_line6;
	uint32_t arp_line7;
};

int main(int argc, char *argv[])
{
	pcap_t *pcap;
	char errbuf[PCAP_ERRBUF_SIZE];
	const unsigned char *pkt;
	struct pcap_pkthdr hdr;
	int num_pkts = 0;

	/* skip program name */
	--argc;

	/* if there is not an argument left print an error message */
	if (argc != 1)
	{
		fprintf(stderr, "usage: ./trace filename\n");
		exit(EXIT_FAILURE);
	}

	/* open a pcap file for readin */
	pcap = pcap_open_offline(argv[1], errbuf);

	/* if NULL is returned, errbuf is filled in with the appropriate error message */
	if (pcap == NULL)
	{
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	/* loop through the packets in the pcap file */
	while ((pkt = pcap_next(pcap, &hdr)) != NULL)
	{
		num_pkts++;
		printf("\nPacket number: %d  Packet Len: %d\n\n", num_pkts, hdr.caplen);
		parse_packet(pcap, pkt, hdr.ts, hdr.caplen);
	}

	return 0;
}

void parse_packet(pcap_t *pcap, const unsigned char *pkt, struct timeval ts, unsigned int cap_len)
{
	int type = pcap_datalink(pcap);

	if (type == 1)
		parse_ethernet(pkt, cap_len);
}

/* need to print the dest, src, and protocol type */
void parse_ethernet(const unsigned char *pkt, unsigned int cap_len)
{
	struct ethernet_header *hdr = (struct ethernet_header *) pkt;
	uint16_t type_ntohs = ntohs(hdr->ether_type);
	
	printf("\tEthernet Header\n\t\tDest MAC: ");
	print_mac_addr(hdr->ether_dst);
	printf("\t\tSource MAC: ");
	print_mac_addr(hdr->ether_src);

	if (type_ntohs == ETHERTYPE_IP)
	{
		printf("\t\tType: IP\n\n\tIP Header\n");
		parse_ip(pkt+sizeof(struct ethernet_header), cap_len);
	}
	else if (type_ntohs == ETHERTYPE_ARP)
	{
		printf("\t\tType: ARP\n\n\tARP Header\n");
		parse_arp(pkt+sizeof(struct ethernet_header));
	}
}

void parse_arp(const unsigned char *pkt)
{
	struct arp_header *hdr = (struct arp_header*) pkt;
	uint32_t line2_ntohl = ntohl(hdr->arp_line2);

	uint16_t *arp_opcode = (uint16_t*) &line2_ntohl;
	char *addr_len = (char*) &(hdr->arp_line2);
	char *mac_addr = (char*) &(hdr->arp_line3);
	int i;

	/* opcode */
	printf("\t\tOpcode: ");
	
	/* host byte order */
	if (*arp_opcode == ARP_RESERVED)
		printf("Reservedy\n");
	else if (*arp_opcode == ARP_REQUEST)
		printf("Request\n");
	else if (*arp_opcode == ARP_REPLY)
		printf("Reply\n");

	/* network byte order */

	/* Sender Mac */
	printf("\t\tSender MAC: ");
	for (i = 0; i < *addr_len; i++)
	{
		/* first 4 bytes of address */
		if (i < 4)
		{
			printf("%x:", *mac_addr & 0xff);
			mac_addr++;
		}
		/* rest of the bytes start in next line */
		else
		{
			if (i == 4)
				mac_addr = (char*) &(hdr->arp_line4);
			(i < (*addr_len - 1))? printf("%x:", *mac_addr & 0xff): 
				printf("%x\n", *mac_addr & 0xff);
			mac_addr++;
		}
	}

	addr_len++;
	
	/* Sender IP */
	printf("\t\tSender IP: ");
	mac_addr = (char*) &(hdr->arp_line4);
	mac_addr += 2;
	for (i = 0; i < *addr_len; i++)
	{
		/* first two bytes of address are in line 4 */
		if (i < 2)
		{
			printf("%u.", *mac_addr & 0xff); 
			mac_addr++;
		}
		else
		{
			if (i == 2)
				mac_addr = (char*) &(hdr->arp_line5);
			(i < (*addr_len - 1))? printf("%u.", *mac_addr): printf("%u\n", *mac_addr);
			mac_addr++;
		}
	}

	addr_len--;
	/* Target MAC */
	printf("\t\tTarget MAC: ");
	mac_addr = (char*) &(hdr->arp_line5);
	mac_addr += 2;
	for (i = 0; i < *addr_len; i++)
	{
		/* first 4 bytes of address */
		if (i < 2)
		{
			printf("%x:", *mac_addr);
			mac_addr++;
		}
		/* rest of the bytes start in next line */
		else
		{
			if (i == 2)
				mac_addr = (char*) &(hdr->arp_line6);
			(i < (*addr_len - 1))? printf("%x:", *mac_addr & 0xff): 
				printf("%x\n", *mac_addr & 0xff);
			mac_addr++;
		}
	}

	/* Target IP */
	addr_len++;
	printf("\t\tTarget IP: ");
	mac_addr = (char*) &(hdr->arp_line7);
	for (i = 0; i < *addr_len; i++, mac_addr++)
	{
		(i < (*addr_len - 1))? printf("%u.", *mac_addr & 0xff): 
			printf("%u\n", *mac_addr & 0xff);
	}
}

void parse_ip(const unsigned char *pkt, unsigned int cap_len)
{
	int i, ip_type;
	struct ip_header *hdr = (struct ip_header*) pkt;
	char version;
	uint32_t total_len = ntohs(((hdr->ip_line1) & 0xffff0000) >> 16);
	uint16_t ihl = (ntohs(((hdr->ip_line1) & 0xff0f)) >> 8)*4;

	/* network byte order */
	char *byte = (char*) &(hdr->ip_line1);
	for (i = 0; i < 4; i++, byte++)
	{
		if (i == 0)
			version = (*byte & 0xf0) >> 4;
		// the second byte has TOS and ECN
		else if (i == 1)
			printf("\t\tTOS: 0x%x\n", 0xff & *byte);
	}	

	/* printing line 3 */
	unsigned int checksum = 0;
	uint16_t *two_bytes = (uint16_t*) pkt;
	uint16_t carry_bits = 0;
	uint16_t checksum_correct = 0;
	for (i = 0; i < 10; i++, two_bytes++)
		checksum += ntohs(*two_bytes);
	carry_bits = checksum >> 16;
	checksum = (checksum & 0x0ffff) + carry_bits;
	checksum = checksum ^ 0xffff;
	if (checksum == 0)
		checksum_correct = 1;
	
	byte = (char*) &(hdr->ip_line3);
	for (i = 0; i < 3; i++, byte++)
	{
		if (i == 0)
			printf("\t\tTTL: %d\n", 0xff & *byte);
		else if (i == 1)
		{
			ip_type = 0xff & *byte;
			printf("\t\tProtocol: ");
			if (ip_type == IP_TYPE_UDP)
				printf("UDP\n");
			else if (ip_type == IP_TYPE_TCP)
				printf("TCP\n");
			else if (ip_type == IP_TYPE_ICMP)
				printf("ICMP\n");
			else
				printf("Unknown\n");
		}
		else if (i == 2)
		{
			int j;
			printf("\t\tChecksum: ");
			(checksum_correct)? printf("Correct "): printf("Incorrect ");
			for (j = 0; j < 2; j++, byte++)
			{
				if (j == 0)
					printf("(0x%0x", 0xff & *byte);
				else
					printf("%02x)\n", 0xff & *byte);
			}
		}
	}

	/* printing sender ip */
	byte = (char*) &(hdr->ip_src);
	printf("\t\tSender IP: ");
	for (i = 0; i < 4; i++, byte++)
	{
		if (i < 3)
			printf("%d.", 0xff & *byte);
		else
			printf("%d", 0xff & *byte);
	}

	/* printing destination ip */
	byte = (char*) &(hdr->ip_dst);
	printf("\n\t\tDest IP: ");
	for (i = 0; i < 4; i++, byte++)
	{
		if (i < 3)
			printf("%d.", 0xff & *byte);
		else
			printf("%d", 0xff & *byte);
	}
	printf("\n");

	if (ip_type == IP_TYPE_UDP)
	{
		printf("\n\tUDP Header\n");
		parse_udp(pkt+sizeof(struct ip_header));
	}
	else if (ip_type == IP_TYPE_TCP)
	{
		printf("\n\tTCP Header\n");
		parse_tcp(pkt+sizeof(struct ip_header), total_len, ihl);
	}
	else if (ip_type == IP_TYPE_ICMP)
	{
		printf("\n\tICMP Header\n");
		if (version == 4)
			parse_icmp(pkt+sizeof(struct ip_header));
		else
			printf("\t\tType: Unknown\n");
	}
}

void parse_icmp(const unsigned char *pkt)
{
	uint32_t *icmp_pkt = (uint32_t*) pkt;	
	char icmp_type = *icmp_pkt & 0xff;

	/* host byte order */
	printf("\t\tType: ");
	if (icmp_type == ICMP_REQUEST)
		printf("Request\n");
	else if (icmp_type == ICMP_REPLY)
		printf("Reply\n");
}

void parse_tcp(const unsigned char *pkt, uint32_t total_len, uint16_t ihl)
{
	struct tcp_header *hdr = (struct tcp_header*) pkt;	
	uint16_t src_port_ntohs = ntohs(hdr->tcp_src_port);
	uint16_t dst_port_ntohs = ntohs(hdr->tcp_dst_port);
	uint32_t sequence_ntohl = ntohl(hdr->tcp_sequence);
	uint32_t ack_ntohl = ntohl(hdr->tcp_ack);
	uint32_t line4_ntohl = ntohl(hdr->tcp_line4);
	uint16_t checksum_ntohs = ntohs(hdr->tcp_checksum);

	char *byte = (char*) &(hdr->tcp_line4);
	uint16_t *window_size = (uint16_t*) &(line4_ntohl);

	/* printing source port */
	printf("\t\tSource Port:  ");

	if (src_port_ntohs == TCP_PORT_HTTP)
		printf("HTTP\n");
	else
		printf("%d\n", src_port_ntohs);

	/* printing destination port */
	printf("\t\tDest Port:  ");

	if (dst_port_ntohs == TCP_PORT_HTTP)
		printf("HTTP\n");
	else
		printf("%d\n", dst_port_ntohs);

	/* printing sequence number */
	printf("\t\tSequence Number: %u\n", sequence_ntohl);

	/* printing acknowledgement number */
	printf("\t\tACK Number: %u\n", ack_ntohl);
	
	/* data offset */
	uint16_t data_offset = (*byte >> 4) & 0xf;

	//printf("data offset original: %x\n", *byte);

	++byte;
	/* syn flag */
	printf("\t\tSYN Flag: ");
	(*byte & 0x2)? printf("Yes\n"): printf("No\n");

	/* rst flag */
	printf("\t\tRST Flag: ");
	(*byte & 0x4)? printf("Yes\n"): printf("No\n");

	/* fin flag */
	printf("\t\tFIN Flag: ");
	(*byte & 0x1)? printf("Yes\n"): printf("No\n");

	/* window size */
	printf("\t\tWindow Size: %hu\n", *window_size);

	uint16_t protocol = 0x0006;
	uint16_t tcp_length = data_offset*4;
	/* take away ethernet, ip, and tcp header length*/
	uint16_t tcp_data_length = total_len - (ihl + tcp_length);
	unsigned int checksum = protocol + (tcp_length+tcp_data_length);
	uint16_t *two_bytes = (uint16_t*) (pkt - 8);
	uint16_t carry_bits = 0;
	uint16_t checksum_correct = 0;
	int i, iterations, even = 1;
	int total_bytes_to_add = tcp_data_length + tcp_length + 8;

	if ((total_bytes_to_add % 2) != 0)
	{
		iterations = total_bytes_to_add/2 + 1;
		even = 0;
	}
	else
		iterations = total_bytes_to_add/2;

	for (i = 0; i < iterations; i++, two_bytes++)
	{
		if (i == (iterations - 1) && !even)
		{
			uint16_t last_byte = ntohs(*two_bytes);
			checksum += (last_byte & 0xff00);
		}
		else
		{
			checksum += ntohs(*two_bytes);
		}
	}

	carry_bits = checksum >> 16;
	checksum = (checksum & 0xffff) + carry_bits;
	checksum = checksum ^ 0xffff;

	if (checksum == 0)
		checksum_correct = 1;

	/* checksum */
	if (checksum_correct)
		printf("\t\tChecksum: Correct (0x%x)\n", checksum_ntohs);
	else
		printf("\t\tChecksum: Incorrect (0x%x)\n", checksum_ntohs);
}

void parse_udp(const unsigned char *pkt)
{
	struct udp_header *hdr = (struct udp_header*) pkt;
	uint16_t src_port_ntohs = ntohs(hdr->udp_src_port);
	uint16_t dst_port_ntohs = ntohs(hdr->udp_dst_port);
	
	/* printing source port */
	printf("\t\tSource Port:  %hd\n", src_port_ntohs);

	/* printing destination port */
	printf("\t\tDest Port:  %hd\n", dst_port_ntohs);
} 

void print_mac_addr(char *addr)
{
	int i;
	unsigned short *ptr = (unsigned short *) addr;
	for (i = 0; i < 3; i++, ptr++)
	{
		int j;
		char *byte;
		unsigned short addr_ntohs = ntohs(*ptr);

		byte = (char*) &addr_ntohs;
		byte++; // print higher byte first

		for (j = 0; j < 2; j++, byte--)
		{
			if (i < 2 || (i == 2 && j == 0))
				printf("%x:", *byte & 0xff);
			else
				printf("%x\n", *byte & 0xff);
		}
	}
}
