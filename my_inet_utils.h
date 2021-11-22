#include <stdio.h>
#include <time.h>

#include <netinet/in.h>

#include "my_pcap_utils.h"

/* Useful stuff */

// TCP header Flags
#define MIU_TCP_FIN 0x01
#define MIU_TCP_SYN 0x02
#define MIU_TCP_RST 0x04
#define MIU_TCP_PSH 0x08
#define MIU_TCP_ACK 0x10
#define MIU_TCP_URG 0x20

#define MIU_IP4_DF 0x4000
#define MIU_IP4_MF 0x2000

// Structs do not use bit-fields because of uncertainty about bit-field packing.
// Instead, separate fields are noted by a double-underscore between field names.

// IPv4 header
struct ipv4_hdr {
	uint8_t version__IHL; // 4 bits for version
	uint8_t type_of_service;
	uint16_t total_length;
	uint16_t identification;
	uint16_t flags__fragment_offset; // 3 bits for flags
	uint8_t time_to_live;
	uint8_t protocol;
	uint16_t header_checksum;
	uint32_t source_address;
	uint32_t destination_address;
} __attribute__ ((packed));

// TCP header
struct tcp_hdr {
	uint16_t source_port;
	uint16_t destination_port;
	uint32_t sequence_number;
	uint32_t acknowledgement_number;
	uint8_t data_offset__reserved__NS; // 4 + 3 + 1
	uint8_t flags;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_pointer;
} __attribute__ ((packed));

// Pseudo-IPv4 header used in calculating the TCP checksum
struct tcp_pseudo_ip_hdr {
   uint32_t src_ip;
   uint32_t dest_ip;
   uint8_t zeroes;
   uint8_t protocol;
   uint16_t tcp_length;
} __attribute__ ((packed));

// Creates an IPv4 header with many values set according to a default.
// hdr: Pointer to allocated memory to create the header in.
// data_len: The length, in bytes, of the data.
// protocol: According to rfc 790 "assigned numbers" 
// srce_ip_addr: Use inet_addr() or inet_aton()
// dest_ip_addr: Use inet_addr() or inet_aton()
void gen_ipv4_hdr(struct ipv4_hdr* hdr, uint16_t data_len, uint8_t protocol, uint32_t srce_ip_addr, uint32_t dest_ip_addr) {
	hdr->version__IHL = 0x45;
	hdr->type_of_service = 0x00;
	hdr->total_length = (((uint8_t) (20 + data_len)) >> 8) + (((uint8_t) (20 + data_len)) << 8); // Fuck little-endian CPUs.
	hdr->identification = 0x0000;
	hdr->flags__fragment_offset = htons(0x4000);
	hdr->time_to_live = 0x40;
	hdr->protocol = protocol;
	hdr->header_checksum = 0x0000;
	hdr->source_address = srce_ip_addr;
	hdr->destination_address = dest_ip_addr;
	
	// Calculate header checksum
	uint32_t checksum = 0;
	for (int i = 0; i < 10; i++) {
		uint16_t word = ((uint16_t*) hdr)[i];
		word = (word >> 8) | (word << 8);
		checksum += word;
		
		if (checksum > 0xFFFF) {
			checksum = (checksum & 0xFFFF) + 1;
		}
	}
	checksum = ~checksum & 0xFFFF;
	hdr->header_checksum = (uint16_t) ((checksum >> 8) | (checksum << 8));
}

void gen_tcp_hdr(struct tcp_hdr* hdr, uint16_t srce_port, uint16_t dest_port, uint8_t flags, uint32_t seq, uint32_t ack, uint16_t wins, 
                 uint32_t srce_addr, uint32_t dest_addr, uint16_t data_len, unsigned char* data) {
	hdr->source_port = htons(srce_port);
	hdr->destination_port = htons(dest_port);
	hdr->sequence_number = htonl(seq);
	hdr->acknowledgement_number = htonl(ack);
	hdr->data_offset__reserved__NS = 0x50;
	hdr->flags = flags;
	hdr->window_size = htons(wins);
	hdr->checksum = 0x0000;
	hdr->urgent_pointer = 0x0000;
	
	// Calculate header checksum
	uint32_t checksum = 0;
	for (int i = 0; i < 10; i++) {
		uint16_t word = ((uint16_t*) hdr)[i];
		checksum += word;
	}
	
	// Add IP pseudo-header to checksum
	uint32_t ph_checksum = 0;
	ph_checksum += (uint16_t) (srce_addr & 0x0000FFFF);
	ph_checksum += (uint16_t) (srce_addr >> 16);
	ph_checksum += (uint16_t) (dest_addr & 0x0000FFFF);
	ph_checksum += (uint16_t) (dest_addr >> 16);
	ph_checksum += htons(0x0006);
	ph_checksum += htons(20 + data_len);
	
	ph_checksum = (ph_checksum >> 16) + (ph_checksum & 0xFFFF);
	ph_checksum += ph_checksum >> 16;
	
	checksum += ph_checksum;
	
	// Add data to checksum
	for (int i = 0; i < data_len/2; i++) {
		uint16_t word = ((uint16_t*) data)[i];
		checksum += word;
	}
	
	// If data is of odd length, include last byte with padded zeroes and include it in the checksum.
	if (data_len % 2 == 1) {
		checksum += (uint16_t) data[data_len-1];
	}
	
	checksum = (checksum & 0xFFFF) + (checksum >> 16);
	if (checksum > 0xFFFF) {
		checksum = (checksum & 0xFFFF) + 1;
	}
	
	checksum = ~checksum & 0xFFFF;
	
	hdr->checksum = (uint16_t) checksum;
}

uint16_t in_cksum(const void* addr, unsigned len, uint16_t init) {
  uint32_t sum;
  const uint16_t* word;

  sum = init;
  word = addr;
	
  while (len >= 2) {
    sum += *(word++);
    len -= 2;
  }

  if (len > 0) {
    sum += (uint16_t) *(uint8_t *)word;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ((uint16_t)~sum);
}

int validate_TCPIP_hdr(const u_char *packets, int validate_tcp_checksum) {
  uint16_t csum;
  
  const struct ipv4_hdr* ip;
  const struct tcp_hdr* tcp;
	
  // Verify IP header and calculate IP payload length
  ip = (const struct ipv4_hdr*)(packets);
  unsigned int ip_hdr_len  = (ip->version__IHL & 0x0F) * 4;
  if (ip_hdr_len < sizeof(struct ipv4_hdr)) {
    printf("IP packets must not be smaller than the mandatory IP header (ip_hdr_len = %d).\n", ip_hdr_len);
    return 0;
  }
  if (in_cksum(ip, ip_hdr_len, 0) != 0) {
    printf("Invalid IP checksum.\n");
    return 0;
  }
  
  unsigned int ip_pkt_len = ntohs(ip->total_length);
  if (ip_pkt_len < ip_hdr_len) {
    printf("The overall packet cannot be smaller than the header.\n");
    return 0;
  }
  
  unsigned int ip_payload_len = ip_pkt_len - ip_hdr_len;

  // Verify that there really is a TCP header following the IP header
  if (ip->protocol != 6) {
      printf("No TCP Packet!\n");
      return 0;
  }
  if (ip_payload_len < sizeof(struct tcp_hdr)) {
    printf("A TCP header doesn't fit into the data that follows the IP header.\n");
    return 0;
  }
	
	if (validate_tcp_checksum) {
		// TCP header starts directly after IP header
		tcp = (const struct tcp_hdr*)((const u_char *)ip + ip_hdr_len);

		// Build the pseudo header and checksum it
		struct tcp_pseudo_ip_hdr pseudo;
		pseudo.src_ip = ip->source_address;
		pseudo.dest_ip = ip->destination_address;
		pseudo.zeroes = 0;
		pseudo.protocol = 6;
		pseudo.tcp_length = htons(ip_payload_len);
		
		csum = in_cksum(&pseudo, (unsigned)sizeof(pseudo), 0);

		// Update the checksum by checksumming the TCP header
		// and data as if those had directly followed the pseudo header
		csum = in_cksum(tcp, ip_payload_len, (uint16_t)~csum);
		
		if (csum) {
			if ((ip->source_address & 0xFF) == 0x7F && (ip->destination_address & 0xFF) == 0x7F) {
				printf("Invalid TCP checksum. NIC is \"lo\", so probably caused by checksum offloading.\n");
			}
			else {
				printf("Invalid TCP checksum.\n");
			}
			
			return 0;
		}
	}

  return 1;
}










