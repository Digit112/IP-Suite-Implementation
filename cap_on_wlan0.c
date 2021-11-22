#include <stdio.h>
#include <stdint.h>
#include <pcap/pcap.h>

#include "my_inet_utils.h"

// Captures and displays the raw bytes of a single TCP/IP packet sent from the wlan0 network device.
// Verifies the packet's checksums using a utility from my_inet_utils.

int main() {
	int err;
	char errbuf[512];
	
	// pcap stuff to intercept the packet
	pcap_t* pcap_handle;
	pcap_handle = pcap_create("wlan0", errbuf);
	if (pcap_handle == NULL) {
		printf("Could not create pcap handle: %s\n", errbuf);
	}
	
	err = pcap_activate(pcap_handle);
	if (err != 0) {
		printf("pcap_activate returned non-zero: %d\n", err);
	}
	
	struct pcap_pkthdr* pkt_hdr;
	const uint8_t* pkt_data = NULL;
	uint8_t is_tcp_ip = 0;
	
	while (!is_tcp_ip) {
		pkt_data = pcap_next(pcap_handle, pkt_hdr);
		
		if (pkt_data != NULL) {
			if ((pkt_data[14] & 0xF0) == 0x40 && pkt_data[23] == 0x06) {
				is_tcp_ip = 1;
			}
		}
	}
	
	pcap_dumper_t* pcap_fout = pcap_dump_open(pcap_handle, "out.pcap");
	pcap_dump((u_char*) pcap_fout, pkt_hdr, pkt_data);
	pcap_dump_close(pcap_fout);
	
	printf("Packet returned, captured %d bytes.\n", pkt_hdr->caplen);
	for (int i = 0; i < 14; i++) {
		printf("%02x ", pkt_data[i]);
	}
	printf("\n");
	for (int i = 14; i < 34; i++) {
		printf("%02x ", pkt_data[i]);
	}
	printf("\n");
	for (int i = 34; i < 54; i++) {
		printf("%02x ", pkt_data[i]);
	}
	printf("\n");
	for (int i = 54; i < pkt_hdr->caplen; i++) {
		printf("%02x ", pkt_data[i]);
	}
	printf("\n");
	
	readTCP(pkt_data+14);
	
	return 0;
}
