#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <pcap/pcap.h> // This header will have to be installed

// Begin libpcap capture. Returns handle used to finish the capture.
pcap_t* begin_cap(const char* NIC) {
	int err;
	char errbuf[512];
	
	// pcap stuff to intercept the packet
	pcap_t* pcap_handle;
	pcap_handle = pcap_create(NIC, errbuf);
	if (pcap_handle == NULL) {
		printf("Could not create pcap handle: %s\n", errbuf);
	}
	
	err = pcap_activate(pcap_handle);
	if (err != 0) {
		printf("pcap_activate returned non-zero: %d\n", err);
	}
	
	// pcap_next will return NULL if a captured packet is not immediately available
	pcap_setnonblock(pcap_handle, 1, errbuf);
	
	return pcap_handle;
}

// End libpcap capture and save the results as a pcap file.
void end_cap(pcap_t* pcap_handle, const char* fn) {
	// Wait a brief time for packets to settle in the buffer.
	float st = (float) clock() / CLOCKS_PER_SEC;
	while ((float) clock() / CLOCKS_PER_SEC - 0.2 < st) {}
	
	struct pcap_pkthdr* pkt_hdr = malloc(sizeof(struct pcap_pkthdr));
	const uint8_t* pkt_data = NULL;
	
	pcap_dumper_t* pcap_fout = pcap_dump_open(pcap_handle, fn);
	while (1) {
		pkt_data = pcap_next(pcap_handle, pkt_hdr);
		
		if (pkt_data == NULL) {
			break;
		}
		else {
			printf("Packet returned, captured %d bytes.\n", pkt_hdr->caplen);
			pcap_dump((u_char*) pcap_fout, pkt_hdr, pkt_data);
		}
	}
	
	pcap_dump_close(pcap_fout);
	pcap_close(pcap_handle);
	
	free(pkt_hdr);
}
