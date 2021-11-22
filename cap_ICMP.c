#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "my_inet_utils.h"

/* Sends a raw IP datagram containing the message "Hello RAW IP!" to a recieving IP Module on 127.0.0.1 */

int main() {
	int err;
	char errbuf[512];
	// pcap stuff to find our local address
	uint32_t laddr;
	
	pcap_if_t* devs;
	
	err = pcap_findalldevs(&devs, errbuf);
	if (err != 0) printf("findalldevs returned nonzero: %s\n", errbuf);
	
	const char nic_n[] = "wlan0";
	int found_local_address = 0;
	for (pcap_if_t* dev = devs; dev != NULL; dev = dev->next) {
		int is_wlan0 = 1;
		
		printf("I see device %s\n", dev->name);
		
		for (int i = 0; i < 6; i++) {
			if (nic_n[i] != dev->name[i]) {
				is_wlan0 = 0;
				printf("Device is not wlan0!\n");
				break;
			}
		}
		
		if (is_wlan0) {
			printf("Found wlan0.\n");
			
			for (pcap_addr_t* laddrp = dev->addresses; laddrp != NULL; laddrp = laddrp->next) {
				printf("I see PF %d.\n", laddrp->addr->sa_family);
				if (laddrp->addr->sa_family == PF_INET) {
					printf("Found %d. Address is %08x\n", PF_INET, ((struct sockaddr_in*) laddrp)->sin_addr.s_addr);
					laddr = ((struct sockaddr_in*) laddrp)->sin_addr.s_addr;
					found_local_address = 1;
					break;
				}
			}
			
			break;
		}
	}
	
	pcap_freealldevs(devs);
	
	if (found_local_address) {
		printf("Local address from wlan0 is %08x.\n", ntohl(laddr));
	}
	else {
		printf("Could not extract local address from device wlan0. Device may not exist or may not be connected to a network.\n");
		return 0;
	}
	
	uint32_t cli_addr = inet_addr("192.168.1.25");
	uint32_t srv_addr = inet_addr("192.168.1.237"); // This device should not exist, prompting the router to send an ICMP packet in response.
	
	struct sockaddr_in cli = {AF_INET, 0, cli_addr};
	struct sockaddr_in srv = {AF_INET, 0, srv_addr};
	
	int sok = socket(PF_INET, SOCK_RAW, 4);
	if (sok == -1) perror("Failed to get socket descriptor");
	
	err = bind(sok, (struct sockaddr*) &cli, sizeof(cli));
	if (err == -1) perror("Failed to bind socket");
	
	// Specify that the header is manually included.
	int hdrincl = 1;
	err = setsockopt(sok, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl));
	if (sok == -1) perror("Failed to set hdrinclr");
	
	unsigned char* buf = malloc(128);
	gen_ipv4_hdr((struct ipv4_hdr*) buf, 0, 255, cli_addr, srv_addr); // Generate headers
	int buf_n = 20;
	
	pcap_t* pcap_handle = begin_cap("wlan0");
	
	err = sendto(sok, buf, buf_n, 0, (struct sockaddr*) &srv, sizeof(srv));
	if (sok == -1) perror("Failed to send");
	
	end_cap(pcap_handle, "icmp_cap.pcap");
	
	close(sok);
}
