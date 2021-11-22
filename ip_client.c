#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#include "my_inet_utils.h"

/* Attempts to form a TCP connection with a server on 127.0.0.1:127 by sending individual, manually formatted IP datagrams */

int main() {
	int err;
	char errbuf[512];
	
	uint32_t cli_addr = inet_addr("127.0.0.2");
	uint32_t srv_addr = inet_addr("127.0.0.3");
	
	struct sockaddr_in cli = {PF_INET, 0, cli_addr}; // Client (me)
	struct sockaddr_in srv = {PF_INET, 0, srv_addr}; // Server
	
	// Get RAW IP socket
	int sok = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sok == -1) perror("Failed to get socket descriptor");
	
	// Bind
	err = bind(sok, (struct sockaddr*) &cli, sizeof(cli));
	if (err == -1) perror("Failed to bind socket");
	
	// Tell IP module that the IP header will be included in the data buffer
	int hdrincl = 1;
	err = setsockopt(sok, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl));
	if (sok == -1) perror("Failed to set hdrincl");
	
	// Create the TCP/IP header
	unsigned char* buf = malloc(1024);
	
	struct tcp_hdr* tcp_head = (struct tcp_hdr*) (buf+20);
	struct ipv4_hdr* ipv4_head = (struct ipv4_hdr*) buf;
	
	gen_tcp_hdr(tcp_head, 0xff91, 0xff19, MIU_TCP_SYN, 1, 0, 4096, cli_addr, srv_addr, 0, NULL);
	gen_ipv4_hdr(ipv4_head, 20, IPPROTO_TCP, cli_addr, srv_addr);
	
	printf("Validating outbound SYN... ");
	if (validate_TCPIP_hdr(buf)) printf("Outbound SYN looks good.\n");
	
	pcap_t* pcap_handle = begin_cap("lo");
	
	// Send homemade SYN packet
	err = sendto(sok, buf, 40, 0, (struct sockaddr*) &srv, sizeof(srv));
	if (err == -1) perror("Failed to send");
	
	// Receive SYN, ACK
	int ssrv = sizeof(srv);
	err = recvfrom(sok, buf, 1024, 0, (struct sockaddr*) &srv, &ssrv);
	if (err == -1) perror("Failed to recieve");
	
	printf("Validating inbound packet... ");
	if (validate_TCPIP_hdr(buf)) printf("Inbound packet looks good.\n");
	
	tcp_head = (struct tcp_hdr*) (buf + (ipv4_head->version__IHL & 0x0F) * 4);
	
	if (tcp_head->flags == (MIU_TCP_SYN | MIU_TCP_ACK)) {
		printf("Inbound packet is SYN-ACK.\n");
		if (ntohl(tcp_head->acknowledgement_number) == 2) {
			printf("Acknowledgement good. Connection accepted.\n");
		}
	}
	
	// Send ACK
	uint32_t seq_of_srv_syn = ntohl(tcp_head->sequence_number);
	gen_tcp_hdr(tcp_head, 0xff91, 0xff19, MIU_TCP_ACK, 2, seq_of_srv_syn+1, 4096, cli_addr, srv_addr, 0, NULL);
	gen_ipv4_hdr(ipv4_head, 20, IPPROTO_TCP, cli_addr, srv_addr);
	
	printf("Validating outbound ACK... ");
	if (validate_TCPIP_hdr(buf)) printf("Outbound ACK looks good.\n");
	
	err = sendto(sok, buf, 40, 0, (struct sockaddr*) &srv, sizeof(srv));
	if (err == -1) perror("Failed to send");
	
	printf("ACK sent, connection established.\n");
	
	// Send data
	int text_len = sprintf(buf+40, "Hello RAW TCP/IP!");
	gen_tcp_hdr(tcp_head, 0xff91, 0xff19, MIU_TCP_ACK, 2, seq_of_srv_syn+1, 4096, cli_addr, srv_addr, text_len, buf+40);
	gen_ipv4_hdr(ipv4_head, 20 + text_len, IPPROTO_TCP, cli_addr, srv_addr);
	
	printf("Validating outbound payload... ");
	if (validate_TCPIP_hdr(buf)) printf("Outbound payload looks good.\n");
	
	err = sendto(sok, buf, 40 + text_len, 0, (struct sockaddr*) &srv, sizeof(srv));
	if (err == -1) perror("Failed to send");
	
	// Receive data ACK
	ssrv = sizeof(srv);
	err = recvfrom(sok, buf, 1024, 0, (struct sockaddr*) &srv, &ssrv);
	if (err == -1) perror("Failed to recieve");
	
	printf("Validating inbound packet... ");
	if (validate_TCPIP_hdr(buf)) printf("Inbound packet looks good.\n");
	
	tcp_head = (struct tcp_hdr*) (buf + (ipv4_head->version__IHL & 0x0F) * 4);
	
	if (tcp_head->flags == MIU_TCP_ACK) {
		printf("Inbound packet is ACK\n");
		if (ntohl(tcp_head->acknowledgement_number) == 2+text_len) {
			printf("Acknowledgement good. Data Received.\n");
		}
	}
	
	// Receive FIN
	ssrv = sizeof(srv);
	err = recvfrom(sok, buf, 1024, 0, (struct sockaddr*) &srv, &ssrv);
	if (err == -1) perror("Failed to recieve");
	
	printf("Validating inbound packet... ");
	if (validate_TCPIP_hdr(buf)) printf("Inbound packet looks good.\n");
	
	tcp_head = (struct tcp_hdr*) (buf + (ipv4_head->version__IHL & 0x0F) * 4);
	
	if (tcp_head->flags == MIU_TCP_ACK | MIU_TCP_FIN) {
		printf("Inbound data reply is FIN-ACK. Server has no data to send.\n");
		if (ntohl(tcp_head->acknowledgement_number) == 2+text_len) {
			printf("Acknowledgement good.\n");
		}
	}
	
	// Send FIN-ACK
	uint32_t seq_of_srv_fin = ntohl(tcp_head->sequence_number);
	gen_tcp_hdr(tcp_head, 0xff91, 0xff19, MIU_TCP_ACK | MIU_TCP_FIN, 2+text_len, seq_of_srv_fin+1, 4096, cli_addr, srv_addr, 0, NULL);
	gen_ipv4_hdr(ipv4_head, 20, IPPROTO_TCP, cli_addr, srv_addr);
	
	printf("Validating outbound FIN-ACK... ");
	if (validate_TCPIP_hdr(buf)) printf("Outbound FIN-ACK looks good.\n");
	
	err = sendto(sok, buf, 40, 0, (struct sockaddr*) &srv, sizeof(srv));
	if (err == -1) perror("Failed to send");
	
	printf("FIN-ACK sent, connection closed.\n");
	
	// Receive data ACK
	ssrv = sizeof(srv);
	err = recvfrom(sok, buf, 1024, 0, (struct sockaddr*) &srv, &ssrv);
	if (err == -1) perror("Failed to recieve");
	
	printf("Validating inbound packet... ");
	if (validate_TCPIP_hdr(buf)) printf("Inbound packet looks good.\n");
	
	tcp_head = (struct tcp_hdr*) (buf + (ipv4_head->version__IHL & 0x0F) * 4);
	
	if (tcp_head->flags == MIU_TCP_ACK) {
		printf("Inbound packet is ACK\n");
		if (ntohl(tcp_head->acknowledgement_number) == 3+text_len) {
			printf("Acknowledgement good. Connection Closed.\n");
		}
	}
	
	end_cap(pcap_handle, "out.pcap");
	
	free(buf);
	
	close(sok);
	
	return 0;
}
