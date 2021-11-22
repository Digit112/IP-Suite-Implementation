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
	
	uint32_t cli_addr = inet_addr("127.0.0.2");
	uint32_t srv_addr = inet_addr("127.0.0.3");
	
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
	int buf_n = sprintf(buf+20, "Hello Raw IP!") + 1; // paste text into buffer
	gen_ipv4_hdr((struct ipv4_hdr*) buf, buf_n, 4, cli_addr, srv_addr); // Generate header
	buf_n += 20;
	printf("Sending %d bytes... (IP header + text...)\n", buf_n);
	
	err = sendto(sok, buf, buf_n, 0, (struct sockaddr*) &srv, sizeof(srv));
	if (sok == -1) perror("Failed to send");
	
	close(sok);
}
