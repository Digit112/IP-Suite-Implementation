#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#include "my_inet_utils.h"

/* Connects to a passive TCP server at 127.0.0.1:127 and, once established, sends "Hello TCP!" */

int main() {
	int err;
	char errbuf[512];
	
	struct sockaddr_in cli = {AF_INET, htons(0xff91), inet_addr("127.0.0.2")};
	struct sockaddr_in srv = {AF_INET, htons(0xff19), inet_addr("127.0.0.3")};
	
	int sok = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sok == -1) perror("Failed to get socket file descriptor");
	
	err = bind(sok, (struct sockaddr*) &cli, sizeof(struct sockaddr_in));
	if (err != 0) perror("Failed to get socket file descriptor");
	
	// intercept packets
	pcap_t* pcap_handle = begin_cap("lo");
	
	err = connect(sok, (struct sockaddr*) &srv, sizeof(srv));
	if (err == -1) perror("Failed to connect socket");
	
	unsigned char* buf = malloc(1024);
	int buf_n = sprintf(buf, "Hello Tcp!");
	
	send(sok, buf, buf_n, 0);
	
	end_cap(pcap_handle, "full_cap.pcap");
	
	close(sok);
	
	free(buf);
	
	return 0;
}
