#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Waits for an IP datagram addressed to 127.0.0.1 and extracts the data. */

int main() {
	int err;
	
	struct sockaddr_in to = {PF_INET, 0, inet_addr("127.0.0.3")};
	
	int sok = socket(PF_INET, SOCK_RAW, 4);
	if (sok == -1) perror("Failed to get socket descriptor");
	
	err = bind(sok, (struct sockaddr*) &to, sizeof(to));
	if (err == -1) perror("Failed to bind socket");
	
	unsigned char* buf = malloc(1024);
	sprintf(buf, "Overwrite me!\n");
	
	err = recv(sok, buf, 1024, 0);
	if (sok == -1) perror("Failed to recieve");
	
	// Get start of data offset by extracting header length.
	int data = (buf[0] & 0x0F) * 4;
	
	printf("%d\n", data);
	
//	printf("Recieved data over RAW IP connected socket:\n%s\n", buf+data);
	
	printf("Data was sent: %08x -> %08x\n", ((unsigned int*) buf)[3], ((unsigned int*) buf)[4]);
	
	printf("msg: %s\n", buf + data);
	
	for (int i = 0; i < 40; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n");
	
	close(sok);
	
	free(buf);
	return 0;
}
