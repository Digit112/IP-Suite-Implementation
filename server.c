#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Starts a passive TCP server listening on 127.0.0.3:240 */

int main() {
	int err;
	
	struct sockaddr_in cli = {PF_INET, htons(19000), inet_addr("127.0.0.2")};
	struct sockaddr_in srv = {PF_INET, htons(18000), inet_addr("127.0.0.3")};
	
	int sok = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sok == -1) perror("Failed to get socket descriptor");
	
	err = bind(sok, (struct sockaddr*) &srv, sizeof(srv));
	if (err == -1) perror("Failed to bind socket");
	
	err = listen(sok, 1);
	if (err == -1) perror("Failed to listen");
	
	int scli = sizeof(struct sockaddr_in);
	int conn_sok = accept(sok, (struct sockaddr*) &cli, &scli);
	
	unsigned char* buff = malloc(1024);
	
	recv(conn_sok, buff, 1024, 0);
	
	printf("Recieved data over TCP/IP connected socket:\n%s\n", buff);
	
	free(buff);
	close(sok);
	
	return 0;
}
