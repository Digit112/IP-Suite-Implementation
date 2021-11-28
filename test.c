#include <stdio.h>
#include "tcp_ip_stack.h"

int main() {
	int err;
	int got_pkt = 0;
	
	pcap_t* pcap_handle = begin_cap("lo");
	
	struct tcp_stack stck;
	
	tcp_init(&stck, 10);
	
	int left = tcp_create_connection(&stck, "127.0.0.2", 19000, "127.0.0.3", 18000);
	if (left < 0) printf("Error creating left connection: %d\n", left);
	
	int rght = tcp_create_connection(&stck, "127.0.0.3", 18000, "127.0.0.2", 19000);
	if (rght < 0) printf("Error creating rght connection: %d\n", rght);
	
	// Set rght to listen
	stck.connections[rght]->state = MIU_TCPIP_LISTEN;
	
	// Send a SYN to the server
	printf("Left is attempting to connect.\n");
	err = tcp_connect(&stck, left);
	if (err != MIU_TCPIP_SUCCESS) printf("Error: %d\n", err);
	
	// Continuously handle the receive queue and the retransmission queue until a packet is received.
	printf("Right is waiting for a packet...\n");
	while (got_pkt == 0) {
		got_pkt = tcp_recv_packets(&stck, rght);
		tcp_check_retransmissions(&stck, rght);
	}
	got_pkt = 0;
	printf("Left is waiting for a packet...\n");
	while (got_pkt == 0) {
		got_pkt = tcp_recv_packets(&stck, left);
		tcp_check_retransmissions(&stck, left);
	}
	
	printf("Sending message...\n");
	// Send a small text message
	char buf[128];
	int buf_n = sprintf(buf, "Hello full TCP/IP Stack!");
//	tcp_send(&stck, left, buf, buf_n);
	
	printf("Disconnecting.\n");
	// Disconnect the connection.
	tcp_disconnect(&stck, left);
	tcp_disconnect(&stck, rght);
	
	end_cap(pcap_handle, "stack.pcap");
	
	// Frees the entire stack and all connections. Open connections are left half-open.
	tcp_delete_stack(&stck);
	
	return 0;
}
