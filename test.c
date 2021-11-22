#include <stdio.h>
#include "tcp_ip_stack.h"

int main() {
	int err;
	int got_pkt = 0;
	
	pcap_t* pcap_handle = begin_cap("lo");
	
	struct tcp_stack stck;
	
	tcp_init(&stck, 10);
	
	int conn = tcp_create_connection(&stck, "127.0.0.2", 19000, "127.0.0.3", 18000);
	if (conn < 0) printf("Error creating connection: %d\n", conn);
	
	// Send a SYN to the server
	err = tcp_connect(&stck, conn);
	if (err != MIU_TCPIP_SUCCESS) printf("Error: %d\n", err);
	
	// Continuously handle the receive queue and the retransmission queue until a packet is received.
	while (got_pkt == 0) {
		got_pkt = tcp_recv_packets(&stck, conn);
		tcp_check_retransmissions(&stck, conn);
	}
	
	// Send a small text message
	char buf[128];
	int buf_n = sprintf(buf, "Hello full TCP/IP Stack!");
	tcp_send(&stck, conn, buf, buf_n);
	
	// Continuously handle the receive queue and the retransmission queue until a packet is received.
	while (got_pkt == 0) {
		got_pkt = tcp_recv_packets(&stck, conn);
		tcp_check_retransmissions(&stck, conn);
	}
	
	// Disconnect the connection.
	tcp_disconnect(&stck, conn);
	
	end_cap(pcap_handle, "stack.pcap");
	
	// Frees the entire stack and all connections. Open connections are left half-open.
	tcp_delete_stack(&stck);
	
	return 0;
}
