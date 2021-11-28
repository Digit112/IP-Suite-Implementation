#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include <fcntl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "my_inet_utils.h"

// This file contains a full TCP/IP stack.

// The user of this header may initialize a "struct tcp_stack" with tcp_init(), open and close ports with tcp_set_port(),
// And send data with tcp_send_bytes()

// Constants used to specify how an incoming connection request will be handled.
#define MIU_TCPIP_ACCEPT 1
#define MIU_TCPIP_REFUSE 2
#define MIU_TCPIP_IGNORE 3

#define MIU_TCPIP_LISTEN 4 // This connection is not established but will connect to incoming SYNs.
#define MIU_TCPIP_CLOSED 5 // This connection is not established and we are not attempting to establish it.
#define MIU_TCPIP_FAILED_RST 6 // Same as closed, but set after a SYN is RST-ACK'd
#define MIU_TCPIP_FAILED_TMO 7 // Same as closed, but set after a SYN is not ACK'd, and times out.
#define MIU_TCPIP_DISCON_HOC 8 // Same as closed, but set after an established connection becomes half-open and is aborted.
#define MIU_TCPIP_DISCON_RST 9 // Same as closed, but set after an established connection is RST'd
#define MIU_TCPIP_DISCON_TMO 10 // Same as closed, but set after an established connection times out.
#define MIU_TCPIP_SYN_SENT 11 // We have sent a SYN and are waiting for either another SYN or a RST.
#define MIU_TCPIP_SYN_RECV 12 // We have recieved a SYN and are replying with a SYN-ACK or SYN-RST.
#define MIU_TCPIP_ESTABLISHED 13 // We have both sent and received a SYN and are ready to transmit and receive data.
#define MIU_TCPIP_FIN_SENT 14 // We have sent a FIN that the peer has ACK'd, we can recieve but not send data.
#define MIU_TCPIP_FIN_RECV 15 // We have ACK'd a FIN that the peer sent. We can send but not recieve data.
#define MIU_TCPIP_FIN_SNRC 16 // We have received an ACK for a FIN we sent and have ACK'd a FIN the peer set. We are waiting to ensure they have recieved our ACK.

// Timeout defaults
#define MIU_TCPIP_RETRANS_ATTEMPTS 2
#define MIU_TCPIP_RETRANS_TIMEOUT 3

// Error codes
#define MIU_TCPIP_SUCCESS 0
#define MIU_TCPIP_MAX_CONNECTIONS -1
#define MIU_TCPIP_INVALID_IPV4_ADDR -2
#define MIU_TCPIP_INSUFFICIENT_RESOURCES -3
#define MIU_TCPIP_CONNECTION_NOT_FOUND -4
#define MIU_TCPIP_CONNECTION_DOES_NOT_EXIST -5
#define MIU_TCPIP_CONNECTION_ALREADY_EXISTS -6
#define MIU_TCPIP_FAILED_TO_GET_SFD -7
#define MIU_TCPIP_FAILED_TO_BIND -8
#define MIU_TCPIP_FAILED_TO_SEND -9
#define MIU_TCPIP_FAILED_TO_RECV -10
#define MIU_TCPIP_INVALID_HEADER -11

// transmission control block used to keep track of a TCP connection.
struct tcp_tcb {
	// The socket file descriptor used by this connection
	int sok;
	
	// Completely identify the connection by these 4 values. Note that this TCP stack may maintain connections under different aliases.
	uint32_t peer_ipv4;
	uint32_t locl_ipv4;
	uint16_t peer_port;
	uint16_t locl_port;
	
	struct tcp_retrans_q* retrans; // The retransmission queue
	struct tcp_msg_q* msg; // The inbound message queue
	
	struct tcp_retrans_q* last_retrans; // The last item on the retransmission queue. Used to quickly append to the queue.
	struct tcp_msg_q* last_msg; // The last item on the retransmission queue. Used to quickly append to the queue.
	
	int state; // The state of the connection
	
	uint32_t SND_UNA; // send unacknowledged
	uint32_t SND_NXT; // send next
	uint32_t SND_WND; // send window
	uint32_t SND_WL1; // segment SEQ of last window
	uint32_t SND_WL2; // segment ACK of last window
	
	uint32_t ISS; // SEQ of first SYN packet sent.
	
	uint32_t RCV_NXT; // receive next
	uint16_t RCV_WND; // receive window
	
	// Tracks whether a fin has been sent (as opposed to whether it has been ACK'd) and what its SEQ number is.
	// When the outbound fin is ACK'd, state will move from ESTABLISHED to FIN_SENT or from FIN_RECV to FIN_SNRC.
	// Some time after entering FIN_SNRC, if the peer does not retransmit anything, state will change to CLOSED.
	// (FIN_SNRC is called TIME_WAIT by rfc 793)
	uint8_t locl_has_sent_fin;
	uint8_t locl_fin_SEQ;
	
	uint32_t IRS; // SEQ of first SYN packet recieved
};

// Retransmit queue for data that has been sent but not ACK'd. Each connection has its own queue.
// Implemented as a linked queue
struct tcp_retrans_q {
	struct tcp_retrans_q* next; // The next item on the queue.
	
	int retrans_attempts; // Number of times this packet has been retransmitted.
	
	// The packet and length of packet to transmit. Includes TCP/IP header.
	uint8_t* packet;
	unsigned int packet_n;
	
	// The sequence number of the last octet in this message. If SND_UNA > last_oc, this segment is fully acknowledged.
	uint32_t last_oc;
	
	time_t retransmit_time; // Time that, when reached, this message will be retransmitted if it is on the queue.
};

// Queue containing data recieved from packets. Each connection has its own queue.
struct tcp_msg_q {
	struct tcp_msg_q* next; // The next item on the queue.
	
	// The packet and length of packet. Includes TCP/IP header.
	uint8_t* packet;
	unsigned int packet_n;
	
	// Pointer to the data of the packet, and length of data. Access this if you don't care about the headers.
	uint8_t* data;
	unsigned int data_n;
};

// Queue containing inbound connection requests. To be accepted/refused on a case by case basis by the user.
// Peek at this queue with tcp_conn_peek() and pop it with tcp_conn_pop()
struct tcp_conn_q {
	struct tcp_conn_q* next; // The next item on the queue.
	
	// A transmission control block allocated and filled in for the connection. Examine this for information.
	struct tcp_tcb* tcb;
};

// Structure representing the TCP stack.
struct tcp_stack {
	// The pointer-to-pointer format is used so that the structs can be randomly accessed without having to be contiguous in memory.
	// Pointer to a list of pointers to TCBs. connections_n may not actually give the number of connections, because
	// tcp_delete_connection only sets its pointer in this list to NULL. The empty space created will be used by a future
	// tcp_create_connection call if it is necessary.
	struct tcp_tcb** connections;
	unsigned int connections_n;
	unsigned int max_connections_n;
	
	// Inbound connections queue. A queue entry is created for every SYN received on a non-existent connection.
	struct tcp_conn_q* connreqs;
	struct tcp_conn_q* last_connreq; // Most recent request.
};

// Function checks all connections and returns the index of the matching connection or MIU_TCPIP_CONNECTION_NOT_FOUND (-4) if it is not found.
int tcp_find_connection(struct tcp_stack* stck, const char* locl_ipv4, uint32_t locl_port) {
	if (stck->connections_n == 0) {
		return MIU_TCPIP_CONNECTION_NOT_FOUND;
	}
	
	// Get ip:port identifiers into network order
	uint32_t l_ip;
	uint16_t l_p = htons(locl_port);
	
	inet_aton(locl_ipv4, (struct in_addr*) &l_ip);
	
	// Iterate over connections.
	for (int i = 0; i < stck->connections_n; i++) {
		if (stck->connections[i] == NULL) {
			continue;
		}
		if (stck->connections[i]->locl_ipv4 == l_ip && stck->connections[i]->locl_port == l_p) {
			return i;
		}
	}
	
	return MIU_TCPIP_CONNECTION_NOT_FOUND;
}

// Initialize the TCPIP stack. This will assume it is being passed a brand-new stack and will not attempt
// to free memory being used by connetions on this stack.
void tcp_init(struct tcp_stack* stck, unsigned int max_connections_n) {
	stck->connections = malloc(sizeof(struct tcp_tcb*) * max_connections_n);
	stck->connections_n = 0;
	stck->max_connections_n = max_connections_n;
	
	stck->connreqs = NULL;
	stck->last_connreq = NULL;
}

// Create a connection and return its handle. This does NOT establish the connection, it ONLY creates the TCB!
// This function will utilize the first unused available handle.
// This function will check to ensure that the connection does not already exist.
// If the returned value is negative, it is an error code.
// The ip fields are IPv4 addresses in dot notation, they're passed to inet_aton().
// The ports are to be passed in host byte order.
int tcp_create_connection(struct tcp_stack* stck, const char* locl_ipv4, uint32_t locl_port, const char* peer_ipv4, uint32_t peer_port) {
	// Check that this connection doesn't already exist.
	if (tcp_find_connection(stck, locl_ipv4, locl_port) != MIU_TCPIP_CONNECTION_NOT_FOUND) {
		return MIU_TCPIP_CONNECTION_ALREADY_EXISTS;
	}
	
	struct tcp_tcb* new_tcb;
	
	int new_tcb_ind = -1;
	
	// Check for unused handles (deleted connections)
	for (int i = 0; i < stck->connections_n; i++) {
		if (stck->connections[i] == NULL) {
			new_tcb_ind = i;
			break;
		}
	}
	
	// If no unused spots exist, append this TCB to the end of the current list
	if (new_tcb_ind == -1) {
		// Check that space exists for this TCB's pointer.
		if (stck->connections_n == stck->max_connections_n) {
			return MIU_TCPIP_MAX_CONNECTIONS;
		}
		else {
			new_tcb_ind = stck->connections_n;
		}
	}
	
	// Allocate space for a new TCB.
	new_tcb = malloc(sizeof(struct tcp_tcb));
	if (new_tcb == NULL) {
		return MIU_TCPIP_INSUFFICIENT_RESOURCES;
	}
	
	// Set the local and peer addresses and ports
	if (inet_aton(locl_ipv4, (struct in_addr*) &(new_tcb->locl_ipv4)) == 0) {
		free(new_tcb);
		return MIU_TCPIP_INVALID_IPV4_ADDR;
	}
	if (inet_aton(peer_ipv4, (struct in_addr*) &(new_tcb->peer_ipv4)) == 0) {
		free(new_tcb);
		return MIU_TCPIP_INVALID_IPV4_ADDR;
	}
	new_tcb->locl_port = htons(locl_port);
	new_tcb->peer_port = htons(peer_port);
	
	// Create socket for this connection
	int sok = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sok == -1) return MIU_TCPIP_FAILED_TO_GET_SFD;
	
	new_tcb->sok = sok;
	
	// Bind
	int err = bind(sok, (struct sockaddr*) &(struct sockaddr_in){AF_INET, new_tcb->locl_port, {new_tcb->locl_ipv4}}, sizeof(struct sockaddr_in));
	if (err == -1) return MIU_TCPIP_FAILED_TO_BIND;
	
	// IP header will be included in the data buffer
	int hdrincl = 1;
	err = setsockopt(sok, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl));
	if (sok == -1) perror("Failed to set hdrincl");
	
	// Socket will be nonblocking
	err = fcntl(sok, F_SETFL, O_NONBLOCK);
	
	// Initialize the queues
	new_tcb->retrans = NULL;
	new_tcb->last_retrans = NULL;
	new_tcb->msg = NULL;
	new_tcb->last_msg = NULL;
	
	new_tcb->state = MIU_TCPIP_CLOSED;
	
	// Setup the actual TCB variables
	new_tcb->SND_UNA = 0;
	new_tcb->SND_NXT = 1;
	new_tcb->SND_WND = 0;
	new_tcb->SND_WL1 = 0;
	new_tcb->SND_WL2 = 0;
	
	new_tcb->ISS = 0;
	
	new_tcb->RCV_NXT = 0;
	new_tcb->RCV_WND = 0;
	
	new_tcb->IRS = 0;
	
	new_tcb->locl_has_sent_fin = 0;
	new_tcb->locl_fin_SEQ = 0;
	
	// Set the appropriate location in the stack's TCB list to point to this TCB.
	stck->connections[new_tcb_ind] = new_tcb;
	
	// If this TCB was added to the end of the list, increase the list size.
	if (new_tcb_ind == stck->connections_n) {
		stck->connections_n++;
	}
	
	return new_tcb_ind;
}

// Appends this packet to the retransmission queue. If the queue is empty, creates one.
// This function is called automatically to queue for retransmission packets sent with tcp_send() and tcp_send_raw().
int tcp_queue_pkt(struct tcp_stack* stck, int conn_id, uint8_t* buf, int buf_n, uint32_t last_oc) {
	struct tcp_tcb* conn = stck->connections[conn_id];
	
	// malloc space for a retransmission queue entry.
	struct tcp_retrans_q* pkt_rt_q = malloc(sizeof(struct tcp_retrans_q));
	if (pkt_rt_q == NULL) return MIU_TCPIP_INSUFFICIENT_RESOURCES;
	
	// malloc space for a copy of this packet and memcpy the packet into it.
	uint8_t* rbuf = malloc(buf_n);
	if (rbuf == NULL) return MIU_TCPIP_INSUFFICIENT_RESOURCES;
	
	memcpy(rbuf, buf, buf_n);
	
	pkt_rt_q->next = NULL;
	pkt_rt_q->retrans_attempts = 0;
	pkt_rt_q->packet = rbuf;
	pkt_rt_q->packet_n = buf_n;
	pkt_rt_q->last_oc = last_oc;
	pkt_rt_q->retransmit_time = time(NULL) + MIU_TCPIP_RETRANS_TIMEOUT;
	
	if (conn->last_retrans == NULL) {
		conn->retrans = pkt_rt_q;
		conn->last_retrans = conn->retrans;
	}
	else {
		conn->last_retrans->next = pkt_rt_q;
		conn->last_retrans = pkt_rt_q;
	}
	
	return MIU_TCPIP_SUCCESS;
}

// Sends buf. Function will send, copy the packet into the retransmission queue, update the TCB, and return.
// Data in buffer will be copied and can be modified or free'd after this function call, and must include TCP/IP headers.
int tcp_send_raw(struct tcp_stack* stck, int conn_id, uint8_t* buf, int buf_n, int is_retransmission) {
	int err;
	
	struct tcp_tcb* conn = stck->connections[conn_id];
	
	if (conn == NULL) return MIU_TCPIP_CONNECTION_DOES_NOT_EXIST;
	if (!validate_TCPIP_hdr(buf, 0)) return MIU_TCPIP_INVALID_HEADER;
	
	err = sendto(conn->sok, buf, buf_n, 0, (struct sockaddr*) &(struct sockaddr_in){AF_INET, conn->peer_port, {conn->peer_ipv4}}, sizeof(struct sockaddr_in));
	if (err == -1) return MIU_TCPIP_FAILED_TO_SEND;
	
	struct tcp_hdr* tcp_head = (struct tcp_hdr*) (buf + (((struct ipv4_hdr*) buf)->version__IHL & 0x0F) * 4);
	
	int seq_size = buf_n - 40;
	if (seq_size == 0 && tcp_head->flags & ~(MIU_TCP_ACK | MIU_TCP_RST)) {
		seq_size = 1;
	}
	
	if (seq_size > 0) {
		err = tcp_queue_pkt(stck, conn_id, buf, buf_n, conn->SND_NXT);
		if (err != MIU_TCPIP_SUCCESS) return err;
	}
	
	if (!is_retransmission) {
		conn->SND_NXT += seq_size;
	}
	
	return MIU_TCPIP_SUCCESS;
}

// Sends a RST packet. RST's do not enter a queue for retransmission as they are not ACK'd.
// If do_ack is true, the outbound packet will contain the passed ACK value.
// The outbound packet will contain the passed seq value. Values are expected in host byte order.
// The seq and ack values should be set based on the nature of the packet which the RST is replying to. 
int tcp_send_rst(struct tcp_stack* stck, int conn_id, struct ipv4_hdr* ipv4_head) {
	struct tcp_tcb* conn = stck->connections[conn_id];
	
	struct tcp_hdr* tcp_head = (struct tcp_hdr*) ((uint8_t*) ipv4_head + (ipv4_head->version__IHL & 0x0F) * 4);
	
	uint8_t* data = (uint8_t*) tcp_head + ((tcp_head->data_offset__reserved__NS & 0xF0) >> 4) * 4;
	int data_len = ipv4_head->total_length - (data - (uint8_t*) (ipv4_head));
	
	uint32_t ack;
	uint32_t seq;
	
	uint8_t flags = MIU_TCP_RST;
	if (!(tcp_head->flags & MIU_TCP_ACK)) {
		seq = 0;
		flags |= MIU_TCP_ACK;
		ack = ntohl(tcp_head->sequence_number) + data_len;
	}
	else {
		ack = 0;
		seq = ntohl(tcp_head->acknowledgement_number);
	}
	
	uint8_t* buf = malloc(40);
	
	gen_ipv4_hdr((struct ipv4_hdr*) buf, 20, IPPROTO_TCP, conn->locl_ipv4, conn->peer_ipv4);
	gen_tcp_hdr((struct tcp_hdr*) (buf+20), ntohs(conn->locl_port), ntohs(conn->peer_port), flags, seq, ack, 512, conn->locl_ipv4, conn->peer_ipv4, 0, NULL);
	
	// Send RST
	int err = sendto(conn->sok, buf, 40, 0, (struct sockaddr*) &(struct sockaddr_in){AF_INET, conn->peer_port, {conn->peer_ipv4}}, sizeof(struct sockaddr_in));
	if (err == -1) return MIU_TCPIP_FAILED_TO_SEND;
	
	free(buf);
}

// Creates TCP/IP headers based on this connection and prefixes them to the passed buffer, then sends the packet.
int tcp_send(struct tcp_stack* stck, int conn_id, uint8_t* buf, int buf_n) {
	struct tcp_tcb* conn = stck->connections[conn_id];
	
	uint8_t* pkt_buf = malloc(40 + buf_n);
	memcpy(pkt_buf+40, buf, buf_n);
	
	// Prefix headers
	gen_ipv4_hdr((struct ipv4_hdr*) pkt_buf, 20 + buf_n, IPPROTO_TCP, conn->locl_ipv4, conn->peer_ipv4);
	gen_tcp_hdr((struct tcp_hdr*) (pkt_buf+20), ntohs(conn->locl_port), ntohs(conn->peer_port), MIU_TCP_ACK, conn->SND_NXT, conn->RCV_NXT, 512, conn->locl_ipv4, conn->peer_ipv4, buf_n, buf);
	
	// Send & put on the retransmission queue.
	int err = tcp_send_raw(stck, conn_id, pkt_buf, 40+buf_n, 0);
	if (err != MIU_TCPIP_SUCCESS) return MIU_TCPIP_FAILED_TO_SEND;
	
	free(pkt_buf);
	
	return MIU_TCPIP_SUCCESS;
}

// Sends a SYN packet to the peer specified when the specified connection was created, set connection state to SYN_SENT
// User is expected to call tcp_recv_packets() on this connection, which will grab data in the receive queue and acknowledge the reply.
int tcp_connect(struct tcp_stack* stck, int conn_id) {
	int err;
	
	// Check that this connection exists
	if (conn_id >= stck->max_connections_n | stck->connections[conn_id] == NULL) {
		return MIU_TCPIP_CONNECTION_DOES_NOT_EXIST;
	}
	
	struct tcp_tcb* conn = stck->connections[conn_id];
	
	// Create a buffer to send data from and put a SYN packet in it.
	uint8_t buf[40];
	if (buf == NULL) return MIU_TCPIP_INSUFFICIENT_RESOURCES;
	
	gen_ipv4_hdr((struct ipv4_hdr*) buf, 20, IPPROTO_TCP, conn->locl_ipv4, conn->peer_ipv4);
	gen_tcp_hdr((struct tcp_hdr*) (buf+20), ntohs(conn->locl_port), ntohs(conn->peer_port), MIU_TCP_SYN, conn->SND_NXT, 0, 512, conn->locl_ipv4, conn->peer_ipv4, 0, NULL);
	
	// Send SYN
	printf("Sending SYN.\n");
	err = tcp_send_raw(stck, conn_id, buf, 40, 0);
	if (err != MIU_TCPIP_SUCCESS) return err;
	
	conn->state = MIU_TCPIP_SYN_SENT;
	
	return MIU_TCPIP_SUCCESS;
}

// Resets a connection completely. Clears the retransmission queue and message queue, and resets TCB.
// Called when a valid RST packet is received.
int tcp_reset_connection(struct tcp_stack* stck, int conn_id) {
	struct tcp_tcb* conn = stck->connections[conn_id];
	
	// Free the retransmission queue
	while (conn->retrans != NULL) {
		struct tcp_retrans_q* first_retrans_q = conn->retrans;
		
		conn->retrans = conn->retrans->next;
		
		free(first_retrans_q->packet);
		free(first_retrans_q);
	}
	
	// Free the message queue
	while (conn->msg != NULL) {
		struct tcp_msg_q* first_msg_q = conn->msg;
		
		conn->msg = conn->msg->next;
		
		free(first_msg_q->packet);
		free(first_msg_q);
	}
	
	// Initialize the queues
	conn->retrans = NULL;
	conn->last_retrans = NULL;
	conn->msg = NULL;
	conn->last_msg = NULL;
	
	conn->state = MIU_TCPIP_CLOSED;
	
	// Setup the actual TCB variables
	conn->SND_UNA = 0;
	conn->SND_NXT = 1;
	conn->SND_WND = 0;
	conn->SND_WL1 = 0;
	conn->SND_WL2 = 0;
	
	conn->ISS = 0;
	
	conn->RCV_NXT = 0;
	conn->RCV_WND = 0;
	
	conn->IRS = 0;
	
	conn->locl_has_sent_fin = 0;
	conn->locl_fin_SEQ = 0;
}

// Retreives all packets from the receive buffer on this connection and handles them in turn.
// Discards TCP packets that do not carry data (after handling them). Data-carrying packets are put on the inbound message queue.
// If closed, inbound SYNs get put on the connection request queue.
int tcp_recv_packets(struct tcp_stack* stck, int conn_id) {
	int err;
	
	struct tcp_tcb* conn = stck->connections[conn_id];
	
	uint8_t* buf = malloc(4096);
	
	struct sockaddr_in from = {AF_INET, conn->peer_port, {conn->peer_ipv4}};
	int from_size = sizeof(struct sockaddr_in);
	
	int num_packets = 0;
	while (1) {
		// Turns out, calling this function on a loop freezes the OS!
		// Delay for ~10ms.
		float st = (float) clock() / CLOCKS_PER_SEC;
		while ((float) clock() / CLOCKS_PER_SEC - st < 0.01) {}
	
		err = recvfrom(conn->sok, buf, 4096, 0, (struct sockaddr*) &from, &from_size);
		if (err == -1) {
			free(buf);
			return num_packets;
		}
		
		num_packets++;
	
		int buf_n = err;
	
		struct ipv4_hdr* ipv4_head = (struct ipv4_hdr*) buf;
		int ipv4_head_len = (ipv4_head->version__IHL & 0x0F) * 4;
		
		struct tcp_hdr* tcp_head = (struct tcp_hdr*) (buf + ipv4_head_len);
		int tcp_head_len = ((tcp_head->data_offset__reserved__NS & 0xF0) >> 4) * 4;
	
		uint8_t* data = tcp_head_len + (uint8_t*) tcp_head;
		
		int data_len = ntohs(ipv4_head->total_length) - ipv4_head_len - tcp_head_len;
	
		printf("Got packet from %08x:%d, layout %ld,%ld,%ld,%ld.\n", ntohl(from.sin_addr.s_addr), ntohs(from.sin_port), (uint8_t*) ipv4_head-buf, (uint8_t*) tcp_head-buf, data-buf, (data-buf)+data_len);
	
		// Process packet
		// First, check if this connection is closed.
		if (conn->state >= MIU_TCPIP_CLOSED && conn->state <= MIU_TCPIP_DISCON_TMO) {
			printf("We're closed!\n");
			// If this is a RST packet, ignore it
			if (tcp_head->flags & MIU_TCP_RST) {
				printf("Packet is RST, ignore.\n");
				continue;
			}
			// Any other packet is responded to with a RST that we will not expect an ACK for.
			else {
				printf("RST'ing connection.\n");
				tcp_send_rst(stck, conn_id, ipv4_head);
			}
		}
		// Check if we're in LISTEN.
		else if (conn->state == MIU_TCPIP_LISTEN) {
			printf("We're establishing connections from inbound SYNs\n");
			// Check for RST flag.
			if (tcp_head->flags & MIU_TCP_RST) {
				printf("Packet has RST set, ignore.\n");
				continue;
			}
			// Check the ACK flag.
			if (tcp_head->flags & MIU_TCP_ACK) {
				printf("Packet has ACK set, reseting peer.\n");
				tcp_send_rst(stck, conn_id, ipv4_head);
			}
			// Check the SYN flag
			if (tcp_head->flags & MIU_TCP_SYN) {
				// Initiate connection
				conn->RCV_NXT = ntohl(tcp_head->sequence_number) + 1;
				conn->IRS = ntohl(tcp_head->sequence_number);
				
				// Create and send SYN-ACK
				uint8_t buf[40];
				gen_ipv4_hdr((struct ipv4_hdr*) buf, 20, IPPROTO_TCP, conn->locl_ipv4, conn->peer_ipv4);
				gen_tcp_hdr((struct tcp_hdr*) (buf+20), ntohs(conn->locl_port), ntohs(conn->peer_port), MIU_TCP_SYN | MIU_TCP_ACK, conn->ISS, conn->RCV_NXT, 512, conn->locl_ipv4, conn->peer_ipv4, 0, NULL);
				
				tcp_send_raw(stck, conn_id, buf, 40, 0);
			}
		}
		// Check if we're in SYN_SENT.
		else if (conn->state == MIU_TCPIP_SYN_SENT) {
			printf("We're expecting a reply to a SYN.\n");
			// If this packet ACK's our SYN
			if (tcp_head->flags & MIU_TCP_ACK) {
				// Check that the ACK is good.
				if (ntohl(tcp_head->acknowledgement_number) <= conn->ISS || ntohl(tcp_head->acknowledgement_number) > conn->SND_NXT) {
					printf("Acknowledgement is bad.\n");
					if (tcp_head->flags & MIU_TCP_RST) {
						printf("packet is RST, ignore.\n");
						continue;
					}
					else {
						printf("RST'ing connection.\n");
						tcp_send_rst(stck, conn_id, ipv4_head);
						continue;
					}
				}
				// If the ACK is good
				else {
					printf("Acknowledgement is good.\n");
					
					// Check if the connection is reset
					if (tcp_head->flags & MIU_TCP_RST) {
						printf("Error: Connection reset.\n");
						tcp_reset_connection(stck, conn_id);
						continue;
					}
					
					// Set TCB to reflect the ACK.
					conn->SND_UNA = ntohl(tcp_head->acknowledgement_number);
				}
			}
			// At this point, the packet either contains a good ACK or no ACK at all.
			// Check if this is a SYN.
			if (tcp_head->flags & MIU_TCP_SYN) {
				// Update the TCB based on this SYN
				conn->IRS = ntohl(tcp_head->sequence_number);
				conn->RCV_NXT = ntohl(tcp_head->sequence_number) + 1;
				conn->RCV_WND = ntohs(tcp_head->window_size);
				
				// Check if we have also received an ACK. If so, connection is established.
				if (tcp_head->flags & MIU_TCP_ACK) {
					conn->state = MIU_TCPIP_ESTABLISHED;
					
					// ACK this SYN.
					uint8_t buf[40];
					gen_ipv4_hdr((struct ipv4_hdr*) buf, 20, IPPROTO_TCP, conn->locl_ipv4, conn->peer_ipv4);
					gen_tcp_hdr((struct tcp_hdr*) (buf+20), ntohs(conn->locl_port), ntohs(conn->peer_port), MIU_TCP_ACK, conn->SND_NXT, conn->RCV_NXT, 512, conn->locl_ipv4, conn->peer_ipv4, 0, NULL);
					
					printf("ACK'ing SYN-ACK.\n");
					tcp_send_raw(stck, conn_id, buf, 40, 0);
					continue;
				}
				// Otherwise, initiate simultaneous connection
				else {
					conn->state = MIU_TCPIP_SYN_RECV;
					
					// Send SYN-ACK
					uint8_t buf[40];
					gen_ipv4_hdr((struct ipv4_hdr*) buf, 20, IPPROTO_TCP, conn->locl_ipv4, conn->peer_ipv4);
					gen_tcp_hdr((struct tcp_hdr*) (buf+20), htons(conn->locl_port), htons(conn->peer_port), MIU_TCP_SYN | MIU_TCP_ACK, conn->ISS, conn->RCV_NXT, 512, conn->locl_ipv4, conn->peer_ipv4, 0, NULL);
					
					printf("Sending Simu. SYN-ACK.\n");
					tcp_send_raw(stck, conn_id, buf, 40, 0);
					continue;
				}
			}
		}
	}
}

// Repeatedly checks the first item on the retransmission queue. If it has been ACK'd, remove it.
// If its retransmission time has passed, and its max retransmission attempts has not been reached, retransmit it
// and move it to the back of the queue.
// If its retransmission time has been reached and its max attempts has been reached, assume the connection has been partitioned and reset.
// This function returns when no items are left on the retransmission queue for which action is required.
void tcp_check_retransmissions(struct tcp_stack* stck, int conn_id) {
	struct tcp_tcb* conn = stck->connections[conn_id];
	
	while (1) {
		if (conn->retrans == NULL) {
			return;
		}
		
		// Check if the packet is fully acknowledged
		if (conn->SND_UNA > conn->retrans->last_oc) {
			free(conn->retrans->packet);
			struct tcp_retrans_q* temp = conn->retrans->next;
			free(conn->retrans);
			conn->retrans = temp;
			
			continue;
		}
		
		// Check if the retransmit time is exceeded.
		if (time(NULL) > conn->retrans->retransmit_time) {
			// Check if the retransmit attempts have been exceeded
			if (conn->retrans->retrans_attempts == MIU_TCPIP_RETRANS_ATTEMPTS) {
				tcp_reset_connection(stck, conn_id);
				conn->state = MIU_TCPIP_DISCON_TMO;
				return;
			}
			
			// Otherwise, retransmit this packet and queue it for retransmission.
			tcp_send_raw(stck, conn_id, conn->retrans->packet, conn->retrans->packet_n, 1);
			
			// send_raw will have queued the packet. Now we just set its attempts and delete this packet
			conn->last_retrans->retrans_attempts = conn->retrans->retrans_attempts + 1;
			conn->last_retrans->last_oc = conn->retrans->last_oc;
			
			free(conn->retrans->packet);
			struct tcp_retrans_q* temp = conn->retrans->next;
			free(conn->retrans);
			conn->retrans = temp;
			
			continue;
		}
		
		// The next retransmission queue item requires no action, return.
		return;
	}
}

// Sends a FIN packet, and sets the TCB fin-tracking variables.
// When the FIN is ACK'd, move from ESTABLISHED to FIN_SENT or from FIN_RECV to FIN_SNRC
int tcp_disconnect(struct tcp_stack* stck, int conn_id) {
	int err;
	
	struct tcp_tcb* conn = stck->connections[conn_id];
	
	// Create a buffer to send data from and put a FIN packet in it.
	uint8_t buf[40];
	
	gen_ipv4_hdr((struct ipv4_hdr*) buf, 20, IPPROTO_TCP, conn->locl_ipv4, conn->peer_ipv4);
	gen_tcp_hdr((struct tcp_hdr*) (buf+20), ntohs(conn->locl_port), ntohs(conn->peer_port), MIU_TCP_FIN | MIU_TCP_ACK, conn->SND_NXT, conn->RCV_NXT, 512, conn->locl_ipv4, conn->peer_ipv4, 0, NULL);
	
	conn->locl_has_sent_fin = 1;
	conn->locl_fin_SEQ = conn->SND_NXT;
	
	// Send FIN
	printf("Sending FIN.\n");
	err = tcp_send_raw(stck, conn_id, buf, 40, 0);
	if (err != MIU_TCPIP_SUCCESS) return err;
}
	

// Deletes a connection. Frees all malloc'd memory that may be used by the retransmission or msg queues, and frees the TCB.
// This will not gracefully close the connection if it is open. The connection should be closed separately via tcp_disconnect().
int tcp_delete_connection(struct tcp_stack* stck, int conn_id) {
	struct tcp_tcb* conn = stck->connections[conn_id];
	
	// Free the retransmission queue
	while (conn->retrans != NULL) {
		struct tcp_retrans_q* first_retrans_q = conn->retrans;
		
		conn->retrans = conn->retrans->next;
		
		free(first_retrans_q->packet);
		free(first_retrans_q);
	}
	
	// Free the message queue
	while (conn->msg != NULL) {
		struct tcp_msg_q* first_msg_q = conn->msg;
		
		conn->msg = conn->msg->next;
		
		free(first_msg_q->packet);
		free(first_msg_q);
	}
	
	free(conn);
	
	stck->connections[conn_id] = NULL;
	
	return MIU_TCPIP_SUCCESS;
}

// Deletes a TCP/IP stack and all extant connections.
// Open connections will not be closed gracefully.
int tcp_delete_stack(struct tcp_stack* stck) {
	for (int i = 0; i < stck->connections_n; i++) {
		if (stck->connections[i] != NULL) {
			tcp_delete_connection(stck, i);
		}
	}
	
	free(stck->connections);
	
	return MIU_TCPIP_SUCCESS;
}




