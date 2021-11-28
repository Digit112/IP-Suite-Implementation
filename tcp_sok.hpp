#ifndef MIU_TCP_SOK
#define MIU_TCP_SOK

/*
	This file defines the tcp_sok class, which provides functions that abstract the user from the complexities of the TCP/IP protocols.
	Each instance of the class represents a connection from a particular address:port, to a particular address:port.
	Of course, either address may be 0.0.0.0 (INADDR_ANY)
	
	All functions are non-blocking. The connect() and disconnect() functions send a SYN and FIN packet, respectively,
	and return without checking for a reply.
	
	Calling receive() will process any incoming packets and should be called regularly.
	receive() will also transfer any incoming data to the receiving queue.
	
	retransmit() should also be called regularly, it will remove any packets queued for retransmission which have
	been acknowledged and retransmit any that have expired without being acknowledged.
	
	After calling connect() or listen(), one should call receive() and retransmit() repeatedly
	until the state changes to ESTABLISHED or some variant of CLOSED (take a look at the tcp_state enum).
	
	Expects & returns ALL values in network order! This library will NEVER adjust the byte order of anything!
*/

#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include "miu_errors.h"
#include "IPv4.hpp"
#include "TCP.hpp"
#include "TCP_IPv4.hpp"

#define MIU_TCP_MAX_SEG_SIZE 4216 // 4096 + 120

#define MIU_TCP_RCV_WND 4096

#define MIU_TCP_SND_BUF_N 65536
#define MIU_TCP_RCV_BUF_N 65536

namespace miu {
	class tcp_sok;
	
	class tcp_sok {
	public:
		enum tcp_state {LISTEN, SYN_SENT, SYN_RECV, ESTABLISHED, FIN_SENT, FIN_RECV, FIN_SNRC, CLOSED};
		
		// Socket, addresses, and ports.
		int sok;
		
		uint32_t locl_addr;
		uint16_t locl_port;
		
		uint32_t peer_addr;
		uint16_t peer_port;
	
//	private:
		// These buffers contain raw data without TCP/IP headers. They are effectively byte queues where data wraps around.
		uint8_t* send_buf;
		int send_buf_l; // Length, in bytes, of the buffer.
		int send_buf_n; // Number of bytes in the buffer.
		int send_buf_s; // Where the next byte to send is located in the buffer.
		
		uint8_t* recv_buf;
		int recv_buf_l; // Length, in bytes, of the buffer.
		int recv_buf_n; // Number of bytes in the buffer.
		int recv_buf_s; // Where the next byte to read from is located in the buffer.
		
	public:
		// Transmission Control Block variables.
		uint32_t ISS;
		
		uint32_t SND_UNA;
		uint32_t SND_NXT;
		uint32_t SND_WND;
		
		uint32_t IRS;
		
		uint32_t RCV_NXT;
		uint32_t RCV_WND;
		
		tcp_state state;
		
		// Whether we have sent a FIN packet.
		bool has_sent_fin;
		
		// Time (given by time(NULL)) of the last sent or received message (whichever is later).
		// Note that this is set by process() according to when it read the message from its internal buffer.
		// This is used to decide when to transition from FIN_SNRC to FIN_CLOSED and for detecting a connection timeout.
		time_t last_msg;
		
		// Initializes the struct including the TCB. Creates, binds, and connects a raw POSIX socket. Does not send any packets.
		// The initial state is closed.
		// Expects all values in network order!
		tcp_sok(uint32_t locl_addr, uint16_t locl_port, uint32_t peer_addr, uint16_t peer_port);
		
//	private:
		// Utility function for creating packets. Addresses, ports, sequence numbers, header lengths, etc. are filled in.
		// Takes a pointer to an allocated buffer where the packet is to be created. The user is responsible for ensuring the allocated buffer
		// is sufficient to hold the headers (up to 120 bytes total) plus all the data and option bytes!
		// The data is used to calculate the checksum, so make sure you pass it to the function!
		int form_packet(uint8_t* buf, uint32_t seq, uint32_t ack, uint16_t flags, uint8_t* data, int data_n,
		                 uint8_t* ip_options = NULL, int ip_options_n = 0, uint8_t* tcp_options = NULL, int tcp_options_n = 0);
		
		// Resets the TCB to its initial state.
		void reset_locl();
		
		// Writes to the socket. Will write repeatedly until all bytes are written.
		int send_bytes(uint8_t* buf, int buf_n);
		
		// Reads from the socket. Reads repeatedly until no bytes are available or until buf_n bytes have been read.
		// Returns the number of bytes or a (negative) error code.
		int recv_bytes(uint8_t* buf, int buf_n);
		
	public:
		// Changes the state to LISTEN.
		int listen();
		
		// Sends a SYN, changes the state to SYN_SENT, and returns.
		int connect();
		
		// Copies the passed data into the send buffer. Data will be sent on the next call to process().
		// Note that not all bytes may be sent, specifically if they exceed the send window size.
		int send(uint8_t* data, int data_n);
		
		// This function should be called repeatedly to maintain the TCP socket.
		// It segmentizes the send buffer and sends the data as packets. No packets will be sent until this function is called.
		// It also extracts data from incoming packets and copies them into the receive buffer.
		// All packets will be procesed and action taken in response. Incoming SYN's will be ACK'd or RST, incoming data will be ACK'd, etc.
		// Also handles the retransmission queue. This function removes packets from the retransmission queue that have been ACK'd and
		// retransmits data that has expired without being ACK'd. If data is retransmitted too many times, 
		// MIU_TCP_PROBABLE_PARTITION will be returned.
		int process();
		
		// Copies up to data_n bytes from the receive buffer into the passed buffer. Returns the number of bytes copied.
		int receive(uint8_t* data, int data_n);
		
		// Sends a FIN and returns. State will not change until process() detects that the FIN has been ACK'd.
		void disconnect();
		
		// Frees the memory used by the receive and send buffers.
		~tcp_sok();
	};
} // miu

#include "tcp_sok.cpp"

#endif
