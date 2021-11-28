inline int sok_connect(int sok, struct sockaddr* addr, int addr_len) {
	return connect(sok, addr, addr_len);
}

namespace miu {
	tcp_sok::tcp_sok(uint32_t locl_addr, uint16_t locl_port, uint32_t peer_addr, uint16_t peer_port) : 
	locl_addr(locl_addr), locl_port(locl_port), peer_addr(peer_addr), peer_port(peer_port),
	send_buf((uint8_t*) malloc(MIU_TCP_SND_BUF_N)), send_buf_l(MIU_TCP_SND_BUF_N), send_buf_n(0), send_buf_s(0),
	recv_buf((uint8_t*) malloc(MIU_TCP_RCV_BUF_N)), recv_buf_l(MIU_TCP_RCV_BUF_N), recv_buf_n(0), recv_buf_s(0),
	ISS(0), SND_UNA(0), SND_NXT(0), SND_WND(0), IRS(0), RCV_NXT(0), RCV_WND(MIU_TCP_RCV_WND), state(CLOSED),
	has_sent_fin(false), last_msg(time(NULL)) {
		int err;
		
		struct sockaddr_in locl = {AF_INET, locl_port, {locl_addr}};
		struct sockaddr_in peer = {AF_INET, peer_port, {peer_addr}};
		
		// Create socket
		sok = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
		if (sok == -1) perror("Could not get socket descriptor");
		
		// Bind socket
		err = bind(sok, (struct sockaddr*) &locl, sizeof(struct sockaddr_in));
		if (err == -1) perror("Could not bind socket");
		
		// IP header will be included in the data buffer
		int hdrincl = 1;
		err = setsockopt(sok, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl));
		if (sok == -1) perror("Failed to set hdrincl");
		
		// IO operations will be non-blocking
		fcntl(sok, F_SETFL, O_NONBLOCK | fcntl(sok, F_GETFL, 0));
		
		// Connect socket
		err = sok_connect(sok, (struct sockaddr*) &peer, sizeof(struct sockaddr_in));
		if (err == -1) perror("Could not connect socket");
	}
	
	int tcp_sok::form_packet(uint8_t* buf, uint32_t seq, uint32_t ack, uint16_t flags, uint8_t* data, int data_n,
	                         uint8_t* ip_options, int ip_options_n, uint8_t* tcp_options, int tcp_options_n) {
		// Header length is 20 plus the options length, rounded up to the nearest multiple of 4.
		int ip_pad_n = 0;
		if (ip_options_n & 0x03) {
			ip_pad_n = 4 - (ip_options_n & 0x03);
		}
		int ip_hdr_len = 20 + ip_options_n + ip_pad_n;
		if (ip_hdr_len > 60) return MIU_IPV4_TOO_MANY_OPTIONS;
		
		int tcp_pad_n = 0;
		if (tcp_options_n & 0x03) {
			tcp_pad_n = 4 - (tcp_options_n & 0x03);
		}
		int tcp_hdr_len = 20 + tcp_options_n + tcp_pad_n;
		if (tcp_hdr_len > 60) return MIU_TCP_TOO_MANY_OPTIONS;
		
		int total_len = ip_hdr_len + tcp_hdr_len + data_n;
		
		// Creaete a TCP/IP header instance
		tcp_ipv4_hdr hd(buf, ip_hdr_len);
		
		// Format the IP header
		hd.ip.header_len(ip_hdr_len);
		hd.ip.diff_serv(0);
		hd.ip.total_len(htons(total_len));
		hd.ip.id(0);
		hd.ip.flags(MIU_IPV4_DONT_FRAGMENT);
		hd.ip.frag_offset(0);
		hd.ip.ttl(64);
		hd.ip.protocol(IPPROTO_TCP);
		hd.ip.srce_addr(locl_addr);
		hd.ip.dest_addr(peer_addr);
		
		// Copy in IP options
		memcpy(hd.ip.hdr + 20, ip_options, ip_options_n);
		
		// Write zeroes for padding
		for (int i = 0; i < ip_pad_n; i++) {
			hd.ip.hdr[20 + ip_options_n + i] = 0;
		}
		
		// Format the TCP header
		hd.tcp.srce_port(locl_port);
		hd.tcp.dest_port(peer_port);
		hd.tcp.seq(seq);
		hd.tcp.ack(ack);
		hd.tcp.header_len(tcp_hdr_len);
		hd.tcp.flags(flags);
		hd.tcp.window(htons(MIU_TCP_RCV_WND));
		hd.tcp.urgent(0);
		
		// Copy in TCP options
		memcpy(hd.tcp.hdr + 20, tcp_options, tcp_options_n);
		
		// Write zeroes for padding
		for (int i = 0; i < tcp_pad_n; i++) {
			hd.tcp.hdr[20 + tcp_options_n + i] = 0;
		}
		
		// Copy the data in
		memcpy(hd.tcp.hdr + tcp_hdr_len, data, data_n);
		
		// Calculate the checksums
		hd.calc_chksm();
		
		// Validate
		int err = hd.validate();
		if (err != MIU_SUCCESS) printf("Well, fuck. (%d)\n", err);
		
		return MIU_SUCCESS;
	}
	
	void tcp_sok::reset_locl() {
		send_buf_s = 0;
		send_buf_n = 0;
		
		recv_buf_s = 0;
		recv_buf_n = 0;
		
		has_sent_fin = false;
		
		ISS = 0;
		
		SND_UNA = 0;
		SND_NXT = 0;
		SND_WND = 0;
		
		IRS = 0;
		
		RCV_NXT = 0;
		RCV_WND = MIU_TCP_RCV_WND;
		
		state = CLOSED;
	}
	
	int tcp_sok::send_bytes(uint8_t* buf, int buf_n) {
		int offset = 0;
		int ret;
		while (true) {
			float s = (float) clock() / CLOCKS_PER_SEC;
			
			ret = write(sok, buf+offset, buf_n-offset);
			
			if (ret == -1) {
				return MIU_FAILED_WRITE;
			}
			
			last_msg = time(NULL);
			
			offset += ret;
			if (offset == buf_n) {
				return offset;
			}
			
			while ((float) clock() / CLOCKS_PER_SEC - s < 0.001) {}
		}
	}
	
	int tcp_sok::recv_bytes(uint8_t* buf, int buf_n) {
		int offset = 0;
		int ret;
		struct pollfd pfd = {sok, POLLIN, 0};
		
		while (poll(&pfd, 1, 0) > 0) {
			ret = read(sok, buf+offset, buf_n-offset);
			
			if (ret == -1) {
				perror("Failed read");
				return MIU_FAILED_READ;
			}
			
			offset += ret;
			if (offset == buf_n) {
				return offset;
			}
		}
		
		return offset;
	}
	
	int tcp_sok::listen() {
		if (state != CLOSED && state != LISTEN) {
			return MIU_TCP_INVALID_STATE_CHANGE;
		}
		
		state = LISTEN;
		return MIU_SUCCESS;
	}
	
	int tcp_sok::connect() {
		if (state != CLOSED && state != LISTEN) {
			return MIU_TCP_INVALID_STATE_CHANGE;
		}
		
		int err;
		
		uint8_t buf[40];
		err = form_packet(buf, ISS, 0, MIU_TCP_SYN, NULL, 0);
		if (err != MIU_SUCCESS) return err;
		
		send_bytes(buf, 40);
		
		state = SYN_SENT;
		
		SND_NXT++;
		
		return MIU_SUCCESS;
	}
	
	// This function is complicated by the fact that the buffer wraps around on itself.
	int tcp_sok::send(uint8_t* data, int data_n) {
		// Check for invalid input
		if (data_n <= 0) return MIU_INVALID_LEN;
		
		// Check that the send buffer can hold this data
		if (send_buf_n + data_n > send_buf_l) {
			return MIU_SEND_BUFFER_FULL;
		}
		
		// Calculate the start and end indices in the array where the data will be copied
		int start = (send_buf_s + send_buf_n) % send_buf_l;
		int end = (start + data_n) % send_buf_l;
		
		// Increase the buffer size
		send_buf_n += data_n;
		
		// If the data doesn't wrap, it can all be copied at once.
		if (end > start || end == 0) {
			memcpy(send_buf + start, data, data_n);
		}
		// Otherwise, copy the first half of the data to the end of the send buffer and copy the second half to the beginning.
		else {
			memcpy(send_buf + start, data, send_buf_l - start);
			memcpy(send_buf, data + (send_buf_l - start), data_n - (send_buf_l - start));
		}
		
		return MIU_SUCCESS;
	}
	
	int tcp_sok::process() {
		int err;
		
		/* PROCESS THE SEND BUFFER */
		
		if (state == ESTABLISHED || state == FIN_RECV) {
			uint8_t* pkt = (uint8_t*) malloc(MIU_TCP_MAX_SEG_SIZE);
			
			// We can transmit. Transmit as many bytes as we can.
			while (true) {
				// Calculate how many bytes to transmit.
				int bytes_to_send;
				int bytes_in_window = (SND_UNA + SND_WND) - SND_NXT; // The number of bytes we could send without exceeding the send window.
			
				if (bytes_in_window < send_buf_n) {
					bytes_to_send = bytes_in_window;
				}
				else {
					bytes_to_send = send_buf_n;
				}
				
				if (bytes_to_send == 0) {
					// Nothing to send, continue to processing received packets.
					break;
				}
				
				// Check that this doesn't exceed the maximum segment size
				if (MIU_TCP_MAX_SEG_SIZE < bytes_to_send + 40) {
					bytes_to_send = MIU_TCP_MAX_SEG_SIZE - 40;
				}
				
				// Create the packet and send.
				form_packet(pkt, htonl(SND_NXT), htonl(RCV_NXT), MIU_TCP_ACK, send_buf + send_buf_s, bytes_to_send);
				int pkt_size = 40 + bytes_to_send;
				
				err = send_bytes(pkt, pkt_size);
				if (err < 0) {free(pkt); return err;}
				
				SND_NXT += bytes_to_send;
				
				send_buf_n -= bytes_to_send;
				send_buf_s += bytes_to_send;
				
				printf("%d\n", SND_NXT);
			}
			
			free(pkt);
		}
		
		/* PROCESS THE RECEIVE QUEUE */
		
		struct pollfd pfd = {sok, POLLIN, 0};
		if (state != CLOSED && poll(&pfd, 1, 0) > 0) {
			printf("Processing receive queue.\n");
			
			// For storing the received packet(s)
			uint8_t* pkts = (uint8_t*) malloc(MIU_TCP_RCV_BUF_N);
			
			// For constructing outgoing packets
			uint8_t* out = (uint8_t*) malloc(MIU_TCP_MAX_SEG_SIZE);
			
			// Attempt to read the buffer
			err = recv_bytes(pkts, MIU_TCP_RCV_BUF_N);
			if (err < 0) return err;
			
			int received_bytes = err;
			
			tcp_ipv4_hdr hdi(pkts);
			tcp_ipv4_hdr hdo(out, 20);
			
			printf("Read %d bytes.\n", received_bytes);
			
			// Process all packets. Start of the next packet is calculated from the header of each previous packet.
			for(; hdi.ip.hdr - pkts < received_bytes; hdi.reset(hdi.ip.hdr + ntohs(hdi.ip.total_len()))) {
				last_msg = time(NULL);
				
				printf("Processing Packet.\n");
				
				if (hdi.ip.hdr + ntohs(hdi.ip.total_len()) - pkts > received_bytes) {
					printf("Packet length exceeds received bytes. Probably a split packet.\n");
					break;
				}
				
				// Validate the IPv4 header
				err = hdi.ip.validate(true, true);
				if (err != MIU_SUCCESS) {
					printf("IP validation failed (%d). All packets dropped.\n", err);
					break;
				}
				
				// Validate the TCP/IPv4 header. Checksums are not done because they are often incorrect due to TCP checksum offloading.
				err = hdi.validate(false, true);
				if (err != MIU_SUCCESS) {
					printf("TCP/IP validation failed (%d). Packet dropped.\n", err);
					continue;
				}
				
				hdi.read_options();
				
				/* CLOSED */
				if (state == CLOSED) {
					printf("CLOSED\n");
					// Incoming RST packets are ignored.
					if (hdi.tcp.get_flags(MIU_TCP_RST)) {
						continue;
					}
					
					// Any other packets are RST'd.
					if (hdi.tcp.get_flags(MIU_TCP_ACK)) {
						// If the ACK flag is set, set SEQ to make the packet valid.
						form_packet(out, hdi.tcp.ack(), 0, MIU_TCP_RST, NULL, 0); 
					}
					else {
						// Otherwise, we'll set SEQ to 0 and ACK their packet.
						form_packet(out, 0, htonl(ntohl(hdi.tcp.seq()) + hdi.seg_size()), MIU_TCP_RST | MIU_TCP_ACK, NULL, 0);
					}
					
					printf("Reseting packet.\n");
					send_bytes(out, ntohs(hdo.ip.total_len()));
					
					continue;
				}
				
				/* LISTEN */
				if (state == LISTEN) {
					printf("LISTEN\n");
					// Incoming RST packets are ignored.
					if (hdi.tcp.get_flags(MIU_TCP_RST)) {
						continue;
					}
					
					// Incoming ACK packets are RST'd
					if (hdi.tcp.get_flags(MIU_TCP_ACK)) {
						printf("Reseting ACK.\n");
						form_packet(out, hdi.tcp.ack(), 0, MIU_TCP_RST, NULL, 0);
						send_bytes(out, ntohs(hdo.ip.total_len()));
						continue;
					}
					
					// Incoming SYN packets are recorded and SYN-ACK'd
					if (hdi.tcp.get_flags(MIU_TCP_SYN)) {
						IRS = ntohl(hdi.tcp.seq());
						RCV_NXT = IRS + 1;
						SND_WND = ntohs(hdi.tcp.window());
						
						ISS = 0;
						
						printf("Acknowledging, synchronising with incoming SYN.\n");
						form_packet(out, htonl(ISS), htonl(RCV_NXT), MIU_TCP_SYN | MIU_TCP_ACK, NULL, 0);
						send_bytes(out, ntohs(hdo.ip.total_len()));
						
						SND_NXT = ISS + 1;
						SND_UNA = ISS;
						
						state = SYN_RECV;
						
						continue;
					}
					
					continue;
				}
				
				/* SYN-SENT */
				if (state == SYN_SENT) {
					printf("SYN-SENT\n");
					// Incoming ACKs are validated, and checked for SYN or RST.
					if (hdi.tcp.get_flags(MIU_TCP_ACK)) {
						printf("pkt has ACK.\n");
						// Invalid ACKs get RST'd
						if (ntohl(hdi.tcp.ack()) <= ISS || ntohl(hdi.tcp.ack()) > SND_NXT) {
							// Unless they have the RST flag set
							if (!hdi.tcp.get_flags(MIU_TCP_RST)) {
								printf("Reseting strange ACK.\n");
								form_packet(out, ntohl(hdi.tcp.ack()), 0, MIU_TCP_RST, NULL, 0);
								send_bytes(out, ntohs(hdo.ip.total_len()));
							}
							continue;
						}
						
						// ACK is good
						printf("ACK is good.\n");
						
						// If this is also a RST, then the connection has been reset and should be closed.
						if (hdi.tcp.get_flags(MIU_TCP_RST)) {
							reset_locl();
							printf("Connection reset.\n");
							continue;
						}
					}
					
					// ACK is good, or there is no ACK. If there is an ACK, then there is no RST.
					
					if (hdi.tcp.get_flags(MIU_TCP_SYN)) {
						IRS = ntohl(hdi.tcp.seq());
						RCV_NXT = IRS + 1;
						SND_WND = ntohs(hdi.tcp.window());
						
						printf("Packet has SYN. Synchronising to IRS=%u\n", IRS);
						
						// If this is a SYN-ACK (And we already know in that case, that the ACK is good) then advance SND_UNA
						if (hdi.tcp.get_flags(MIU_TCP_ACK)) {
							SND_UNA = ntohl(hdi.tcp.ack());
							printf("pkt is good SYN-ACK.\n");
						}
						
						// If our SYN has been ACK'd, connection is now established. Send ACK.
						if (SND_UNA > ISS) {
							printf("Connection established.\n");
							state = ESTABLISHED;
							form_packet(out, htonl(SND_NXT), htonl(RCV_NXT), MIU_TCP_ACK, NULL, 0);
							send_bytes(out, ntohs(hdo.ip.total_len()));
						}
						// Otherwise, intiate simultaneous connection. Go to SYN_RECV and send a SYN-ACK.
						else {
							printf("Simultaneous synchronization.\n");
							state = SYN_RECV;
							form_packet(out, htonl(ISS), htonl(RCV_NXT), MIU_TCP_SYN | MIU_TCP_ACK, NULL, 0);
							send_bytes(out, ntohs(hdo.ip.total_len()));
						}
					}
					
					continue;
				}
				
				/* OTHER */
				printf("OTHER\n");
				
				// Check that the sequence is valid. If not, send an acknowledgement.
				uint32_t in_seq = ntohl(hdi.tcp.seq());
				uint32_t in_ack = ntohl(hdi.tcp.ack());
				
				printf("%u, %u, %u, %u\n", in_seq, RCV_NXT, RCV_WND, hdi.seg_size()); 
				if (in_seq >= RCV_NXT + RCV_WND || in_seq + hdi.seg_size() < RCV_NXT) {
					if (!hdi.tcp.get_flags(MIU_TCP_RST)) {
						printf("Acknowledging strange sequence.\n");
						form_packet(out, htonl(SND_NXT), htonl(RCV_NXT), MIU_TCP_ACK, NULL, 0);
						send_bytes(out, ntohs(hdo.ip.total_len()));
					}
					continue;
				}
				
				/* 
					rfc 793 leaves it as implementation-defined whether out of order segments are held or not.
					As this is a simple personal project, we will be discarding all out of order segments, forcing the sender
					to retransmit them in this case. Data should never arrive out of order on the loopback device.
				*/
				if (in_seq != RCV_NXT) {
					continue;
				}
				
				// Valid resets cause the connection to reset.
				if (hdi.tcp.get_flags(MIU_TCP_RST)) {
					reset_locl();
					continue;
				}
				
				// Valid SYN's elicit a RST.
				if (hdi.tcp.get_flags(MIU_TCP_SYN)) {
					printf("Reseting unexpected SYN.\n");
					form_packet(out, htonl(SND_NXT), 0, MIU_TCP_RST, NULL, 0);
					send_bytes(out, ntohs(hdo.ip.total_len()));
					reset_locl();
					continue;
				}
				
				// Segments without an ACK get dropped.
				if (!hdi.tcp.get_flags(MIU_TCP_ACK)) {
					continue;
				}
				
				// In SYN_RECV, ACK's move us to ESTABLISHED and we continue processing.
				if (state == SYN_RECV) {
					if (SND_UNA <= in_ack && in_ack <= SND_NXT) {
						state = ESTABLISHED;
					}
					// If the ACK is invalid, send a reset.
					else {
						printf("Reseting strange ACK.\n");
						form_packet(out, in_ack, 0, MIU_TCP_RST, NULL, 0);
						send_bytes(out, ntohs(hdo.ip.total_len()));
						continue;
					}
				}
				
				// In ESTABLISHED and FIN_RECV, move ACK forward if it is acceptable.
				if (state == ESTABLISHED || state == FIN_RECV) {
					// If the ACK is a duplicate, ignore it.
					if (SND_UNA <= in_ack && in_ack <= SND_NXT) {
						printf("Packet contains acceptable ACK.\n");
						SND_UNA = in_ack; 
						SND_WND = ntohs(hdi.tcp.window());
					}
					// If this ACK's something not yet sent, reply with an ACK.
					else if (in_ack > SND_NXT) {
						printf("Acknowledging strange ACK.\n");
						form_packet(out, in_ack, 0, MIU_TCP_RST, NULL, 0);
						send_bytes(out, ntohs(hdo.ip.total_len()));
						continue;
					}
					
					// Check if our FIN has been ACK'd and change state accordingly.
					if (has_sent_fin) {
						if (SND_UNA == SND_NXT) {
							printf("Our FIN has been acknowledged.\n");
							if (state == ESTABLISHED) {
								state = FIN_SENT;
							}
							else {
								state = FIN_SNRC;
							}
						}
					}
				}
				
				// In ESTABLISHED and FIN_SENT, we can receive a FIN.
				if (hdi.tcp.get_flags(MIU_TCP_FIN)) {
					if (state == ESTABLISHED) {
						printf("Received FIN.\n");
						state = FIN_RECV;
					}
					else if (state == FIN_SENT) {
						printf("Received FIN.\n");
						state = FIN_SNRC;
					}
				}
				
				// Acknowledge this packet and update the TCB, copy any data into the receive buffer.
				if (hdi.seg_size() > 0) {
					RCV_NXT += hdi.seg_size();
					printf("Acknowledging packet.\n");
					form_packet(out, htonl(SND_NXT), htonl(RCV_NXT), MIU_TCP_ACK, NULL, 0);
					send_bytes(out, ntohs(hdo.ip.total_len()));
				}
				
				// Check for data
				if (hdi.data_len() > 0) {
					// Check that the receive buffer can hold this data
					if (recv_buf_n + hdi.data_len() > recv_buf_l) {
						return MIU_RECV_BUFFER_FULL;
					}
		
					// Calculate the start and end indices in the array where the data will be copied
					int start = (recv_buf_s + recv_buf_n) % recv_buf_l;
					int end = (start + hdi.data_len()) % recv_buf_l;
		
					// Increase the buffer size
					recv_buf_n += hdi.data_len();
		
					// If the data doesn't wrap, it can all be copied at once.
					if (end > start || end == 0) {
						memcpy(recv_buf + start, hdi.tcp.hdr + hdi.tcp.header_len(), hdi.data_len());
					}
					// Otherwise, copy the first half of the data to the end of the receive buffer and copy the second half to the beginning.
					else {
						memcpy(recv_buf + start, hdi.tcp.hdr + hdi.tcp.header_len(), recv_buf_l - start);
						memcpy(recv_buf, hdi.tcp.hdr + hdi.tcp.header_len() + (recv_buf_l - start), hdi.data_len() - (recv_buf_l - start));
					}
				}
			}
			
			free(pkts);
			free(out);
		}
		
		return MIU_SUCCESS;
	}
	
	void tcp_sok::disconnect() {
		printf("%d\n", SND_NXT);
		uint8_t buf[40];
		form_packet(buf, htonl(SND_NXT), htonl(RCV_NXT), MIU_TCP_ACK | MIU_TCP_FIN, NULL, 0);
		tcp_ipv4_hdr hdo(buf);
		send_bytes(buf, ntohs(hdo.ip.total_len()));
		SND_NXT++;
		has_sent_fin = true;
	}
	
	tcp_sok::~tcp_sok() {
		free(send_buf);
		free(recv_buf);
		
		close(sok);
	}
} // miu
