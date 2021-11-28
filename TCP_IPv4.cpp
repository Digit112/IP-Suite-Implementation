namespace miu {
	tcp_ipv4_hdr::tcp_ipv4_hdr(uint8_t* ip_hdr, int ip_hdr_len) : ip(ip_hdr), tcp(ip_hdr + ip_hdr_len) {}
	tcp_ipv4_hdr::tcp_ipv4_hdr(uint8_t* ip_hdr) : ip(ip_hdr), tcp(ip_hdr + ip.header_len()) {}
	
	void tcp_ipv4_hdr::reset(uint8_t* ip_hdr, int ip_hdr_len) {
		if (ip.options != NULL) {
			delete[] ip.options;
		}
		ip.options = NULL;
		ip.options_n = -1;
		
		if (tcp.options != NULL) {
			delete[] tcp.options;
		}
		tcp.options = NULL;
		tcp.options_n = -1;
		
		ip.hdr = ip_hdr;
		tcp.hdr = ip_hdr + ip_hdr_len;
	}
	
	void tcp_ipv4_hdr::reset(uint8_t* ip_hdr) {
		if (ip.options != NULL) {
			delete[] ip.options;
		}
		ip.options = NULL;
		ip.options_n = -1;
		
		if (tcp.options != NULL) {
			delete[] tcp.options;
		}
		tcp.options = NULL;
		tcp.options_n = -1;
		
		ip.hdr = ip_hdr;
		tcp.hdr = ip_hdr + ip.header_len();
	}
	
	void tcp_ipv4_hdr::read_options() {
		tcp.read_options();
		ip.read_options();
	}
	
	int tcp_ipv4_hdr::header_len() {
		return ip.header_len() + tcp.header_len();
	}
	
	int tcp_ipv4_hdr::data_len() {
		return ntohs(ip.total_len()) - header_len();
	}
	
	int tcp_ipv4_hdr::seg_size() {
		return data_len() + (bool) tcp.get_flags(MIU_TCP_SYN) + (bool) tcp.get_flags(MIU_TCP_FIN);
	}
	
	// Calculate the tcp checksum.
	void tcp_ipv4_hdr::tcp_calc_chksm() {
		((uint16_t*) tcp.hdr)[8] = 0;
		
		uint32_t chksm = 0;
		uint16_t chksm_16;
		
		int tcp_seg_len = ntohs(ip.total_len()) - ip.header_len();
		for (int i = 0; i < tcp_seg_len/2; i++) {
			chksm += ((uint16_t*) tcp.hdr)[i];
		}
		
		if (tcp_seg_len % 2 == 1) {
			chksm += tcp.hdr[tcp_seg_len-1];
		}
		
		chksm += (uint16_t) ip.srce_addr() & 0x0000FFFF;
		chksm += (uint16_t) (ip.srce_addr() >> 16);
		chksm += (uint16_t) ip.dest_addr() & 0x0000FFFF;
		chksm += (uint16_t) (ip.dest_addr() >> 16);
		chksm += htons(0x0006);
		chksm += htons(tcp_seg_len);
		
		chksm    = (chksm >> 16) + (chksm & 0x0000FFFF);
		chksm_16 = (chksm >> 16) + (chksm & 0x0000FFFF);
		chksm_16 = ~chksm_16;
		
		((uint16_t*) tcp.hdr)[8] = chksm_16;
	}
	
	// Verify the tcp checksum. returns true if the checksum is good, false otherwise.
	bool tcp_ipv4_hdr::tcp_verify_chksm() {
		uint32_t chksm = 0;
		uint16_t chksm_16;
		
		int tcp_seg_len = ntohs(ip.total_len()) - ip.header_len();
		for (int i = 0; i < tcp_seg_len/2; i++) {
			chksm += ((uint16_t*) tcp.hdr)[i];
		}
		
		if (tcp_seg_len % 2 == 1) {
			chksm += tcp.hdr[tcp_seg_len-1];
		}
		
		chksm += (uint16_t) ip.srce_addr() & 0x0000FFFF;
		chksm += (uint16_t) (ip.srce_addr() >> 16);
		chksm += (uint16_t) ip.dest_addr() & 0x0000FFFF;
		chksm += (uint16_t) (ip.dest_addr() >> 16);
		chksm += htons(0x0006);
		chksm += htons(tcp_seg_len);
		
		chksm    = (chksm >> 16) + (chksm & 0x0000FFFF);
		chksm_16 = (chksm >> 16) + (chksm & 0x0000FFFF);
		chksm_16 = ~chksm_16;
		
		return !chksm_16;
	}
	
	void tcp_ipv4_hdr::calc_chksm() {
		ip.calc_chksm();
		tcp_calc_chksm();
	}
	
	int tcp_ipv4_hdr::validate(bool validate_checksums, bool validate_options) {
		int err;
		
		err = ip.validate(validate_checksums, validate_options);
		if (err != MIU_SUCCESS) return err;
		
		err = tcp.validate(validate_options);
		if (err != MIU_SUCCESS) return err;
		
		if (ntohs(ip.total_len()) < ip.header_len() + tcp.header_len()) {
			return MIU_TCPIPV4_INVALID_TOT_SIZE;
		}
		
		// verify TCP checksums.
		if (validate_checksums) {
			if (!tcp_verify_chksm()) {
				return MIU_TCP_INVALID_CHECKSUM;
			}
		}
		
		return MIU_SUCCESS;
	}
} // miu
