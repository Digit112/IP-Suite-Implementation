namespace miu {
	/* tcp_hdr */
	
	tcp_hdr::tcp_hdr(uint8_t* hdr) : hdr(hdr), options(NULL), options_n(-1) {}
	
	// Populate the options array
	void tcp_hdr::read_options() {
		int options_bytes = header_len() - 20;
		
		// Deallocate the options list if it already exists
		if (options != NULL) {
			delete[] options;
		}
		
		// Calculate the number of options
		options_n = 0;
		for (int i = 0; i < options_bytes && hdr[i+20] > 0;) {
			if (hdr[i+20] == 1) {
				i++;
				continue;
			}
			
			options_n++;
			i += hdr[i+21];
		}
		
		// If there are no options, return.
		if (options_n == 0) {
			options = NULL;
			return;
		}
		
		// Allocate space for these options
		options = new tcp_opt[options_n];
		
		// Fill out the array
		int opt_i = 0;
		for (int i = 0; i < options_bytes && hdr[i+20] > 0;) {
			if (hdr[i+20] == 1) {
				i++;
				continue;
			}
			
			options[opt_i].opt = hdr + 20 + i;
			opt_i++;
			i += hdr[i+21];
		}
	}
	
	int tcp_hdr::validate(bool validate_options) {
		if (header_len() < 20) {
			return MIU_TCP_INVALID_HDR_SIZE;
		}
		
		if (validate_options) {
			int options_bytes = header_len() - 20;
			
			int i;
			for (i = 0; i < options_bytes && hdr[i+20] > 0;) {
				if (hdr[i+20] == 1) {
					i++;
					continue;
				}
				
				int opt_len = hdr[i+21];
				if (opt_len < 2) {
					return MIU_TCP_MALFORMED_OPTIONS;
				}
				i += opt_len;
			}
			
			// If i has been thrown more than one byte outside of the header, then the options are malformed.
			if (i > options_bytes) {
				return MIU_TCP_MALFORMED_OPTIONS;
			}
		}
		
		return MIU_SUCCESS;
	}
	
	uint16_t tcp_hdr::srce_port() {
		return ((uint16_t*) hdr)[0];
	}
	void tcp_hdr::srce_port(uint16_t a) {
		((uint16_t*) hdr)[0] = a;
	}
	
	uint16_t tcp_hdr::dest_port() {
		return ((uint16_t*) hdr)[1];
	}
	void tcp_hdr::dest_port(uint16_t a) {
		((uint16_t*) hdr)[1] = a;
	}
	
	uint32_t tcp_hdr::seq() {
		return ((uint32_t*) hdr)[1];
	}
	void tcp_hdr::seq(uint32_t a) {
		((uint32_t*) hdr)[1] = a;
	}
	
	uint32_t tcp_hdr::ack() {
		return ((uint32_t*) hdr)[2];
	}
	void tcp_hdr::ack(uint32_t a) {
		((uint32_t*) hdr)[2] = a;
	}
	
	uint8_t tcp_hdr::header_len() {
		return (hdr[12] & 0xF0) >> 2;
	}
	void tcp_hdr::header_len(uint8_t a) {
		hdr[12] = (a & 0x3C) << 2;
	}
	
	uint16_t tcp_hdr::flags() {
		return ((uint16_t*) hdr)[6] & 0xFF0F;
	}
	void tcp_hdr::flags(uint16_t a) {
		((uint16_t*) hdr)[6] = (((uint16_t*) hdr)[6] & 0x00F0) | (a & 0xFF0F);
	}
	
	uint16_t tcp_hdr::get_flags(uint16_t mask) {
		return flags() & mask;
	}
	void tcp_hdr::set_flags(uint16_t a) {
		flags(flags() | a);
	}
	void tcp_hdr::reset_flags(uint16_t a) {
		flags(flags() & ~a);
	}
	
	uint16_t tcp_hdr::window() {
		return ((uint16_t*) hdr)[7];
	}
	void tcp_hdr::window(uint16_t a) {
		((uint16_t*) hdr)[7] = a;
	}
	
	uint16_t tcp_hdr::urgent() {
		return ((uint16_t*) hdr)[9];
	}
	void tcp_hdr::urgent(uint16_t a) {
		((uint16_t*) hdr)[9] = a;
	}
	
	tcp_hdr::~tcp_hdr() {
		if (options != NULL) {
			delete[] options;
		}
	}
	
	/* tcp_opt */
	
	uint8_t tcp_opt::opt_type() {
		return opt[0];
	}
	
	uint8_t tcp_opt::opt_len() {
		return opt[1];
	}
} //miu
