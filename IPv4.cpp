namespace miu {
	/* ipv4_hdr */
	
	ipv4_hdr::ipv4_hdr(uint8_t* hdr) : hdr(hdr), options(NULL), options_n(-1) {}
	
	// Populate the options array
	void ipv4_hdr::read_options() {
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
		options = new ipv4_opt[options_n];
		
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
	
	int ipv4_hdr::validate(bool validate_checksum, bool validate_options) {
		if ((hdr[0] & 0xF0) >> 4 != 4) {
			return MIU_IPV4_WRONG_VERSION;
		}
		
		if (header_len() < 20) {
			return MIU_IPV4_INVALID_HDR_SIZE;
		}
		
		if (ntohs(total_len()) < header_len()) {
			return MIU_IPV4_INVALID_TOT_SIZE;
		}
		
		if (ttl() == 0) {
			return MIU_IPV4_PACKET_EXPIRED;
		}
		
		if (validate_checksum) {
			if (!verify_chksm()) {
				return MIU_IPV4_INVALID_CHECKSUM;
			}
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
					return MIU_IPV4_MALFORMED_OPTIONS;
				}
				i += opt_len;
			}
			
			// If i has been thrown more than one byte outside of the header, then the options are malformed.
			if (i > options_bytes) {
				return MIU_IPV4_MALFORMED_OPTIONS;
			}
		}
		
		return MIU_SUCCESS;
	}
	
	uint8_t ipv4_hdr::header_len() {
		return (hdr[0] & 0x0F) << 2;
	}
	void ipv4_hdr::header_len(uint8_t a) {
		hdr[0] = (a >> 2 & 0x0F) | 0x40;
	}
	
	uint8_t ipv4_hdr::diff_serv() {
		return hdr[1];
	}
	void ipv4_hdr::diff_serv(uint8_t a) {
		hdr[1] = a;
	}
	
	uint16_t ipv4_hdr::total_len() {
		return ((uint16_t*) hdr)[1];
	}
	void ipv4_hdr::total_len(uint16_t a) {
		((uint16_t*) hdr)[1] = a;
	}
	
	uint16_t ipv4_hdr::id() {
		return ((uint16_t*) hdr)[2];
	}
	void ipv4_hdr::id(uint16_t a) {
		((uint16_t*) hdr)[2] = a;
	}
	
	uint8_t ipv4_hdr::flags() {
		return hdr[6] & 0xE0;
	}
	void ipv4_hdr::flags(uint8_t a) {
		hdr[6] = (a & 0xE0) | (hdr[6] & 0x1F);
	}
	
	uint8_t ipv4_hdr::get_flags(uint8_t mask) {
		return flags() & mask;
	}
	void ipv4_hdr::set_flags(uint8_t a) {
		flags(flags() | a);
	}
	void ipv4_hdr::reset_flags(uint8_t a) {
		flags(flags() & ~a);
	}
	
	uint16_t ipv4_hdr::frag_offset() {
		return ((uint16_t*) hdr)[3] & 0x1FFF;
	}
	void ipv4_hdr::frag_offset(uint16_t a) {
		uint16_t* hdr_16 = (uint16_t*) hdr;
		hdr_16[3] = (a & 0xFF1F) | (hdr_16[3] & 0x00E0);
	}
	
	uint8_t ipv4_hdr::ttl() {
		return hdr[8];
	}
	void ipv4_hdr::ttl(uint8_t a) {
		hdr[8] = a;
	}
	
	uint8_t ipv4_hdr::protocol() {
		return hdr[9];
	}
	void ipv4_hdr::protocol(uint8_t a) {
		hdr[9] = a;
	}
	
	bool ipv4_hdr::verify_chksm() {
		int header_len_16 = header_len() >> 1;
		uint32_t chksm = 0;
		for (int i = 0; i < header_len_16; i++)  {
			chksm += ((uint16_t*) hdr)[i];
		}
		
		chksm = (chksm >> 16) + (chksm & 0x0000FFFF);
		chksm = (chksm >> 16) + (chksm & 0x0000FFFF);
		uint16_t chksm_16 = ~((uint16_t) chksm);
		
		return !chksm_16;
	}
	
	void ipv4_hdr::calc_chksm() {
		((uint16_t*) hdr)[5] = 0;
		
		int header_len_16 = header_len() >> 1;
		uint32_t chksm = 0;
		for (int i = 0; i < header_len_16; i++)  {
			chksm += ((uint16_t*) hdr)[i];
		}
		
		chksm = (chksm >> 16) + (chksm & 0x0000FFFF);
		((uint16_t*) hdr)[5] = (uint16_t) ~((chksm >> 16) + (chksm & 0x0000FFFF));
	}
	
	uint32_t ipv4_hdr::srce_addr() {
		return ((uint32_t*) hdr)[3];
	}
	void ipv4_hdr::srce_addr(uint32_t a) {
		((uint32_t*) hdr)[3] = a;
	}
	
	uint32_t ipv4_hdr::dest_addr() {
		return ((uint32_t*) hdr)[4];
	}
	void ipv4_hdr::dest_addr(uint32_t a) {
		((uint32_t*) hdr)[4] = a;
	}
	
	ipv4_hdr::~ipv4_hdr() {
		if (options != NULL) {
			delete[] options;
		}
	}
	
	/* ipv4_opt */
	
	uint8_t ipv4_opt::opt_type() {
		return opt[0];
	}
	
	uint8_t ipv4_opt::opt_len() {
		return opt[1];
	}
	
	uint8_t ipv4_opt::opt_copied() {
		return opt[0] >> 7;
	}
	
	uint8_t ipv4_opt::opt_class() {
		return (opt[0] & 0x7F) >> 5;
	}
	
	uint8_t ipv4_opt::opt_number() {
		return opt[0] & 0x1F;
	}
} // miu















