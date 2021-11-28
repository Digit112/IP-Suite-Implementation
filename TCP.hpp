#ifndef MIU_TCP
#define MIU_TCP

/*
	This file defines the tcp_hdr class which, much like the ipv4_hdr class, contains a pointer to a buffer containing the expected
	header, and has many utility functions for easily reading from and writing to the fields in that buffer. Also like ipv4_hdr, this
	class contains a list of pointers to options in that header.
	These pointers are encapsulated in tcp_opt instances (much like how ipv4 options are represented by ipv4_opt instances).
	
	This class always extracts the values, a process often involving bit manipulation, from the underlying array whenever those values are requested. They are never cached.
*/

#include <stdint.h>
#include <stdio.h>

#include "miu_errors.h"

// TCP flags
#define MIU_TCP_FIN 0x0100
#define MIU_TCP_SYN 0x0200
#define MIU_TCP_RST 0x0400
#define MIU_TCP_PSH 0x0800
#define MIU_TCP_ACK 0x1000
#define MIU_TCP_URG 0x2000

namespace miu {
	class tcp_hdr;
	class tcp_opt;
	
	// Defines a TCP header as per rfc 793
	// The actual bytes of the header are pointed to by the uint8_t pointer.
	// The member functions are mostly getters and setters as well as ways of getting calculated values.
	class tcp_hdr {
	public:
		// The raw bytes of the TCP header.
		uint8_t* hdr;
		
		// This array can be constructed from an incoming packet, but editing of it is not supported.
		// This array will be NULL until read_options() is called.
		tcp_opt* options;
		int options_n; // Initialized to -1 and set by read_options()
	
		// Construct with a pointer to at least 20 bytes of allocated space. A TCP header can be up to 60 bytes long.
		// The user is responsible for the management of this memory
		tcp_hdr(uint8_t* hdr);
	
		// Reads the data pointed to by hdr and creates an array of tcp_opt objects which is pointed to by options.
		// If options already contains an array, it is automatically deallocated and replaced.
		// Note that NOPs in the option list will NOT be included in the options array.
		void read_options();
		
		// Validates that this hdr points to a valid TCP header. Performs some sanity checks, and optionally validates that the options
		// are correctly formed. Returns 0 on success or an error code otherwise.
		int validate(bool validate_options = true);
	
		// Getters and setters.
		// ALL VALUES ARE EXPECTED AND RETURNED IN NETWORK ORDER.
		
		// The source port.
		uint16_t srce_port();
		void srce_port(uint16_t);
		
		// The destination port.
		uint16_t dest_port();
		void dest_port(uint16_t);
		
		// The sequence number of the first byte in this packet, or of the SYN flag if it is set.
		uint32_t seq();
		void seq(uint32_t);
		
		// Should be 0 unless the ACK flag is set. If it is, this is the sequence number of the first byte that we haven't received.
		uint32_t ack();
		void ack(uint32_t);
		
		// Size of the header. This field is called "Data Offset" by rfc 793.
		// Value is given and returned in bytes, but the undelying value is stored in increments of 4 bytes.
		uint8_t header_len();
		void header_len(uint8_t);
		
		// TCP flags
		uint16_t flags();
		void flags(uint16_t);
		
		// Flag manipulation utilities.
		uint16_t get_flags(uint16_t mask); // AND's the flags with the mask before returning.
		void set_flags(uint16_t flags); // The passed flags, if reset, will be set.
		void reset_flags(uint16_t flags); // The passed flags, if set, will be reset.
		
		// Window size. This is the number of bytes that we haven't received that we are willing to accept.
		uint16_t window();
		void window(uint16_t);
		
		/* Did you expect checksum validation here? Checksums require information from the IP header! ipv4_tcp_hdr contains this ability. */
		
		// If the URG flag is set, this gives the number of bytes in this segment, starting from the first, are considered "urgent".
		// Urgent data is (supposed to be) pushed to the receiving application before any preceeding data.
		uint16_t urgent();
		void urgent(uint16_t);
		
		~tcp_hdr();
	};
	
	class tcp_opt {
	public:
		// pointer to the option type byte.
		uint8_t* opt;
		
		// This option's type
		uint8_t opt_type();
		
		// Length of this option, in bytes, including the type byte and length byte as well as the data bytes.
		uint8_t opt_len();
	};
} //miu

#include "TCP.cpp"

#endif
