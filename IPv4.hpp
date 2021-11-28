#ifndef MIU_IPV4
#define MIU_IPV4

/*
	This header defines the ipv4_hdr class, which is assigned a pointer to an IPv4 header in memory and provides many utilities
	for reading and writing to that header. Checksum calculation/verification is also provided.
	
	This header also defines the ipv4_opt class which similarly provides utilities for reading (but not writing) the options
	of a received IPv4 packet. Writing may be added in the future.
	The ipv4_opt class, like the ipv4_hdr class, is just a pointer to some bytes and utility functions for extracting information
	from those bytes.
*/

#include <stdint.h>
#include <stdio.h>

#include <netinet/in.h>

#include "miu_errors.h"

// Flags
#define MIU_IPV4_DONT_FRAGMENT 0x40
#define MIU_IPV4_MORE_FRAGMENTS 0x20

// Option classes
#define MIU_IPV4_OPT_CONTROL 0x00
#define MIU_IPV4_OPT_DEBUG 0x40

namespace miu {
	class ipv4_hdr;
	class ipv4_opt;

	// Defines an IPv4 header as per rfc 791
	// The actual bytes of the header are pointed to by the uint8_t pointer.
	// The member functions are mostly getters and setters as well as ways of getting calculated values.
	class ipv4_hdr {
	public:
		// The raw bytes of the IPv4 header.
		uint8_t* hdr;
	
		// Array of "ipv4_opt"s that describe and point to the IPv4 header's option data.
		// This array can be constructed from an incoming packet, but editing of it is not supported.
		// This array will be NULL until read_options() is called.
		ipv4_opt* options;
		int options_n; // Is initialized to -1, and set by read_options().
	
		// Construct with a pointer to at least 20 bytes of allocated space. An IPv4 header can be up to 60 bytes long.
		// The user is responsible for the manaagement of this memory.
		ipv4_hdr(uint8_t* hdr);
	
		// Reads the data pointed to by hdr and creates an array of ipv4_opt objects which is pointed to by options.
		// If options already contains an array, it is automatically deallocated and replaced.
		// Note that NOPs in the option list will NOT be included in the options array.
		void read_options();
		
		// Validates that this hdr points to a valid IPv4 header. Performs some sanity checks, and optionally validates that the options
		// are correctly formed and that the checksum is correct. Returns 0 on success or an error code otherwise.
		int validate(bool validate_checksum = true, bool validate_options = true);
	
		// Getters and setters.
		// ALL VALUES ARE EXPECTED AND RETURNED IN NETWORK ORDER.
	
		// Length of the IP header in bytes. (actual stored value is measured in 32-bit segments)
		// This also sets the IP version field to 4.
		uint8_t header_len();
		void header_len(uint8_t);
	
		// Diffserv field (rfc 2475), replaces original type-of-service field.
		uint8_t diff_serv();
		void diff_serv(uint8_t);
	
		// Length, in bytes, of the IP header and all data after it. Be careful when setting this value! It is used all over as a measure of the length of hdr.
		uint16_t total_len();
		void total_len(uint16_t);
	
		// Identification. Used in fragment reassembly. Most IP packets (All TCP packets) aren't fragmented, so this can be safely ignored.
		uint16_t id();
		void id(uint16_t);
	
		// Flags. Two exist: IPV4_DONT_FRAGMENT and IPV4_MORE_FRAGMENTS.
		uint8_t flags();
		void flags(uint8_t);
		
		// Flag manipulation utilities.
		uint8_t get_flags(uint8_t mask); // AND's the flags with the mask before returning.
		void set_flags(uint8_t flags); // The passed flags, if reset, will be set.
		void reset_flags(uint8_t flags); // The passed flags, if set, will be reset.
	
		// Fragment offset. Like id, can typically be ignored.
		uint16_t frag_offset();
		void frag_offset(uint16_t);
	
		// Time to live. Reduced by every IP module that the packet passes through.
		uint8_t ttl();
		void ttl(uint8_t);
	
		// Protocol. Values used here should be taken from <netinet/in.h>
		uint8_t protocol();
		void protocol(uint8_t);
	
		// Checksum is not handled via getter and setter, but by calculate and verify functions.
		bool verify_chksm(); // Returns true if checksum is good, false otherwise.
		void calc_chksm(); // Should be called after all other fields are set.
	
		// Source and destination IPv4 addresses.
		uint32_t srce_addr();
		void srce_addr(uint32_t);
	
		uint32_t dest_addr();
		void dest_addr(uint32_t);
		
		// Frees the options list if read_options() was called.
		~ipv4_hdr();
	};
	
	class ipv4_opt {
	public:
		// pointer to the option type byte.
		uint8_t* opt;
		
		// This option's type
		uint8_t opt_type();
		
		// Length of this option, in bytes, including the type byte and length byte as well as the data bytes.
		uint8_t opt_len();
		
		// First bit of type, if true, this option should be copied into all fragments during fragmentation.
		uint8_t opt_copied();
		
		// Second and third bits of type. Values 1 and 3 are reserved. See IPv4 option classes.
		uint8_t opt_class();
		
		// Remaining bits of type. 
		uint8_t opt_number();
	};
} // miu

#include "IPv4.cpp"

#endif

