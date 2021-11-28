#ifndef MIU_TCP_IPV4
#define MIU_TCP_IPV4

/*
	This class defines the tcp_ipv4_hdr class, which combines the tcp_hdr and ipv4_hdr classes.
	It provides an additional TCP checksum verification that cannot be provided solely by the TCP
	class as well as additional integrity-verification utilities.
	
	This library and, more importantly, its derivatives, assume that the two underlying headers' bytes
	are stored continuously in memory.
	To enforce this, the pointer to the TCP header is calculated from the IP header length.
	This length may be passed (in bytes) or taken from an already-formatted IP datagram.
*/

#include <stdio.h>

#include "IPv4.hpp"
#include "TCP.hpp"

namespace miu {
	class tcp_ipv4_hdr;
	
	class tcp_ipv4_hdr {
	public:
		ipv4_hdr ip;
		tcp_hdr tcp;
		
		// Initialize with a pointer to the IPv4 header and its known length.
		// This is how you should create an object that you intend to fill out.
		// If you do not know the IP header length, you can set the TCP header's hdr pointer manually later.
		tcp_ipv4_hdr(uint8_t* ip_hdr, int ip_hdr_len);
		
		// Initialize with a pointer to the IPv4 header. IPv4 header length will be used to calculate the TCP pointer.
		// This is how you should create an object from an already-formatted TCP/IP header, for instance, one that was
		// just received.
		tcp_ipv4_hdr(uint8_t* ip_hdr);
		
		// Reinitialize the header object. This resets the options, if necessary, and recalculates the TCP pointer.
		void reset(uint8_t* ip_hdr, int ip_hdr_len);
		void reset(uint8_t* ip_hdr);
		
		// Calls read_options() on both headers.
		void read_options();
		
		// Length of both headers combined.
		int header_len();
		
		// Length of the data.
		int data_len();
		
		// Size of this packet in sequence space. Equal to data_len() plus one for the SYN and FIN flags each.
		int seg_size();
		
		// Utilities to calculate and verify the TCP checksum. These assume the segment data follows the TCP header.
		// These utilities could not be provided by the tcp_hdr class because they require information from the IP header.
		void tcp_calc_chksm();
		bool tcp_verify_chksm();
		
		// Calculate both checksums.
		void calc_chksm();
		
		// Calls validate() on both headers and returns any error they produce, but also (optionally) validates the TCP
		// checksum, and performs additional sanity checks.
		int validate(bool validate_checksums = true, bool validate_options = true);
	};
} // miu

#include "TCP_IPv4.cpp"

#endif
