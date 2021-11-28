#include <stdio.h>

#include "my_pcap_utils.h"

#include "tcp_sok.hpp"

using namespace miu;

int main() {
	int err;
	
	uint32_t locl_addr = htonl(0x7F000003);
	uint32_t peer_addr = htonl(0x7F000002);
	
	uint16_t locl_port = htons(1200);
	uint16_t peer_port = htons(2400);
	
	tcp_sok sok(locl_addr, locl_port, peer_addr, peer_port);
	
	pcap_t* pcap_handle = begin_cap("lo");
	
	err = sok.connect();
	if (err != MIU_SUCCESS) printf("Could not connect: %d\n", err);
	
	while (sok.state != tcp_sok::ESTABLISHED) {
		err = sok.process();
		if (err != MIU_SUCCESS) printf("Could not process: %d\n", err);
	}
	
	char buf[128];
	int buf_n = sprintf(buf, "Hello TCP/IPv4 implementation!");
	sok.send((uint8_t*) buf, buf_n);
	
	sok.process();
	
	sok.disconnect();
	
	while (sok.state != tcp_sok::FIN_SNRC) {
		err = sok.process();
		if (err != MIU_SUCCESS) printf("Could not process: %d\n", err);
	}
	
	end_cap(pcap_handle, "IPv4_test.pcap");
	
	return 0;
}
