#pragma pack(push, 1)
struct udphdr {
	uint16_t	uh_sport;	//Source Port
	uint16_t	uh_dport;	//Destination Port
	uint16_t	uh_ulen;	//UDP Length
	uint16_t	uh_sum;		//UDP Checksum
};

struct arphdr {
	uint16_t	ar_hrd;	// format of hardware address
	uint16_t	ar_pro;	// format of protocol address
	uint8_t	ar_hln;	// length of hardware address
	uint8_t	ar_pln;	// length of protocol address
	uint16_t	ar_op;	// ARP opcode (command)

	uint8_t	ar_sha[ETH_ALEN];	// sender hardware address
	struct in_addr ar_sip;	// sender IP address	
	uint8_t	ar_tha[ETH_ALEN];	// target hardware address
	struct in_addr ar_tip;	// target IP address
};
#pragma pack(pop)

