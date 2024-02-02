#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<features.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <netinet/ip_icmp.h>
//#include<linux/ip.h>
//#include<linux/tcp.h>
#include<linux/if_arp.h>
#include<netinet/in.h>

// protocol_to_sniff est le protocole niveau liaison. ça sera le protocole ETHERNET
// car nous allons faire du sniffing sur un réseau local de type ETHERNET
int CreateRawSocket(int protocol_to_sniff)
{
	int rawsock;

	if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff)))== -1)
	{
		perror("Error creating raw socket: ");
		exit(-1);
	}

	return rawsock;
}

int BindRawSocketToInterface(char *device, int rawsock, int protocol)
{
	struct sockaddr_ll sll;
	struct ifreq ifr;

	bzero(&sll, sizeof(sll));
	bzero(&ifr, sizeof(ifr));
	
	/* First Get the Interface Index  */

	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)
	{
		printf("Error getting Interface index !\n");
		exit(-1);
	}

	/* Bind our raw socket to this interface */

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(protocol); 


	if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
	{
		perror("Error binding raw socket to interface\n");
		exit(-1);
	}

	return 1;
	
}

void PrintPacketInHex(unsigned char *packet, int len)
{
	unsigned char *p = packet;

	printf("\n\n---------Packet---Starts----\n\n");
	
	while(len--)
	{
		printf("%.2x ", *p);
		p++;
	}

	printf("\n\n--------Packet---Ends-----\n\n");

}


PrintInHex(char *mesg, unsigned char *p, int len)
{
	printf("%s",mesg);

	while(len--)
	{
		printf("%.2X ", *p);
//		printf("%c",*p);
		p++;
	}

}


ParseEthernetHeader(unsigned char *packet, int len)
{
	struct ethhdr *ethernet_header;

	if(len > sizeof(struct ethhdr))
	{
		ethernet_header = (struct ethhdr *)packet;

		/* First set of 6 bytes are Destination MAC */

		PrintInHex("Destination MAC: ", ethernet_header->h_dest, 6);
		printf("\n");
		
		/* Second set of 6 bytes are Source MAC */

		PrintInHex("Source MAC: ", ethernet_header->h_source, 6);
		printf("\n");

		/* Last 2 bytes in the Ethernet header are the protocol it carries */

		PrintInHex("Protocol: ",(void *)&ethernet_header->h_proto, 2);
		printf("\n");

		
	}
	else
	{
		printf("Packet size too small !\n");
	}
}

ParseIpHeader(unsigned char *packet, int len)
{
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	

	/* First Check if the packet contains an IP header using
	   the Ethernet header                                */

	ethernet_header = (struct ethhdr *)packet;

	if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
	{
		/* The IP header is after the Ethernet header  */
		
		if(len >= (sizeof(struct ethhdr) + sizeof(struct iphdr)))
		{
			ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));
			
			/* print the Source and Destination IP address */
			printf("TTL: %d \n",ip_header->ttl);
		printf("Dest IP address: %s\n", inet_ntoa( *(struct in_addr*)&ip_header->daddr));
		printf("Source IP address: %s\n", inet_ntoa( *(struct in_addr*)&ip_header->saddr));
	

		}
		else
		{
			printf("IP packet does not have full header\n");
		}

	}
	else
	{
		/* Not an IP packet */

	}
}



ParseTcpHeader(unsigned char *packet , int len)
{
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;

	/* Check if enough bytes are there for TCP Header */

	if(len >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
	{
		/* Do all the checks: 1. Is it an IP pkt ? 2. is it TCP ? */
		
		ethernet_header = (struct ethhdr *)packet;

		if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
		{
			ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));


			if(ip_header->protocol == IPPROTO_TCP)
			{
			     printf("----------------------------egment (TCP protocol num=%d)\n",ip_header->protocol);						
				tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4 );
				/* Print the Dest and Src ports */

				printf("Source Port: %d\n", ntohs(tcp_header->source));
				printf("Dest Port: %d\n", ntohs(tcp_header->dest));

			}
			else
			{
				printf("Not a TCP packet\n");
			}
		}
		else
		{
			printf("Not an IP packet\n");
		}	
		
	}
	else
	{
		printf("TCP Header not present \n");

	} 
}


int ParseData(unsigned char *packet, int len)
{
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	unsigned char *data;
	int data_len;

	/* Check if any data is there */

	if(len > (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
	{
		
		ip_header = (struct iphdr*)(packet + sizeof(struct ethhdr));

		
		data = (packet + sizeof(struct ethhdr) + ip_header->ihl*4 +sizeof(struct tcphdr));
		data_len = ntohs(ip_header->tot_len) - ip_header->ihl*4 - sizeof(struct tcphdr);

		if(data_len)
		{
			printf("Data Len : %d\n", data_len);
			printf("------------------\n");
			printf("%s\n",(char*)data);
			printf("********************\n");
			PrintInHex("Data : ", data, data_len);
			printf("\n\n");		
			return 1;	
		}
		else
		{
			printf("No Data in packet\n");
			return 0;
		}
	}
	else
	{
		printf("No Data in packet\n");
		return 0;
	} 	

}

int IsIpAndTcpPacket(unsigned char *packet, int len)
{
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;

	ethernet_header = (struct ethhdr *)packet;

	if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
	{
		ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

		if(ip_header->protocol == IPPROTO_TCP)
			return 1;
		else		
			return -1;
	}
	else
	{
		return -1;
	}
}

//*******************************************
ParseUdpHeader(unsigned char *packet , int len)
{
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	struct udphdr *udp_header;

	/* Check if enough bytes are there for UDP Header */

	if(len >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)))
	{
		/* Do all the checks: 1. Is it an IP pkt ? 2. is it UDP ? */
		
		ethernet_header = (struct ethhdr *)packet;

		if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
		{
			ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));


			if(ip_header->protocol == IPPROTO_UDP)
			{
			     printf("----------------------------egment (UDP protocol num=%d)\n",ip_header->protocol);						
				udp_header = (struct udphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4 );
				/* Print the Dest and Src ports */

				printf("Source Port: %d\n", ntohs(udp_header->source));
				printf("Dest Port: %d\n", ntohs(udp_header->dest));

			}
			else
			{
				printf("Not a UDP packet\n");
			}
		}
		else
		{
			printf("Not an IP packet\n");
		}	
		
	}
	else
	{
		printf("UDP Header not present \n");

	} 
}



//******************************************
ParseICMPHeader(unsigned char *packet , int len)
{
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	struct icmphdr *icmp_header;

	/* Check if enough bytes are there for TCP Header */

	if(len >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr)))
	{
		/* Do all the checks: 1. Is it an IP pkt ? 2. is it ICMP ? */
		
		ethernet_header = (struct ethhdr *)packet;

		if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
		{
			ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));


			if(ip_header->protocol == IPPROTO_ICMP)
			{
			     printf("----------------------------egment (ICMP protocol num=%d)\n",ip_header->protocol);						
				icmp_header = (struct icmphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4 );

                                printf("Type: %d\n", ntohs(icmp_header->type));
				printf("Code: %d\n", ntohs(icmp_header->code));				

			}
			else
			{
				printf("Not a ICMP packet\n");
			}
		}
		else
		{
			printf("Not an IP packet\n");
		}	
		
	}
	else
	{
		printf("ICMP Header not present \n");

	} 
}//***********************************
 //*



ParseArpHeader(unsigned char *packet, int len)
{
	struct ethhdr *ethernet_header;
	struct arphdr *arp_header;
	

	/* First Check if the packet contains an IP header using
	   the Ethernet header                                */

	ethernet_header = (struct ethhdr *)packet;

	if(ntohs(ethernet_header->h_proto) == ETH_P_ARP)
	{
		/* The IP header is after the Ethernet header  */
		
		if(len >= (sizeof(struct ethhdr) + sizeof(struct arphdr)))
		{
			arp_header = (struct arphdr*)(packet + sizeof(struct ethhdr));
			
			/* print the Source and Destination IP address */
		//	printf("TTL: %d \n",arp_header->ttl);
		printf("Hardware type: %s\n", inet_ntoa( *(struct in_addr*)&arp_header->ar_hrd));
		printf("Protocol type: %s\n", inet_ntoa( *(struct in_addr*)&arp_header->ar_pro));
	        printf("Protocol length %s\n", inet_ntoa( *(struct in_addr*)&arp_header->ar_pln));
		printf("Hardware length %s\n", inet_ntoa( *(struct in_addr*)&arp_header->ar_hln));

		}
		else
		{
			printf("ARP packet does not have full header\n");
		}

	}
	else
	{
		/* Not an IP packet */

	}
}
//********************************
main(int argc, char **argv)
{
	int raw;
	unsigned char packet_buffer[2048]; 
	int len;
	int packets_to_sniff;
	struct sockaddr_ll packet_info;
	int packet_info_size = sizeof(packet_info);

	if (argc < 3 )
	{
		printf("--------------------------------------------------\n");
		printf("Usage: ./sniffer <Interface> <Nbr of packets to sniff>\n");
		printf("--------------------------------------------------\n");
		return (EINVAL);
	}

	/* create the raw socket */

	raw = CreateRawSocket(ETH_P_ARP);

	/* Bind socket to interface */

	BindRawSocketToInterface(argv[1], raw, ETH_P_ARP);

	/* Get number of packets to sniff from user */

	packets_to_sniff = atoi(argv[2]);

	/* Start Sniffing and print Hex of every packet */
	
	while(packets_to_sniff--)
	{
		if((len = recvfrom(raw, packet_buffer, 2048, 0, (struct sockaddr*)&packet_info, (socklen_t*)&packet_info_size)) == -1)
		{
			perror("Recv from returned -1: ");
			exit(-1);
		}
		else
		{
			/* Packet has been received successfully !! */

		//	PrintPacketInHex(packet_buffer, len);

			/*Parse Ethernet Header */
			
		//	ParseEthernetHeader(packet_buffer, len);
			
			/* Parse IP Header */

			ParseArpHeader(packet_buffer, len);
		//
//		ParseICMPHeader(packet_buffer, len);

			/* Parse TCP Header */

	//	ParseTcpHeader(packet_buffer, len);
			/* Parse UDP Header */

	//		ParseUdpHeader(packet_buffer, len);

			//ICMP:
		//	ParseIcmpHeader(packet_buffer, len);
			
	//		if(IsIpAndTcpPacket(packet_buffer, len))
	//		{
	//			if(!ParseData(packet_buffer, len))
	//				packets_to_sniff++;
	//		}		
		}
	}
	return 0;
}

	
