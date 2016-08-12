#include <winsock2.h>		
#include <stdio.h>			
#include <string.h>			
#include <windivert.h>		

#define MAX_BUF  0xFFFF			
#define HTTP_OFFSET 54

typedef struct iptcp_hdr		
{
	WINDIVERT_IPHDR ip;			
	WINDIVERT_TCPHDR tcp;	
} TCPPACKET, *PTCPPACKET;

typedef struct ip6tcp_hdr		
{
	WINDIVERT_IPV6HDR ipv6;		
	WINDIVERT_TCPHDR tcp;		
} TCPV6PACKET, *PTCPV6PACKET;

typedef struct ipicmp_hdr		
{
	WINDIVERT_IPHDR ip;			
	WINDIVERT_ICMPHDR icmp;		
	UINT8 data[];				
} ICMPPACKET, *PICMPPACKET;

typedef struct ipicmp6_hdr		
{								
	WINDIVERT_IPV6HDR ipv6;
	WINDIVERT_ICMPV6HDR icmpv6;
	UINT8 data[];
} ICMPV6PACKET, *PICMPV6PACKET;


void PacketIpInit(PWINDIVERT_IPHDR packet)		
{												
	memset(packet, 0, sizeof(WINDIVERT_IPHDR));
	packet->Version = 4;						
	packet->HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->Id = ntohs(0xDEAD);					
	packet->TTL = 64;							
}

void PacketIpTcpInit(PTCPPACKET packet)
{
	memset(packet, 0, sizeof(TCPPACKET));
	PacketIpInit(&packet->ip);
	packet->ip.Length = htons(sizeof(TCPPACKET));
	packet->ip.Protocol = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}


void PacketIpIcmpInit(PICMPPACKET packet)
{
	memset(packet, 0, sizeof(ICMPPACKET));
	PacketIpInit(&packet->ip);
	packet->ip.Protocol = IPPROTO_ICMP;
}


void PacketIpv6Init(PWINDIVERT_IPV6HDR packet)
{
	memset(packet, 0, sizeof(WINDIVERT_IPV6HDR));
	packet->Version = 6;
	packet->HopLimit = 64;
}


void PacketIpv6TcpInit(PTCPV6PACKET packet)
{
	memset(packet, 0, sizeof(TCPV6PACKET));
	PacketIpv6Init(&packet->ipv6);
	packet->ipv6.Length = htons(sizeof(WINDIVERT_TCPHDR));
	packet->ipv6.NextHdr = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

void PacketIpv6Icmpv6Init(PICMPV6PACKET packet)
{
	memset(packet, 0, sizeof(ICMPV6PACKET));
	PacketIpv6Init(&packet->ipv6);
	packet->ipv6.NextHdr = IPPROTO_ICMPV6;
}

void newstrcpy(unsigned char *dst, unsigned char *src)
{
	int base = 0;
	if (!src || !dst) exit(1);
	while ((*(src + base) != 13)) {
		*(dst + base) = *(src + base);
		base++;

	}
	*(dst + base) = '\n';
	*(dst + base) = '\0';
}


char *newstrstr(unsigned char *str1, char *str2)
{
	char *cp = (char *)str1;
	char *s1, *s2;
	if (!*str2) return (char *)str1;
	while (*cp)
	{
		s1 = cp;
		s2 = (char *)str2;
		while (*s1 && *s2 && !(*s1 - *s2)) s1++, s2++;
		if (!*s2) return cp;
		cp++;
	}
}

int __cdecl main(int argc, char **argv)
{
	HANDLE handle, console;
	UINT i;
	INT16 priority = 0;
	unsigned char packet[MAX_BUF];
	unsigned char site[100];
	char buf[1024] = { 0, };
	FILE *Log;
	FILE *Malsite_list;
	UINT packet_len;
	WINDIVERT_ADDRESS recv_addr, send_addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	UINT payload_len;
	TCPPACKET reset0;
	PTCPPACKET reset = &reset0;
	unsigned char *tcppacket;
	bool malsite_check = false;


	PacketIpTcpInit(reset);
	reset->tcp.Rst = 1;
	reset->tcp.Ack = 1;


	handle = WinDivertOpen("Outbound Packet of TCP Payload_Length > 0 && TCP_Dport == 80", WINDIVERT_LAYER_NETWORK, 0, 0);

	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}


	while (TRUE)
	{
		malsite_check = false;						
		Log = fopen("log.txt", "a+");				
		Malsite_list = fopen("mal_site.txt", "r");			
														
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr, &packet_len))		
		{																					
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}

		WinDivertHelperParsePacket(packet, packet_len, &ip_header,			
			&ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,		
			&udp_header, NULL, &payload_len);							
		if (ip_header == NULL && ipv6_header == NULL) continue;				
		tcppacket = (unsigned char*)malloc(packet_len);						
		memcpy(tcppacket, packet, packet_len);								

																			
		for (int i = HTTP_OFFSET; i < packet_len; i++)	
		{
			if (tcppacket[i] == 'H' && tcppacket[i + 1] == 'o' && tcppacket[i + 2] == 's' && tcppacket[i + 3] == 't')	
			{																											
				newstrcpy(site, tcppacket + i + 5);			
				break;
			}
		}


		while (!feof(Malsite_list))		
		{

			fgets(buf, 1024, Malsite_list);		
			for (int i = 0; i < sizeof(buf); i++)
			{
				if (buf[i] == 10)					
				{
					buf[i] = 0;
					break;
				}
			}
			if (newstrstr(site, buf))					
			{										
				UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;		
				UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;		
				printf("The harmful site : %s\nSrc IP : %u.%u.%u.%u\nDst IP : %u.%u.%u.%u\n", buf,
					src_addr[0], src_addr[1], src_addr[2], src_addr[3],	
					dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
				fprintf(Log, "The harmful site : %s\nSrc IP : %u.%u.%u.%u\nDst IP : %u.%u.%u.%u\n", buf,
					src_addr[0], src_addr[1], src_addr[2], src_addr[3],		
					dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
				fclose(Log);
				malsite_check = true;
				break;
			}
		}
		if (malsite_check == true)
		{	
			continue;
		}
		else
		{	
			WinDivertSend(handle, (PVOID)packet, sizeof(packet), &send_addr, NULL);
		}
		putchar('\n');
	}
	return 1;
}
