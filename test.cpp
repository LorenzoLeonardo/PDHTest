
// Module Name: Ping.c
//
// Description:
//    This sample illustrates how an ICMP ping app can be written
//    using the SOCK_RAW socket type and IPPROTO_ICMP protocol.
//    By creating a raw socket, the underlying layer does not change
//    the protocol header so that when we submit the ICMP header
//    nothing is changed so that the receiving end will see an
//    ICMP packet. Additionally, we use the record route IP option
//    to get a round trip path to the endpoint. Note that the size
//    of the IP option header that records the route is limited to
//    nine IP addresses.
//
// Compile:
//     cl -o Ping Ping.c ws2_32.lib /Zp1
//
// Command Line Options/Parameters:
//     Ping [host] [packet-size]
//
//     host         String name of host to ping
//     packet-size  Integer size of packet to send
//                      (smaller than 1024 bytes)
//
//#pragma pack(1)

#define WIN32_LEAN_AND_MEAN

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "Ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <process.h>

using namespace std;

#define IP_RECORD_ROUTE  0x7
//
// IP header structure
//
typedef struct _tIPV4HDR
{
	UCHAR ucIPHeaderLen : 4;
	UCHAR ucIPVersion : 4;
	UCHAR ucIPTos;
	USHORT usIPTotalLength;
	USHORT usIPID;
	UCHAR ucIPFragOffset : 5;
	UCHAR ucIPMoreFragment : 1;
	UCHAR ucIPDontFragment : 1;
	UCHAR ucIPReservedZero : 1;
	UCHAR ucIPFragOffset1;
	UCHAR ucIPTTL;
	UCHAR ucIPProtocol;
	USHORT usIPChecksum;
	UINT unSrcaddress;
	UINT unDestaddress;
} IPV4_HDR;

#define ICMP_ECHO        8
#define ICMP_ECHOREPLY   0
#define ICMP_MIN         8 // Minimum 8-byte ICMP packet (header)

//
// ICMP header structure
//
typedef struct _tICMPHDR
{
	BYTE byType;
	BYTE byCode;
	USHORT checksum;
	USHORT id;
	USHORT seq;
	ULONG  timestamp;
} ICMP_HDR;

//
// IP option header - use with socket option IP_OPTIONS
//
typedef struct _ipoptionhdr
{
	unsigned char        code;        // Option type
	unsigned char        len;         // Length of option hdr
	unsigned char        ptr;         // Offset into options
	unsigned long        addr[9];     // List of IP addrs
} IpOptionHeader;

#define DEF_PACKET_SIZE  32        // Default packet size
#define MAX_PACKET       65535      // Max ICMP packet size
#define MAX_IP_HDR_SIZE  60        // Max IP header size w/options

BOOL  bRecordRoute;
int   datasize;
char* lpdest;

//
// Function: usage
//
// Description:
//    Print usage information
//
void usage(char* progname)
{
	printf("usage: ping -r  [data size]\n");
	printf("       -r           record route\n");
	printf("        host        remote machine to ping\n");
	printf("        datasize    can be up to 1KB\n");
	ExitProcess(-1);
}

//
// Function: FillICMPData
//
// Description:
//    Helper function to fill in various fields for our ICMP request
//
void FillICMPData(char* icmp_data, int datasize)
{
	ICMP_HDR* icmp_hdr = NULL;
	char* datapart = NULL;

	icmp_hdr = (ICMP_HDR*)icmp_data;
	icmp_hdr->byType = ICMP_ECHO;        // Request an ICMP echo
	icmp_hdr->byCode = 0;
	icmp_hdr->id = (USHORT)GetCurrentProcessId();
	icmp_hdr->checksum = 0;
	icmp_hdr->seq = 0;

	datapart = icmp_data + sizeof(ICMP_HDR);
	//
	// Place some junk in the buffer
	//
	memset(datapart, 'E', datasize - sizeof(ICMP_HDR));
}

//
// Function: checksum
//
// Description:
//    This function calculates the 16-bit one's complement sum
//    of the supplied buffer (ICMP) header
//
USHORT checksum(USHORT* buffer, int size)
{
	unsigned long cksum = 0;

	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}

//
// Function: DecodeIPOptions
//
// Description:
//    If the IP option header is present, find the IP options
//    within the IP header and print the record route option
//    values
//
void DecodeIPOptions(char* buf, int bytes)
{
	IpOptionHeader* ipopt = NULL;
	IN_ADDR         inaddr;
	int             i;
	HOSTENT* host = NULL;

	ipopt = (IpOptionHeader*)(buf + 20);

	printf("RR:   ");
	for (i = 0; i < (ipopt->ptr / 4) - 1; i++)
	{
		inaddr.S_un.S_addr = ipopt->addr[i];
		if (i != 0)
			printf("      ");
		host = gethostbyaddr((char*)&inaddr.S_un.S_addr,
			sizeof(inaddr.S_un.S_addr), AF_INET);
		if (host)
			printf("(%-15s) %s\n", inet_ntoa(inaddr), host->h_name);
		else
			printf("(%-15s)\n", inet_ntoa(inaddr));
	}
	return;
}

//
// Function: DecodeICMPHeader
//
// Description:
//    The response is an IP packet. We must decode the IP header to
//    locate the ICMP data.
//
void DecodeICMPHeader(string ipAdd, char* buf, int bytes,
	struct sockaddr_in* from)
{
	IPV4_HDR* iphdr = NULL;
	ICMP_HDR* icmphdr = NULL;
	unsigned short  iphdrlen;
	DWORD           tick;
	static   int    icmpcount = 0;

	iphdr = (IPV4_HDR*)buf;
	// Number of 32-bit words * 4 = bytes
	iphdrlen = iphdr->ucIPHeaderLen * 4;
	tick = GetTickCount();

	if ((iphdrlen == MAX_IP_HDR_SIZE) && (!icmpcount))
		DecodeIPOptions(buf, bytes);

	if (bytes < iphdrlen + ICMP_MIN) {
		printf("Too few bytes from %s\n", inet_ntoa(from->sin_addr));
	}
	icmphdr = (ICMP_HDR*)(buf + iphdrlen);

	if (icmphdr->byType != ICMP_ECHOREPLY)
	{
		printf("%s: nonecho type %d recvd\n", ipAdd.c_str(), icmphdr->byType);
		return;
	}
	// Make sure this is an ICMP reply to something we sent!
	//
	if (icmphdr->id != (USHORT)GetCurrentProcessId())
	{
		printf("someone else's packet!\n");
		return;
	}
	printf("%s: %d bytes received", ipAdd.c_str(), bytes);
	printf(" icmp_seq = %d. ", icmphdr->seq);
	printf(" time: %d ms", tick - icmphdr->timestamp);
	printf("\n");

	icmpcount++;
	return;
}

void ValidateArgs(int argc, char** argv)
{
	int                i;

	bRecordRoute = FALSE;
	lpdest = NULL;
	datasize = DEF_PACKET_SIZE;

	for (i = 1; i < argc; i++) {
		if ((argv[i][0] == '-') || (argv[i][0] == '/')) {
			switch (tolower(argv[i][1])) {
			case 'r': // Record route option 
				bRecordRoute = TRUE;
				break;
			default:
				usage(argv[0]); break;
			}
		}
		else if (isdigit(argv[i][0]))
			datasize = atoi(argv[i]);
		else lpdest = argv[i];
	}
}

unsigned __stdcall SecondThreadFunc(void* pArguments)
{
	printf("In second thread...\n");

	_endthreadex(0);
	return 0;
}

// 
// Function: main 
// 
// Description: 
// Setup the ICMP raw socket, and create the ICMP header. Add 
// the appropriate IP option header, and start sending ICMP 
// echo requests to the endpoint. For each send and receive, 
// we set a timeout value so that we don't wait forever for a 
// response in case the endpoint is not responding. When we 
// receive a packet decode it. 
// 
int main(int argc, char** argv) {
	WSADATA wsaData;
	SOCKET sockRaw = INVALID_SOCKET;
	struct sockaddr_in dest, from;
	int bread, fromlen = sizeof(from), timeout = 1000, ret;
	char* icmp_data = NULL, * recvbuf = NULL;
	unsigned int addr = 0;
	USHORT seq_no = 0;
	struct hostent* hp = NULL;
	IpOptionHeader ipopt;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("WSAStartup() failed: %d\n", GetLastError());
		return -1;
	}
	string inPut;

	icmp_data = (char*)malloc(MAX_PACKET);
	recvbuf = (char*)malloc(MAX_PACKET);
	if (!icmp_data)
	{
		printf("HeapAlloc() failed: %d\n", GetLastError());
		return -1;
	}

	sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (sockRaw == INVALID_SOCKET) {
		printf("WSASocket() failed: %d\n", WSAGetLastError());
		return -1;
	}

	for (int i = 100; i < 255; i++)
	{
		memset(icmp_data, 0, MAX_PACKET);
		memset(recvbuf, 0, MAX_PACKET);

		inPut = "192.168.0." + to_string(i);
		lpdest = (char*)inPut.c_str();
		//ValidateArgs(argc, argv);
		// 
		// WSA_FLAG_OVERLAPPED flag is required for SO_RCVTIMEO, 
		// SO_SNDTIMEO option. If NULL is used as last param for 
		// WSASocket, all I/O on the socket is synchronous, the 
		// internal user mode wait code never gets a chance to 
		// execute, and therefore kernel-mode I/O blocks forever. 
		// A socket created via the socket function has the over- 
		// lapped I/O attribute set internally. But here we need
		// to use WSASocket to specify a raw socket. 
		// 
		// If you want to use timeout with a synchronous 
		// nonoverlapped socket created by WSASocket with last 
		// param set to NULL, you can set the timeout by using 
		// the select function, or you can use WSAEventSelect and 
		// set the timeout in the WSAWaitForMultipleEvents 
		// function. 
		// 

		if (bRecordRoute) {
			// Setup the IP option header to go out on every ICMP packet 
			// 
			ZeroMemory(&ipopt, sizeof(ipopt));
			ipopt.code = IP_RECORD_ROUTE;
			// Record route option 
			ipopt.ptr = 4;
			// Point to the first addr offset 
			ipopt.len = 39;
			// Length of option header 
			ret = setsockopt(sockRaw, IPPROTO_IP, IP_OPTIONS, (char*)&ipopt, sizeof(ipopt));
			if (ret == SOCKET_ERROR) {
				printf("setsockopt(IP_OPTIONS) failed: %d\n", WSAGetLastError());
			}
		}
		// Set the send/recv timeout values 
		// 
		bread = setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
		if (bread == SOCKET_ERROR)
		{
			printf("setsockopt(SO_RCVTIMEO) failed: %d\n", WSAGetLastError());
			return -1;
		}
		timeout = 1000;
		bread = setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
		if (bread == SOCKET_ERROR)
		{
			printf("setsockopt(SO_SNDTIMEO) failed: %d\n", WSAGetLastError());
			return -1;
		}
		memset(&dest, 0, sizeof(dest));

		// 
		// Resolve the endpoint's name if necessary 
		// 
		dest.sin_family = AF_INET;
		if ((dest.sin_addr.s_addr = inet_addr(lpdest)) == INADDR_NONE)
		{
			if ((hp = gethostbyname(lpdest)) != NULL)
			{
				memcpy(&(dest.sin_addr), hp->h_addr, hp->h_length);
				dest.sin_family = hp->h_addrtype;
				printf("dest.sin_addr = %s\n", inet_ntoa(dest.sin_addr));
			}
			else
			{
				printf("gethostbyname() failed: %d\n",
					WSAGetLastError());
				return -1;
			}
		}

		//
		// Create the ICMP packet
		//
		datasize += sizeof(ICMP_HDR);



		FillICMPData(icmp_data, datasize);
		//
		// Start sending/receiving ICMP packets
		//
		//while (1)
		//{
		//	static int nCount = 0;
		int        bwrote;

		//if (nCount++ == 4)
		//	break;

		((ICMP_HDR*)icmp_data)->checksum = 0;
		((ICMP_HDR*)icmp_data)->timestamp = GetTickCount();
		((ICMP_HDR*)icmp_data)->seq = 0;//seq_no++;
		((ICMP_HDR*)icmp_data)->checksum =
			checksum((USHORT*)icmp_data, datasize);

		bwrote = sendto(sockRaw, icmp_data, datasize, 0,
			(struct sockaddr*)&dest, sizeof(dest));
		if (bwrote == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAETIMEDOUT)
			{
				printf("%s: timed out\n", inPut.c_str());
				continue;
			}
			printf("sendto() failed: %d\n", WSAGetLastError());
			continue;
		}
		if (bwrote < datasize)
		{
			printf("Wrote %d bytes\n", bwrote);
		}
		bread = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0,
			(struct sockaddr*)&from, &fromlen);
		if (bread == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAETIMEDOUT)
			{
				printf("%s: timed out\n", inPut.c_str());
				continue;
			}
			printf("recvfrom() failed: %d\n", WSAGetLastError());
			continue;
		}
		DecodeICMPHeader(inPut, recvbuf, bread, &from);

		//	Sleep(1000);
		//}
		// Cleanup
		//

	
	}
	if (sockRaw != INVALID_SOCKET)
		closesocket(sockRaw);

	free(recvbuf);
	free(icmp_data);
	WSACleanup();
	return 0;
}