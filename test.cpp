
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
#include <mutex>
#include <map>
#include <thread>
#include <conio.h>
using namespace std;
mutex mtx;
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

map<thread*, int> m_mapThreads;
//
// ICMP header structure
//
typedef struct _tICMPHDR
{
	BYTE byType;
	BYTE byCode;
	USHORT checksum;
	USHORT usID;
	USHORT usSeq;
	ULONG  ulTimeStamp;
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
#define MAX_PACKET       65536      // Max ICMP packet size
#define MAX_IP_HDR_SIZE  60        // Max IP header size w/options

BOOL  bRecordRoute;
int   datasize;


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
	icmp_hdr->byType = ICMP_ECHO;  
	icmp_hdr->byCode = 0;
	icmp_hdr->usID = (USHORT)GetCurrentProcessId();
	icmp_hdr->checksum = 0;
	icmp_hdr->usSeq = 0;

	datapart = icmp_data + sizeof(ICMP_HDR);

	memset(datapart, 'E', datasize - sizeof(ICMP_HDR));
}

//
// Function: checksum
//
// Description:
//    This function calculates the 16-bit one's complement sum
//    of the supplied buffer (ICMP) header
//
USHORT CheckSum(USHORT* buffer, int size)
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
	//	if (host)
	//		printf("(%-15s) %s\n", inet_ntoa(inaddr), host->h_name);
	//	else
	//		printf("(%-15s)\n", inet_ntoa(inaddr));
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
bool DecodeICMPHeader(USHORT usSeq, char* buf, int bytes, struct sockaddr_in* from)
{
	IPV4_HDR* iphdr = NULL;
	ICMP_HDR* icmphdr = NULL;
	unsigned short  iphdrlen;

	iphdr = (IPV4_HDR*)buf;
	// Number of 32-bit words * 4 = bytes
	iphdrlen = iphdr->ucIPHeaderLen * 4;

	if (bytes < iphdrlen + ICMP_MIN)
		return false;

	icmphdr = (ICMP_HDR*)(buf + iphdrlen);

	if (icmphdr->byType != ICMP_ECHOREPLY)
			return false;

	// Make sure this is an ICMP reply to something we sent!
	//
	if (icmphdr->usID != (USHORT)GetCurrentProcessId())
		return false;

	if (icmphdr->usSeq == usSeq)
		return true;

	return false;
}

void Callback(const char* IP, bool bFlag)
{
	if(bFlag)
		printf("%s is connected\n", IP);
//	else
//		printf("%s is disconnected\n", IP);
}

typedef void(*FNPtr)(const char*,bool);

FNPtr gPTR;


bool CheckDeviceEx(string ipAddress, string& hostname, string& sMacAddress)
{
	SOCKET sockRaw;
	const char* lpdest = ipAddress.c_str();
	char* icmp_data = NULL, * recvbuf = NULL;
	struct sockaddr_in dest, from;
	int iResult = 0, timeoutsend = 5000, timeoutrecv = 5000, fromlen = sizeof(from);
	struct hostent* hp = NULL;
	USHORT usSequenceNumber = atoi(ipAddress.substr(ipAddress.rfind('.', ipAddress.size()) + 1, ipAddress.size()).c_str());
	bool bRet = false;

	icmp_data = (char*)malloc(MAX_PACKET);
	if (!icmp_data)
		return bRet;
	memset((void*)icmp_data, 0, MAX_PACKET);
	
	recvbuf = (char*)malloc(MAX_PACKET);
	if (!recvbuf)
		return bRet;
	memset((void*)recvbuf, 0, MAX_PACKET);

	sockRaw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockRaw == INVALID_SOCKET)
		goto CLEANPUP;

	iResult = setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeoutsend, sizeof(timeoutsend));
	if (iResult == SOCKET_ERROR)
		goto CLEANPUP;

	iResult = setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeoutrecv, sizeof(timeoutrecv));
	if (iResult == SOCKET_ERROR)
		goto CLEANPUP;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	if ((dest.sin_addr.s_addr = inet_addr(lpdest)) == INADDR_NONE)
	{
		if ((hp = gethostbyname(lpdest)) != NULL)
		{
			memcpy(&(dest.sin_addr), hp->h_addr, hp->h_length);
			dest.sin_family = hp->h_addrtype;
		}
	}
	datasize += sizeof(ICMP_HDR);

	FillICMPData(icmp_data, datasize);

	((ICMP_HDR*)icmp_data)->byType = ICMP_ECHO;
	((ICMP_HDR*)icmp_data)->checksum = 0;
	((ICMP_HDR*)icmp_data)->ulTimeStamp = GetTickCount();
	((ICMP_HDR*)icmp_data)->usSeq = usSequenceNumber;
	((ICMP_HDR*)icmp_data)->checksum = CheckSum((USHORT*)icmp_data, datasize);

	iResult = sendto(sockRaw, icmp_data, datasize, 0,
		(struct sockaddr*)&dest, sizeof(dest));
	if (iResult == SOCKET_ERROR)
		goto CLEANPUP;

	iResult = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0, (struct sockaddr*)&from, &fromlen);
	if (iResult == SOCKET_ERROR)
		goto CLEANPUP;
	else
	{
		if (DecodeICMPHeader(usSequenceNumber, recvbuf, iResult, &from))
			bRet = true;
	}

CLEANPUP:
	if(sockRaw!=INVALID_SOCKET)
		closesocket(sockRaw);
	free(recvbuf);
	free(icmp_data);
	recvbuf = NULL;
	icmp_data = NULL;
	
	return bRet;
}
void SecondThreadFunc(void* pArguments)
{
	//SOCKET sockRaw;
	string hostname, macAddress;
	string ipAdd = *(string*)pArguments;
	if(CheckDeviceEx(ipAdd,hostname, macAddress))
		gPTR(ipAdd.c_str(), true);
/*	char* icmp_data = NULL, * recvbuf = NULL;
	
	struct sockaddr_in dest, from;
	int bread, fromlen = sizeof(from), timeoutsend = 5000, timeoutrecv= 5000;
	string* ipAddress = (string*)pArguments;
	const char* lpdest = ipAddress->c_str();
	USHORT usSequenceNumber = atoi(ipAddress->substr(ipAddress->rfind('.', ipAddress->size()) + 1, ipAddress->size()).c_str());
	int bwrote;
	unsigned int addr = 0;
	USHORT seq_no = 0;
	struct hostent* hp = NULL;


	icmp_data = (char*)malloc(MAX_PACKET);
	recvbuf = (char*)malloc(MAX_PACKET);
	memset((void*)icmp_data, 0, MAX_PACKET);
	memset((void*)recvbuf, 0, MAX_PACKET);

	if (!icmp_data)
		goto CLEANUP;

		
	sockRaw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockRaw == INVALID_SOCKET)
	{
		goto CLEANUP;
	}

	bread = setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeoutsend, sizeof(timeoutsend));
	if (bread == SOCKET_ERROR)
	{
		printf("setsockopt(SO_RCVTIMEO) failed: %d\n", WSAGetLastError());
		gPTR(lpdest, false);
		goto CLEANUP;
	}

	bread = setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeoutrecv, sizeof(timeoutrecv));
	if (bread == SOCKET_ERROR)
	{
		printf("setsockopt(SO_SNDTIMEO) failed: %d\n", WSAGetLastError());
		gPTR(lpdest, false);
		goto CLEANUP;
	}

	memset(&dest, 0, sizeof(dest));

	dest.sin_family = AF_INET;
	if ((dest.sin_addr.s_addr = inet_addr(lpdest)) == INADDR_NONE)
	{
		if ((hp = gethostbyname(lpdest)) != NULL)
		{
			memcpy(&(dest.sin_addr), hp->h_addr, hp->h_length);
			dest.sin_family = hp->h_addrtype;
		}
		else
		{
			goto CLEANUP;
		}
	}

	datasize += sizeof(ICMP_HDR);


	FillICMPData(icmp_data, datasize);


	((ICMP_HDR*)icmp_data)->byType = ICMP_ECHO;
	((ICMP_HDR*)icmp_data)->checksum = 0;
	((ICMP_HDR*)icmp_data)->ulTimeStamp = GetTickCount();
	((ICMP_HDR*)icmp_data)->usSeq = usSequenceNumber;//seq_no++;
	((ICMP_HDR*)icmp_data)->checksum =	CheckSum((USHORT*)icmp_data, datasize);

	//mtx.lock();


	bwrote = sendto(sockRaw, icmp_data, datasize, 0,
		(struct sockaddr*)&dest, sizeof(dest));
	if (bwrote == SOCKET_ERROR)
	{
		if (WSAGetLastError() == WSAETIMEDOUT)
		{
			printf("%s: timed out\n", ipAddress->c_str());
			gPTR(lpdest, false);
			goto CLEANUP;
		}
		printf("sendto() failed: %d\n", WSAGetLastError());
		gPTR(lpdest, false);
		goto CLEANUP;
	}

	bread = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0,	(struct sockaddr*)&from, &fromlen);

	if (bread == SOCKET_ERROR)
	{
		DWORD dwRet = WSAGetLastError();
		if (dwRet == WSAETIMEDOUT)
		{
	//		printf("%s: timed out\n", ipAddress.c_str());
			gPTR(lpdest, false);
			goto CLEANUP;
		}
		gPTR(lpdest, false);
		goto CLEANUP;
	}
	else
	{
		
		if (DecodeICMPHeader(usSequenceNumber, recvbuf, bread, &from))
			gPTR(lpdest, true);
		else
			gPTR(lpdest, false);
	}

CLEANUP:
	free(icmp_data);
	free(recvbuf);


	if (sockRaw != INVALID_SOCKET)
		closesocket(sockRaw);

	delete ipAddress;
	ipAddress = NULL;
	//mtx.unlock();*/
	return;
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

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("WSAStartup() failed: %d\n", GetLastError());
		return -1;
	}


	gPTR = Callback;
	//while(!_kbhit())
	//{
		for (int i = 1; i < 255; i++)
		{

			string* inPut = new string;
			*inPut = "192.168.0." + to_string(i);

			m_mapThreads[new thread(SecondThreadFunc, inPut)] = i;
		}
		map<thread*, int>::iterator it = m_mapThreads.begin();
		while (it != m_mapThreads.end())
		{
			it->first->join();
			it++;
		}
		it = m_mapThreads.begin();
		while (it != m_mapThreads.end())
		{
			delete it->first;
			it++;
		}
		m_mapThreads.clear();
	//	printf("SEARCHING DONE\n");
	//}

	WSACleanup();
	_getch();
	return 0;
}