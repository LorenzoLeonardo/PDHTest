#ifndef HAVE_REMOTE
#define HAVE_REMOTE
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef WIN32
#define WIN32
#endif

#include <conio.h>
#include <stdio.h>
#include "pcap.h"
#include <winsock2.h>
#include <math.h>

#pragma comment(lib,"Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

/* 4 bytes IP address */
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header {
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header {
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

int ForUDP()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;
    char packet_filter[] = "ip and udp";
    struct bpf_program fcode;

    /* Retrieve the device list */
    if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf_s("%d", &inum);

    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    /* Open the adapter */
    if ((adhandle = pcap_open(d->name,  // name of the device
        65536,     // portion of the packet to capture. 
                   // 65536 grants that the whole packet will be captured on all the MACs.
        PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
        1000,      // read timeout
        NULL,      // remote authentication
        errbuf     // error buffer
    )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Check the link layer. We support only Ethernet for simplicity. */
    if (pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    if (d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask = 0xffffff;


    //compile the filter
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    //set the filter
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr, "\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    return 0;
}

#define LINE_LEN 16

int main(int argc, char** argv)
{
    pcap_if_t* alldevs, * d;
    pcap_t* fp;
    u_int inum, i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;
    struct pcap_pkthdr* header;
    const u_char* pkt_data;

    printf("pktdump_ex: prints the packets of the network using WinPcap.\n");
    printf("   Usage: pktdump_ex [-s source]\n\n"
        "   Examples:\n"
        "      pktdump_ex -s file://c:/temp/file.acp\n"
        "      pktdump_ex -s rpcap://\\Device\\NPF_{C8736017-F3C3-4373-94AC-9A34B7DAD998}\n\n");

    if (argc < 3)
    {

        printf("\nNo adapter selected: printing the device list:\n");
        /* The user didn't provide a packet source: Retrieve the local device list */
        if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
        {
            fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
            return -1;
        }

        /* Print the list */
        for (d = alldevs; d; d = d->next)
        {
            printf("%d. %s\n    ", ++i, d->name);

            if (d->description)
                printf(" (%s)\n", d->description);
            else
                printf(" (No description available)\n");
        }

        if (i == 0)
        {
            fprintf(stderr, "No interfaces found! Exiting.\n");
            return -1;
        }

        printf("Enter the interface number (1-%d):", i);
        scanf_s("%d", &inum);

        if (inum < 1 || inum > i)
        {
            printf("\nInterface number out of range.\n");

            /* Free the device list */
            pcap_freealldevs(alldevs);
            return -1;
        }

        /* Jump to the selected adapter */
        for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

        /* Open the device */
        if ((fp = pcap_open(d->name,
            100 /*snaplen*/,
            PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
            20 /*read timeout*/,
            NULL /* remote authentication */,
            errbuf)
            ) == NULL)
        {
            fprintf(stderr, "\nError opening adapter\n");
            return -1;
        }
    }
    else
    {
        // Do not check for the switch type ('-s')
        if ((fp = pcap_open(argv[2],
            100 /*snaplen*/,
            PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
            20 /*read timeout*/,
            NULL /* remote authentication */,
            errbuf)
            ) == NULL)
        {
            fprintf(stderr, "\nError opening source: %s\n", errbuf);
            return -1;
        }
    }

    /* Read the packets */
    while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
    {

        if (res == 0)
            /* Timeout elapsed */
            continue;

        /* print pkt timestamp and pkt len */
        printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

        /* Print the packet */
        for (i = 1; (i < header->caplen + 1); i++)
        {
            printf("%.2x ", pkt_data[i - 1]);
            if ((i % LINE_LEN) == 0) printf("\n");
        }

        printf("\n\n");
    }

    if (res == -1)
    {
        fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(fp));
        return -1;
    }

    return 0;
}
int nTotal = 0;
long  ntimeBefore = 0, ntimeCurrent = 0, nDIfference = 0;
/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
    struct tm ltime;
    char timestr[16];
    ip_header* ih;
    udp_header* uh;
    u_int ip_len;
    u_short sport, dport;
    time_t local_tv_sec;

    /*
     * Unused variable
     */
    (VOID)(param);
    /* retireve the position of the ip header */
    ih = (ip_header*)(pkt_data +
        14); //length of ethernet header

    if ((ih->saddr.byte1 == 192 && ih->saddr.byte2 == 168 && ih->saddr.byte3 == 0 && ih->saddr.byte4 ==101))
    {
    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
  

    /* print timestamp and length of the packet */
    printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

    ntimeCurrent = ltime.tm_sec;
    nTotal += header->len;

    nDIfference = ntimeCurrent - ntimeBefore;
    if (nDIfference < 0)
    {
        nDIfference = 60 - (ntimeBefore + ntimeCurrent);
    }

       
   //     printf("TIME DIFERENCE : %d TOTAL LEN: %d RATE : %f\n", nDIfference, nTotal,(float)nTotal/ nDIfference);
    if (nDIfference >= 1)
    {
        nTotal = 0;
        ntimeBefore = ntimeCurrent;
    }
    /* retireve the position of the udp header */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header*)((u_char*)ih + ip_len);

    /* convert from network byte order to host byte order */
    sport = ntohs(uh->sport);
    dport = ntohs(uh->dport);

    /* print ip addresses and udp ports */

        printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
            ih->saddr.byte1,
            ih->saddr.byte2,
            ih->saddr.byte3,
            ih->saddr.byte4,
            sport,
            ih->daddr.byte1,
            ih->daddr.byte2,
            ih->daddr.byte3,
            ih->daddr.byte4,
            dport);
    }
}


/*int main(int argc, char* argv[])
{
    PDH_STATUS           pdhStatus = ERROR_SUCCESS;
    LPTSTR               szCounterListBuffer = NULL;
    DWORD                dwCounterListSize = 0;
    LPTSTR               szInstanceListBuffer = NULL;
    DWORD                dwInstanceListSize = 0;
    HQUERY               hQuery;
    HCOUNTER             hCounter;
    DWORD                dwType = 0;
    PDH_FMT_COUNTERVALUE value;
    char                 szCounter[256] = { 0 };

    pdhStatus = PdhEnumObjectItems(NULL, NULL,
        "Network Interface",
        szCounterListBuffer,
        &dwCounterListSize,
        szInstanceListBuffer,
        &dwInstanceListSize,
        PERF_DETAIL_WIZARD,
        0);

    szCounterListBuffer = (LPTSTR)malloc((dwCounterListSize * sizeof(char)));
    szInstanceListBuffer = (LPTSTR)malloc((dwInstanceListSize * sizeof(char)));

    if (!szCounterListBuffer || !szInstanceListBuffer)
    {
        printf("unable to allocate buffer\n");
        return 1;
    }

    pdhStatus = PdhEnumObjectItems(NULL, NULL,
        "Network Interface",
        szCounterListBuffer,
        &dwCounterListSize,
        szInstanceListBuffer,
        &dwInstanceListSize,
        PERF_DETAIL_WIZARD,
        0);

    if (pdhStatus == ERROR_SUCCESS)
    {
        sprintf_s(szCounter,sizeof(szCounter), "\\Network Interface(%s)\\Current Bandwidth", szInstanceListBuffer);

    }
    else
    {
        printf("unable to allocate buffer\n");
        return 1;
    }

    if (PdhOpenQuery(NULL, 0, &hQuery))
    {
        printf("PdhOpenQuery failed\n");
        return 1;
    }

    if (PdhAddCounter(hQuery, szCounter, NULL, &hCounter))
    {
        printf("PdhAddCounter failed\n");
        return 1;
    }

    PDH_STATUS Status = PdhCollectQueryData(hQuery);
    if (Status != ERROR_SUCCESS)
    {
        wprintf(L"\nPdhCollectQueryData failed with 0x%x.\n", Status);
        return 1;
    }

    while (!_kbhit())
    {
        if (PdhCollectQueryData(hQuery))
        {
            printf("PdhCollectQueryData failed\n");
            break;
        }

        if (PdhGetFormattedCounterValue(hCounter, PDH_FMT_LONG, &dwType, &value))
        {
            printf("PdhGetFormattedCounterValue failed\n");
            break;
        }

        printf("Current Bandwidth : %llu\r", value.largeValue);
        Sleep(1000);
    }

    if (szCounterListBuffer != NULL)
        free(szCounterListBuffer);

    if (szInstanceListBuffer != NULL)
        free(szInstanceListBuffer);

    PdhRemoveCounter(hCounter);
    PdhCloseQuery(hQuery);

    return 0;
}*/