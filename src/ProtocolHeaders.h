//
//  ProtocolHeaders.h
//  IPSpoofer
//
//  Created by Alexander Perechnev on 15.09.13.
//  Copyright (c) 2013 Alexander Perechnev. All rights reserved.
//

#ifndef IPSpoofer_ProtocolHeaders_h
#define IPSpoofer_ProtocolHeaders_h

#define PACKET_LENGTH 8192

/*
 * IP header structure
 */
struct IPHeader {
    unsigned char   iph_ihl: 4,
iph_ver: 4;
    unsigned char   iph_tos;
    uint16_t        iph_len;
    uint16_t        iph_ident;
    unsigned char   iph_flags;
    unsigned char   iph_offset;
    unsigned char   iph_ttl;
    unsigned char   iph_protocol;
    uint16_t        iph_chksum;
    uint32_t        iph_sourceip;
    uint32_t        iph_destip;
};

/*
 * TCP header structure
 */
struct TCPHeader {
	uint16_t	tcph_srcport;
	uint16_t	tcph_destport;
	uint32_t	tcph_seqnum;
	uint32_t	tcph_acknum;
	unsigned char	tcph_reserved: 4,
                tcph_offset: 4;
	unsigned char	tcph_fin: 1,       // Finish flag "fin"
                    tcph_syn: 1,       // Synchronize sequence numbers to start a connection
                    tcph_rst: 1,       // Reset flag
                    tcph_psh: 1,       // Push, sends data to the application
                    tcph_ack: 1,       // acknowledge
                    tcph_urg: 1,
                    tcph_reser: 2;
	uint16_t	tcph_win;
	uint16_t	tcph_chksum;
	uint16_t	tcph_urgptr;
};

/*
 * UDP header structure
 */
struct UDPHeader {
	uint16_t	udph_srcport;
	uint16_t	udph_destport;
    uint16_t    udph_len;
	uint16_t	udph_chksum;
};

/*
 * DNS header structure
 */
struct DNSHeader {
	uint16_t    dnsh_identification;
	uint16_t
dnsh_recursion: 1,
dnsh_truncated: 1,
dnsh_res1: 1,
dnsh_opcode: 4,
dnsh_response: 1,
dnsh_res3: 4,
dnsh_nonauth: 1,
dnsh_res2: 3;
	uint16_t    dnsh_questions;
	uint16_t    dnsh_answerRRs;
	uint16_t    dnsh_authorityRRs;
	uint16_t    dnsh_additionalRRs;
};

struct DNSQuery {
    char dnsq_name[6]; // 4 arpa 0
    uint16_t dnsq_type;
    uint16_t dnsq_class;
};

#endif
