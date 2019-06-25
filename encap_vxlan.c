#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define S_MAC_LEN	6

#define S_PRINT_SIZE( t ) \
	do { \
		printf( "sizeof( " #t " ): %zu\n", sizeof( t ) ); \
	} while ( 0 )

#define S_PRINT_STRUCT( t, f ) \
	do { \
		printf( #t "->" #f ": %zu\n", offsetof( t, f ) ); \
	} while ( 0 )

typedef struct s_eth_hdr {
	union {
		struct {
			u8	dmac[ S_MAC_LEN ];	/* 6byte */
			u8	smac[ S_MAC_LEN ];	/* 6byte */
		} __attribute__((packed));

		/* info for outer IP/UDP */
		struct {
			u32		daddr;	/* 4byte */
			u16		dport;	/* 2byte */
			u32		saddr;	/* 4byte */
			u16		sport;	/* 2byte */
		} __attribute__((packed));
	};
	u16		type;
} __attribute__((packed)) s_eth_hdr_t;

static void s_print_eth_hdr_size( void )
{
	S_PRINT_SIZE( s_eth_hdr_t );
	S_PRINT_STRUCT( s_eth_hdr_t, dmac );
	S_PRINT_STRUCT( s_eth_hdr_t, smac );
	S_PRINT_STRUCT( s_eth_hdr_t, daddr );
	S_PRINT_STRUCT( s_eth_hdr_t, dport );
	S_PRINT_STRUCT( s_eth_hdr_t, saddr );
	S_PRINT_STRUCT( s_eth_hdr_t, sport );
	S_PRINT_STRUCT( s_eth_hdr_t, type );
	return;
}

#define S_IP_VER_IHL	(( 4 << 4 ) + ( 20 >> 2 ))
#define S_IP_FLG_OFF	(htons( ( 0x02 << 13 ) + 0 ))
#define S_IP_TTL		64

typedef struct s_ip_hdr {
	u8		ver_ihl;
	u8		tos;
	u16		totlen;
	u16		id;
	u16		flg_off;
	u8		ttl;
	u8		proto;
	u16		cksum;
	u32		saddr;
	u32		daddr;
} s_ip_hdr_t;

static void s_print_ip_hdr_size( void )
{
	S_PRINT_SIZE( s_ip_hdr_t );
	S_PRINT_STRUCT( s_ip_hdr_t, ver_ihl );
	S_PRINT_STRUCT( s_ip_hdr_t, tos );
	S_PRINT_STRUCT( s_ip_hdr_t, totlen );
	S_PRINT_STRUCT( s_ip_hdr_t, id );
	S_PRINT_STRUCT( s_ip_hdr_t, flg_off );
	S_PRINT_STRUCT( s_ip_hdr_t, ttl );
	S_PRINT_STRUCT( s_ip_hdr_t, proto );
	S_PRINT_STRUCT( s_ip_hdr_t, cksum );
	S_PRINT_STRUCT( s_ip_hdr_t, saddr );
	S_PRINT_STRUCT( s_ip_hdr_t, daddr );
	return;
}

#define S_UDP_DPORT	4789

typedef struct s_udp_hdr {
	u16		sport;
	u16		dport;
	u16		len;
	u16		cksum;
} s_udp_hdr_t;

static void s_print_udp_hdr_size( void )
{
	S_PRINT_SIZE( s_udp_hdr_t );
	S_PRINT_STRUCT( s_udp_hdr_t, sport );
	S_PRINT_STRUCT( s_udp_hdr_t, dport );
	S_PRINT_STRUCT( s_udp_hdr_t, len );
	S_PRINT_STRUCT( s_udp_hdr_t, cksum );
	return;
}

#define S_VXLAN_RSVD		(1 << 27)
#define S_VXLAN_VNI_RSVD	(1234 << 8)

typedef struct s_vxlan_hdr {
	u32		rsvd;
	u32		vni_rsvd;
} s_vxlan_hdr_t;

static void s_print_vxlan_hdr_size( void )
{
	S_PRINT_SIZE( s_vxlan_hdr_t );
	S_PRINT_STRUCT( s_vxlan_hdr_t, rsvd );
	S_PRINT_STRUCT( s_vxlan_hdr_t, vni_rsvd );
	return;
}

typedef struct s_outer_hdr {
	s_eth_hdr_t		eth;
	s_ip_hdr_t		ip;
	s_udp_hdr_t		udp;
	s_vxlan_hdr_t	vxlan;
} __attribute__((packed)) s_outer_hdr_t;

#define S_OUTER_HDR_LEN		sizeof( s_outer_hdr_t )

static void s_print_outer_hdr_size( void )
{
	S_PRINT_SIZE( s_outer_hdr_t );
	S_PRINT_STRUCT( s_outer_hdr_t, eth );
	S_PRINT_STRUCT( s_outer_hdr_t, ip );
	S_PRINT_STRUCT( s_outer_hdr_t, udp );
	S_PRINT_STRUCT( s_outer_hdr_t, vxlan );
	return;
}

static int s_encap_vxlan( const char *in_file, const char *out_file );

int main( int argc, char *argv[] )
{
	int i;
	char *in_file;
	char *out_file;

	s_print_eth_hdr_size();
	s_print_ip_hdr_size();
	s_print_udp_hdr_size();
	s_print_vxlan_hdr_size();
	s_print_outer_hdr_size();

	for ( i = 0; i < argc; i++ )
	{
		printf( "argv-%d: [%s]\n", i, argv[ i ] );
	}

	if ( argc > 1 )
	{
		in_file = argv[ 1 ];
	}
	else
	{
		in_file = "in.pcap";
	}

	if ( argc > 2 )
	{
		out_file = argv[ 2 ];
	}
	else
	{
		out_file = "out.pcap";
	}

	s_encap_vxlan( in_file, out_file );

	return 0;
}

static int s_encap_vxlan( const char *in_file, const char *out_file )
{
	char errbuf[ PCAP_ERRBUF_SIZE ];
	pcap_t *in_pcap;
	pcap_t *out_pcap;
	pcap_dumper_t *out_dump;
	struct pcap_pkthdr hdr;
	const u_char *data;
	u8 packet[ S_OUTER_HDR_LEN + IP_MAXPACKET ];
	u16 id;
	s_outer_hdr_t *outer;
	s_eth_hdr_t *inner;

	memset( packet, 0, sizeof( packet ) );
	outer = ( s_outer_hdr_t * )packet;
	inner = ( s_eth_hdr_t * )( packet + S_OUTER_HDR_LEN );
	id = 1;

	printf( "in[%s] ==> out[%s]\n", in_file, out_file );

	in_pcap = pcap_open_offline( in_file, errbuf );
	if ( in_pcap == NULL )
	{
		printf( "failed to open [%s]: %s\n", in_file, errbuf );
		return 1;
	}

	out_pcap = pcap_open_dead( DLT_EN10MB, 65535 );
	out_dump = pcap_dump_open( out_pcap, out_file );
	if ( out_dump == NULL )
	{
		printf( "failed to open [%s]: %s\n",
				out_file, pcap_geterr( out_pcap ) );
		return 2;
	}

	outer->ip.ver_ihl = S_IP_VER_IHL;
	outer->ip.flg_off = S_IP_FLG_OFF;
	outer->ip.ttl = S_IP_TTL;
	outer->ip.proto = IPPROTO_UDP;
	outer->udp.dport = htons( S_UDP_DPORT );
	outer->vxlan.rsvd = htonl( S_VXLAN_RSVD );
	outer->vxlan.vni_rsvd = htonl( S_VXLAN_VNI_RSVD );

	while ( ( data = pcap_next( in_pcap, &hdr ) ) != NULL )
	{
		memcpy( inner, data, hdr.caplen );
		outer->eth = *inner;
		outer->eth.type = htons( ETHERTYPE_IP );
		outer->ip.totlen =
			htons( S_OUTER_HDR_LEN - sizeof( s_eth_hdr_t ) + hdr.caplen );
		outer->ip.saddr = htonl( inner->saddr );
		outer->ip.daddr = htonl( inner->daddr );
		outer->ip.id = htons( id );
		outer->udp.sport = htons( inner->sport );
		outer->udp.len =
			htons( sizeof( s_udp_hdr_t ) + sizeof( s_vxlan_hdr_t ) +
				   hdr.caplen );

		hdr.caplen += S_OUTER_HDR_LEN;
		hdr.len += S_OUTER_HDR_LEN;

		pcap_dump( ( u_char * )out_dump, &hdr, packet );

		id++;
	}

	pcap_dump_close( out_dump );
	pcap_close( out_pcap );
	pcap_close( in_pcap );

	return 0;
}

/* EOF */
