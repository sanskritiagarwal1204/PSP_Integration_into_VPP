// psp.h
#ifndef _PSP_H_
#define _PSP_H_


#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <stdint.h>
// Missing macros for PSP
#define IPV4_ETYPE 0x0800
#define IPV6_ETYPE 0x86DD

#define PSP_HDR_EXT_LEN_UNITS 8  /* Each PSP ext len unit is 8 bytes */
#define PSP_HDR_VER_SHIFT 4      /* Shift for version bits */
#define PSP_HDR_ALWAYS_1 0x08    /* Bit always set in PSP header */
#define PSP_HDR_FLAG_V_SHIFT 3   /* Shift for 'Include VC' flag */


#define PACKED __attribute__((packed))
#define MAC_ADDR_OCTETS         6
#define IPV6_ADDR_OCTETS       16
#define IP_PROTO_UDP           0x11
#define UDP_PORT_PSP         1000
#define PSP_INITIAL_IV         1
#define PSP_ICV_OCTETS        16
#define PSP_HDR_EXT_LEN_MIN    1
#define PSP_HDR_EXT_LEN_WITH_VC 2
#define PSP_HDR_VC_OCTETS       8
#define PSP_CRYPT_OFFSET_UNITS  4
#define PSP_CRYPT_OFFSET_MASK   0x3f

typedef enum { PSP_TRANSPORT, PSP_TUNNEL } psp_encap_t;
typedef enum { AES_GCM_128, AES_GCM_256 } crypto_alg_t;
typedef enum { PSP_VER0 = 0, PSP_VER1, PSP_VER2, PSP_VER3 } psp_ver_t;

struct eth_hdr {
    uint8_t  dmac[MAC_ADDR_OCTETS];
    uint8_t  smac[MAC_ADDR_OCTETS];
    uint16_t etype;
} PACKED;

struct ipv4_hdr {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t len;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t csum;
    uint32_t sip;
    uint32_t dip;
} PACKED;

struct ipv6_hdr {
    uint32_t ver_tc_flow;
    uint16_t plen;
    uint8_t  proto;
    uint8_t  ttl;
    uint8_t  sip[IPV6_ADDR_OCTETS];
    uint8_t  dip[IPV6_ADDR_OCTETS];
} PACKED;

struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t csum;
} PACKED;

struct psp_hdr {
    uint8_t  next_hdr;
    uint8_t  hdr_ext_len;
    uint8_t  crypt_off;
    uint8_t  s_d_ver_v_1;
    uint32_t spi;
    uint64_t iv;
} PACKED;

struct psp_icv {
    uint8_t octets[PSP_ICV_OCTETS];
} PACKED;

struct psp_trailer {
    struct psp_icv icv;
} PACKED;

/* 64-bit byte order */
#define HTONLL(x)                              \
  ((1 == htonl(1)) ? (x)                        \
    : ((((uint64_t)htonl((x)&0xFFFFFFFFUL))<<32) \
         | htonl((uint32_t)((x)>>32))))

extern uint16_t ipv4_hdr_csum(uint8_t *ip_hdr);
extern uint16_t ipv4_udp_csum(uint8_t *ip_hdr);
extern uint16_t ipv6_udp_csum(uint8_t *ip_hdr);

#endif /* _PSP_H_ */
