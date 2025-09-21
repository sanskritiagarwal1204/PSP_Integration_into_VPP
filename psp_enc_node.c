// psp_enc_node.c
#define OPENSSL_API_COMPAT 0x10100000L
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include "psp.h"
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <string.h>
#include <vnet/plugin/plugin.h> 

typedef struct {
    uint8_t      master_key0[32];
    uint8_t      master_key1[32];
    uint32_t     spi;
    psp_encap_t  encap_mode;
    crypto_alg_t crypto_alg;
    uint8_t      crypt_offset;  /* units of 4 octets */
    bool         include_vc;
} psp_cfg_t;

static psp_cfg_t psp_cfg;

/* AES-GCM encrypt helper */
static int
psp_aes_gcm_encrypt(const uint8_t *key, int key_len,
                    const uint8_t *iv,  int iv_len,
                    const uint8_t *aad, int aad_len,
                    const uint8_t *pt,  int pt_len,
                    uint8_t       *ct,
                    uint8_t       *tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *c = (key_len==16)?EVP_aes_128_gcm():EVP_aes_256_gcm();
    int len;
    EVP_EncryptInit_ex(ctx,c,NULL,NULL,NULL);
    EVP_EncryptInit_ex(ctx,NULL,NULL,key,iv);
    EVP_EncryptUpdate(ctx,NULL,&len,aad,aad_len);
    EVP_EncryptUpdate(ctx,ct,&len,pt,pt_len);
    EVP_EncryptFinal_ex(ctx,ct+len,&len);
    EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,PSP_ICV_OCTETS,tag);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/* CMAC-based key derivation (phase 1) */
static int
derive_psp_key_128(const uint8_t *master,uint8_t ctr,uint8_t *out)
{
    CMAC_CTX *ctx = CMAC_CTX_new();
    uint8_t block[16]={0}; size_t outl=0;
    block[3]=ctr;
    CMAC_Init(ctx,master,32,EVP_aes_256_cbc(),NULL);
    CMAC_Update(ctx,block,sizeof(block));
    CMAC_Final(ctx,out,&outl);
    CMAC_CTX_free(ctx);
    return outl==16?0:-1;
}

/* full key derivation */
static int
derive_psp_key(uint8_t *out_key)
{
    if(derive_psp_key_128(psp_cfg.master_key0,1,out_key))return-1;
    if(psp_cfg.crypto_alg==AES_GCM_256)
       derive_psp_key_128(psp_cfg.master_key1,2,out_key+16);
    return 0;
}

/* device-output node */
static uword
psp_encrypt_node_fn(vlib_main_t *vm,vlib_node_runtime_t *node,vlib_frame_t *frame)
{
    u32 n_left=frame->n_vectors,*from=vlib_frame_vector_args(frame);
    while(n_left--){
        vlib_buffer_t *b=vlib_get_buffer(vm,from[0]);
        uint8_t *pkt=vlib_buffer_get_current(b);
        //uint32_t pkt_len=b->current_length;

        struct eth_hdr *eth=(void*)pkt;
        uint16_t etype=ntohs(eth->etype);
        uint8_t *l3=pkt+sizeof(*eth),ip_proto;
        uint16_t ip_hdr_len;//ip_len;
        if(etype==IPV4_ETYPE){
            struct ipv4_hdr *ip4=(void*)l3;
            ip_hdr_len=(ip4->ver_ihl&0x0F)*4;
            ip_proto=ip4->proto;
            //ip_len=ntohs(ip4->len);
        } else if(etype==IPV6_ETYPE){
            struct ipv6_hdr *ip6=(void*)l3;
            ip_hdr_len=sizeof(*ip6);
            ip_proto=ip6->proto;
            //ip_len=ntohs(ip6->plen)+ip_hdr_len;
        } else goto skip;
        if(ip_proto!=IP_PROTO_UDP)goto skip;

        uint8_t *l4=l3+ip_hdr_len; struct udp_hdr *udp=(void*)l4;
        int crypt_off_bytes=psp_cfg.crypt_offset*PSP_CRYPT_OFFSET_UNITS;
        int payload_len=ntohs(udp->len)-sizeof(*udp);
        int hdr_ext_bytes=(psp_cfg.include_vc?PSP_HDR_EXT_LEN_WITH_VC:PSP_HDR_EXT_LEN_MIN-1)*PSP_HDR_EXT_LEN_UNITS;
        int psp_hdr_len=sizeof(struct psp_hdr)+hdr_ext_bytes;
        int overhead=psp_hdr_len+PSP_ICV_OCTETS;
        if(overhead>payload_len||crypt_off_bytes>payload_len)goto skip;

        uint8_t *psp_loc=l4+sizeof(*udp);
        memmove(psp_loc+overhead,psp_loc,payload_len);

        struct psp_hdr *ph=(void*)psp_loc;
        ph->next_hdr=IP_PROTO_UDP;
        ph->hdr_ext_len=(psp_cfg.include_vc?PSP_HDR_EXT_LEN_WITH_VC:PSP_HDR_EXT_LEN_MIN);
        ph->crypt_off=psp_cfg.crypt_offset&PSP_CRYPT_OFFSET_MASK;
        ph->s_d_ver_v_1=(psp_cfg.crypto_alg==AES_GCM_128?PSP_VER0<<PSP_HDR_VER_SHIFT:PSP_VER1<<PSP_HDR_VER_SHIFT)|PSP_HDR_ALWAYS_1|(psp_cfg.include_vc<<PSP_HDR_FLAG_V_SHIFT);
        ph->spi=htonl(psp_cfg.spi);
        static uint64_t ctr=PSP_INITIAL_IV;
        uint64_t local_ctr = ctr++;
        ph->iv=HTONLL(local_ctr);
        if(ctr==0)ctr=PSP_INITIAL_IV;

        uint8_t key[32];
        derive_psp_key(key);

        uint8_t iv_buf[12];
        memcpy(iv_buf,&ph->spi,4);
        memcpy(iv_buf+4,&ph->iv,8);

        uint8_t *ct=psp_loc+psp_hdr_len;
        int ct_len=payload_len-overhead;
        uint8_t *tag=ct+ct_len;
        psp_aes_gcm_encrypt(key,(psp_cfg.crypto_alg==AES_GCM_128?16:32),
                            iv_buf,12,
                            psp_loc,psp_hdr_len+crypt_off_bytes,
                            ct,ct_len,
                            ct,tag);

        udp->len=htons(ntohs(udp->len)+overhead);
        udp->csum=0;
        if(etype==IPV4_ETYPE){
            struct ipv4_hdr *ip4=(void*)l3;
            ip4->len=htons(ntohs(ip4->len)+overhead);
            ip4->csum=0; ip4->csum=ipv4_hdr_csum((uint8_t*)ip4);
            udp->csum=ipv4_udp_csum((uint8_t*)ip4);
        } else {
            struct ipv6_hdr *ip6=(void*)l3;
            ip6->plen=htons(ntohs(ip6->plen)+overhead);
            udp->csum=ipv6_udp_csum((uint8_t*)ip6);
        }
        b->current_length+=overhead;

    skip:
        from++;
    }
    return frame->n_vectors;
}

VLIB_REGISTER_NODE(psp_encrypt_node) = {
    .function = psp_encrypt_node_fn,
    .name     = "psp-encrypt",
};

VNET_FEATURE_INIT(psp_encrypt_feat) = {
    .arc_name    = "device-output",
    .node_name   = "psp-encrypt",
    .runs_before = VNET_FEATURES("interface-output"),
};
VLIB_PLUGIN_REGISTER() = {
    .version = "1.0",
    .description = "Packet Security Protocol Plugin",
};
