// psp_dec_node.c
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
    uint8_t      crypt_offset;
    bool         include_vc;
} psp_cfg_t;
static psp_cfg_t psp_cfg;

static int
psp_aes_gcm_decrypt(const uint8_t *key,int key_len,
                    const uint8_t *iv,int iv_len,
                    const uint8_t *aad,int aad_len,
                    const uint8_t *ct,int ct_len,
                    const uint8_t *tag,
                    uint8_t       *pt)
{
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();
    const EVP_CIPHER *c=(key_len==16)?EVP_aes_128_gcm():EVP_aes_256_gcm();
    int len,ret;
    EVP_DecryptInit_ex(ctx,c,NULL,NULL,NULL);
    EVP_DecryptInit_ex(ctx,NULL,NULL,key,iv);
    EVP_DecryptUpdate(ctx,NULL,&len,aad,aad_len);
    ret=EVP_DecryptUpdate(ctx,pt,&len,ct,ct_len);
    EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,PSP_ICV_OCTETS,(void*)tag);
    ret&=EVP_DecryptFinal_ex(ctx,pt+len,&len);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int
derive_psp_key_128(const uint8_t *master,uint8_t ctr,uint8_t *out)
{
    CMAC_CTX *ctx=CMAC_CTX_new();
    uint8_t block[16]={0}; size_t outl=0;
    block[3]=ctr;
    CMAC_Init(ctx,master,32,EVP_aes_256_cbc(),NULL);
    CMAC_Update(ctx,block,sizeof(block));
    CMAC_Final(ctx,out,&outl);
    CMAC_CTX_free(ctx);
    return outl==16?0:-1;
}

static int
derive_psp_key(uint8_t *out_key)
{
    if(derive_psp_key_128(psp_cfg.master_key0,1,out_key))return-1;
    if(psp_cfg.crypto_alg==AES_GCM_256)
       derive_psp_key_128(psp_cfg.master_key1,2,out_key+16);
    return 0;
}

static uword
psp_decrypt_node_fn(vlib_main_t *vm,vlib_node_runtime_t *node,vlib_frame_t *frame)
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
        int payload_len=ntohs(udp->len)-sizeof(*udp);
        struct psp_hdr *ph=(void*)(l4+sizeof(*udp));
        int hdr_ext_bytes=(ph->hdr_ext_len-PSP_HDR_EXT_LEN_MIN)*PSP_HDR_EXT_LEN_UNITS;
        int psp_hdr_len=sizeof(*ph)+hdr_ext_bytes;
        int psp_trailer_len=PSP_ICV_OCTETS;
        int overhead=psp_hdr_len+psp_trailer_len;
        int crypt_off_bytes=(ph->crypt_off&PSP_CRYPT_OFFSET_MASK)*PSP_CRYPT_OFFSET_UNITS;
        if(overhead>payload_len||crypt_off_bytes>payload_len)goto skip;

        uint8_t iv_buf[12];
        memcpy(iv_buf,&ph->spi,4);
        memcpy(iv_buf+4,&ph->iv,8);

        uint8_t key[32];
        derive_psp_key(key);

        uint8_t *ct=(uint8_t*)ph+psp_hdr_len;
        int ct_len=payload_len-overhead;
        uint8_t *tag=ct+ct_len;
        uint8_t *pt=alloca(ct_len);
        psp_aes_gcm_decrypt(key,(psp_cfg.crypto_alg==AES_GCM_128?16:32),
                            iv_buf,12,
                            (uint8_t*)ph,psp_hdr_len+crypt_off_bytes,
                            ct,ct_len,
                            tag,
                            pt);

        memmove(l4+sizeof(*udp),pt+crypt_off_bytes,ct_len-crypt_off_bytes);
        b->current_length-=overhead;

        udp->len=htons(ntohs(udp->len)-overhead);
        udp->csum=0;
        if(etype==IPV4_ETYPE){
            struct ipv4_hdr *ip4=(void*)l3;
            ip4->len=htons(ntohs(ip4->len)-overhead);
            ip4->csum=0; ip4->csum=ipv4_hdr_csum((uint8_t*)ip4);
            udp->csum=ipv4_udp_csum((uint8_t*)ip4);
        } else {
            struct ipv6_hdr *ip6=(void*)l3;
            ip6->plen=htons(ntohs(ip6->plen)-overhead-sizeof(*ip6));
            udp->csum=ipv6_udp_csum((uint8_t*)ip6);
        }

    skip:
        from++;
    }
    return frame->n_vectors;
}

VLIB_REGISTER_NODE(psp_decrypt_node) = {
    .function = psp_decrypt_node_fn,
    .name     = "psp-decrypt",
};

VNET_FEATURE_INIT(psp_decrypt_feat) = {
    .arc_name    = "device-input",
    .node_name   = "psp-decrypt",
    .runs_before = VNET_FEATURES("ip4-unicast","ip6-unicast"),
};

