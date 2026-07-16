#include <stdint.h>
#include <string.h>
#include <stdio.h>
typedef uint32_t uint32; typedef uint8_t uint8; typedef uint16_t uint16; typedef uint64_t uint64;
#define PKCS5_SALT_SIZE 64
#include "Sha3.h"   /* real header: SHA3_CTX + SHA3_512_BLOCKSIZE/DIGESTSIZE + protos */
static uint32_t bswap_32(uint32_t x){return (x<<24)|((x&0xFF00)<<8)|((x>>8)&0xFF00)|(x>>24);}
static void burn(void*p,size_t n){volatile unsigned char*q=p;while(n--)*q++=0;}
#include "pkcs5_sha3_extract.c"   /* shipped hmac_sha3_512 / derive_key_sha3_512 verbatim */
static int chk(const char*l,const unsigned char*g,const char*hex){
    size_t n=strlen(hex)/2,i;unsigned char e[256];
    for(i=0;i<n;i++){unsigned v;sscanf(hex+2*i,"%2x",&v);e[i]=v;}
    if(memcmp(g,e,n)){printf("  [FAIL] %s\n",l);return 1;}
    printf("  [ OK ] %s\n",l);return 0;}
int main(void){
    int f=0;unsigned char out[256];unsigned char salt[4]={0x12,0x34,0x56,0x78};
    {unsigned char d[64];memcpy(d,"abc",3);hmac_sha3_512((unsigned char*)"key",3,d,3);
     f+=chk("HMAC-SHA3-512(key,\"abc\")",d,"085e4e83503f40b82fef38438bc4905a55dbaa8c8878097a899db0b57ce7da57a368251c34474f60b3ebacb39b2edaca4b290456411c76ec7ab61944cfe2288e");}
    derive_key_sha3_512((unsigned char*)"password",8,salt,4,5,out,4,(volatile long*)0);
    f+=chk("PBKDF2-SHA3-512 dklen=4",out,"971f8731");
    derive_key_sha3_512((unsigned char*)"password",8,salt,4,5,out,64,(volatile long*)0);
    f+=chk("PBKDF2-SHA3-512 dklen=64 (1 block)",out,"971f8731bcd98e2089fab703be3f86b93a9f83a591a57ad5bcb1caf6f1deb7080c2011cb3cda7132a84e91bc536b357135568c18810def2e791c6bd622f08a4f");
    derive_key_sha3_512((unsigned char*)"password",8,salt,4,5,out,96,(volatile long*)0);
    f+=chk("PBKDF2-SHA3-512 dklen=96 (2 blocks)",out,"971f8731bcd98e2089fab703be3f86b93a9f83a591a57ad5bcb1caf6f1deb7080c2011cb3cda7132a84e91bc536b357135568c18810def2e791c6bd622f08a4f0619fb9868fdd503bfaab2046f5a0711eab0e8ccb2a3cf31f40009698d11a02c");
    {unsigned char lp[200];int i;for(i=0;i<200;i++)lp[i]=(unsigned char)i;
     derive_key_sha3_512(lp,200,salt,4,3,out,64,(volatile long*)0);
     f+=chk("PBKDF2-SHA3-512 long-pwd (>72B) dklen=64",out,"0080652f4127089ae48157097ef8e2dca9f158c74a434e1db3672d4fc435e4a60beca66a394ce24583fd8a96e194a5abf3735d7bba642e5743738b9a7ed0eda0");}
    printf(f?"\nRESULT: %d FAIL\n":"\nRESULT: ALL SHA3 HMAC/PBKDF2 VECTORS PASS\n",f);return f?1:0;}
