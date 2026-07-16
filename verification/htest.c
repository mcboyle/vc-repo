#include <stdio.h>
#include <string.h>
#include "Common/HardwareKeyFactor.h"
/* real VeraCrypt PBKDF2 */
extern void derive_key_sha3_512(const unsigned char*,int,const unsigned char*,int,unsigned int,unsigned char*,int,long volatile*);
static void hex(const char*l,const unsigned char*b,int n){printf("%s ",l);for(int i=0;i<n;i++)printf("%02x",b[i]);printf("\n");}
int main(void){
    /* (1) HMAC-SHA1 correctness via the simulator: RFC 2202 test case 1 */
    HKFConfig cfg; memset(&cfg,0,sizeof cfg);
    cfg.backend=HKF_BACKEND_SIMULATOR; cfg.simMac=1;
    cfg.simSecretLen=20; memset(cfg.simSecret,0x0b,20);
    unsigned char resp[64]; int rlen=0;
    HKFComputeResponse(&cfg,(const unsigned char*)"Hi There",8,resp,&rlen);
    hex("HMAC-SHA1(0x0b*20,\"Hi There\")   =",resp,rlen);
    printf("expect RFC2202 case1            = b617318655057264e28bc0b6fb378c8ef146be00\n\n");

    /* (2) full chain with a 64-byte salt: token response over the salt, mix, then real PBKDF2 */
    unsigned char salt[64]; for(int i=0;i<64;i++) salt[i]=(unsigned char)(i*7+1);
    /* simulate a programmed 20-byte YubiKey HMAC-SHA1 secret */
    unsigned char secret[20]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
    memcpy(cfg.simSecret,secret,20); cfg.simSecretLen=20; cfg.simMac=1;
    HKFComputeResponse(&cfg,salt,64,resp,&rlen);
    hex("token response over salt        =",resp,rlen);

    /* password buffer must hold >=128 for the pool */
    unsigned char pw[256]; memset(pw,0,sizeof pw);
    const char* base="correct horse battery staple"; int plen=(int)strlen(base);
    memcpy(pw,base,plen);
    HKFMixResponseIntoPassword(pw,&plen,resp,rlen);
    printf("mixed password length           = %d\n",plen);
    hex("mixed password (first 32 bytes) =",pw,32);

    unsigned char dk[64];
    derive_key_sha3_512(pw,plen,salt,64,5,dk,64,(long volatile*)0);
    hex("HEADER KEY = PBKDF2-SHA512(mix)  =",dk,64);

    /* (3) gating: flip one bit of the secret -> header key must change completely */
    unsigned char pw2[256]; memset(pw2,0,sizeof pw2); memcpy(pw2,base,strlen(base)); int p2=(int)strlen(base);
    cfg.simSecret[0]^=0x01;
    HKFComputeResponse(&cfg,salt,64,resp,&rlen);
    HKFMixResponseIntoPassword(pw2,&p2,resp,rlen);
    unsigned char dk2[64]; derive_key_sha3_512(pw2,p2,salt,64,5,dk2,64,(long volatile*)0);
    int diff=0; for(int i=0;i<64;i++) if(dk[i]!=dk2[i]) diff++;
    printf("\nwrong-secret key differs in %d/64 bytes (want ~64 = access gated)\n",diff);
    return 0;
}
