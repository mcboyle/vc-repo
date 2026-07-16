/* Self-contained proof of the HardwareKeyFactor crypto + mixing seam. Needs ONLY the module
 * (built with -DVC_ENABLE_HKF_SIMULATOR); no other VeraCrypt objects. Compare its output to
 * reference_check.py. The full "token -> mix -> real derive_key_sha3_512" chain was additionally
 * verified against the actual VeraCrypt derivation code (see README, Verification). */
#include <stdio.h>
#include <string.h>
#include "HardwareKeyFactor.h"
static void hex(const char*l,const unsigned char*b,int n){printf("%s ",l);for(int i=0;i<n;i++)printf("%02x",b[i]);printf("\n");}
int main(void){
    unsigned char resp[64]; int rlen=0; HKFConfig cfg; memset(&cfg,0,sizeof cfg);
    cfg.backend=HKF_BACKEND_SIMULATOR;

    /* 1. HMAC-SHA1 correctness (RFC 2202 case 1): key=0x0b*20, msg="Hi There" */
    cfg.simMac=1; cfg.simSecretLen=20; memset(cfg.simSecret,0x0b,20);
    HKFComputeResponse(&cfg,(const unsigned char*)"Hi There",8,resp,&rlen);
    hex("hmac_sha1_rfc2202 =",resp,rlen);

    /* 2. YubiKey-profile response over a 64-byte salt with a programmed 20-byte secret */
    unsigned char salt[64]; for(int i=0;i<64;i++) salt[i]=(unsigned char)(i*7+1);
    unsigned char secret[20]; for(int i=0;i<20;i++) secret[i]=(unsigned char)(i+1);
    memcpy(cfg.simSecret,secret,20); cfg.simSecretLen=20; cfg.simMac=1;
    HKFComputeResponse(&cfg,salt,64,resp,&rlen); hex("yk_response       =",resp,rlen);

    /* 3. mixed password (base password + response, keyfile pool method) */
    unsigned char pw[256]; memset(pw,0,sizeof pw); const char*base="correct horse battery staple";
    int plen=(int)strlen(base); memcpy(pw,base,plen);
    HKFMixResponseIntoPassword(pw,&plen,resp,rlen);
    printf("mixed_len         = %d\n",plen); hex("mixed_pw32        =",pw,32);

    /* 4. FIDO2-profile response: HMAC-SHA256(cred, SHA256(salt)) */
    unsigned char cred[32]; for(int i=0;i<32;i++) cred[i]=(unsigned char)(0xA0+i);
    memcpy(cfg.simSecret,cred,32); cfg.simSecretLen=32; cfg.simMac=2;
    HKFComputeResponse(&cfg,salt,64,resp,&rlen); hex("fido2_response    =",resp,rlen);
    return 0;
}
