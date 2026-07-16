#include <stdio.h>
#include <string.h>
#include "Common/HardwareKeyFactor.h"
int main(void){
    HKFConfig cfg; memset(&cfg,0,sizeof cfg);
    cfg.backend=HKF_BACKEND_SIMULATOR; cfg.simMac=2;   /* emulate FIDO2 hmac-secret */
    unsigned char cred[32]; for(int i=0;i<32;i++) cred[i]=(unsigned char)(0xA0+i);
    memcpy(cfg.simSecret,cred,32); cfg.simSecretLen=32;
    unsigned char salt[64]; for(int i=0;i<64;i++) salt[i]=(unsigned char)(i*7+1);
    unsigned char resp[64]; int rlen=0;
    HKFComputeResponse(&cfg,salt,64,resp,&rlen);
    printf("FIDO2-sim response (%d bytes)    = ",rlen); for(int i=0;i<rlen;i++)printf("%02x",resp[i]); printf("\n");
    return 0;
}
