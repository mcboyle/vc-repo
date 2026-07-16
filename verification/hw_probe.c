#include <stdio.h>
#include <string.h>
#include "Common/HardwareKeyFactor.h"
int main(void){
    unsigned char salt[64]; memset(salt,0x5a,64); unsigned char resp[64]; int rlen=0;
    HKFConfig yk; memset(&yk,0,sizeof yk); yk.backend=HKF_BACKEND_YK_HMAC_SHA1; yk.ykSlot=2; yk.ykMayBlock=1;
    printf("YubiKey HMAC-SHA1 backend rc = %d (%s)\n", HKFComputeResponse(&yk,salt,64,resp,&rlen),
           "expect -2 HKF_ERR_NO_DEVICE with no key attached");
    HKFConfig fi; memset(&fi,0,sizeof fi); fi.backend=HKF_BACKEND_FIDO2_HMAC_SECRET;
    strcpy(fi.fidoRpId,"veracrypt-volume"); fi.fidoCredIdLen=16; memset(fi.fidoCredId,0x11,16);
    printf("FIDO2 hmac-secret backend rc = %d (%s)\n", HKFComputeResponse(&fi,salt,64,resp,&rlen),
           "expect -2 NO_DEVICE / -3 DEVICE with no authenticator");
    return 0;
}
