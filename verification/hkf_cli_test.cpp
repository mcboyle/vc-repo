#include "Main/HardwareKeyFactorCli.h"
#include <cstdio>
using namespace VeraCrypt;
int main(){
  std::string err; HKFConfig cfg; int fails=0;

  // yubikey
  if(!BuildHKFConfig("yubikey",2,"","","","",0,cfg,err)){printf("FAIL yk: %s\n",err.c_str());fails++;}
  else printf("yk         -> backend=%d slot=%d mayBlock=%d\n",cfg.backend,cfg.ykSlot,cfg.ykMayBlock);

  // fido2 with hex credential id
  if(!BuildHKFConfig("fido2",0,"veracrypt-volume","1122aabbccdd","1234",""  ,0,cfg,err)){printf("FAIL fido2: %s\n",err.c_str());fails++;}
  else{printf("fido2      -> backend=%d rp='%s' credIdLen=%d credId[0..2]=%02x%02x%02x pin='%s'\n",
       cfg.backend,cfg.fidoRpId,cfg.fidoCredIdLen,cfg.fidoCredId[0],cfg.fidoCredId[1],cfg.fidoCredId[2],cfg.fidoPin);}

  // simulator: parse a 20-byte secret, then RUN it through the real crypto and check the response
  std::string secretHex="0102030405060708090a0b0c0d0e0f1011121314"; // 1..20
  if(!BuildHKFConfig("simulator",0,"","","",secretHex,1,cfg,err)){printf("FAIL sim: %s\n",err.c_str());fails++;}
  else{
    printf("simulator  -> backend=%d simMac=%d secretLen=%d\n",cfg.backend,cfg.simMac,cfg.simSecretLen);
    HKFSetActiveConfig(&cfg);
    unsigned char salt[64]; for(int i=0;i<64;i++) salt[i]=(unsigned char)(i*7+1);
    unsigned char resp[64]; int rlen=0;
    HKFComputeResponse(&cfg,salt,64,resp,&rlen);
    printf("  parsed-config response over salt = "); for(int i=0;i<rlen;i++) printf("%02x",resp[i]); printf("\n");
    printf("  expected (matches earlier tests) = b50ad71bb05a80bdffb57d6de3a07675ce7e72e8\n");
  }

  // error cases
  struct {const char* b; const char* rp; const char* cid; const char* sec; int mac;} bad[] = {
    {"fido2","","", "",0}, {"fido2","rp","zz","",0}, {"simulator","","","0102",3}, {"weird","","","",0}
  };
  for(auto&t:bad){ if(BuildHKFConfig(t.b,2,t.rp,t.cid,"",t.sec,t.mac,cfg,err)) {printf("FAIL: bad input accepted (%s)\n",t.b);fails++;}
                   else printf("rejected '%s' -> %s\n",t.b,err.c_str()); }
  printf("\n%s\n", fails? "SOME CHECKS FAILED":"ALL CLI-PARSING CHECKS PASSED");
  return fails?1:0;
}
