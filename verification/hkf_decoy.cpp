#include "Platform/Platform.h"
#include "Volume/VolumePassword.h"
#include "Volume/Pkcs5Kdf.h"
#include "Volume/HardwareKeyFactorMix.h"
#include <cstdio>
#include <cstring>
using namespace VeraCrypt;
static void deriveKey(const VolumePassword& pw,const uint8* saltBytes,bool applyFactor,uint8 out[64]){
  ConstBufferPtr salt(saltBytes,64); shared_ptr<VolumePassword> eff; const VolumePassword* p=&pw;
  if(applyFactor){ eff=HKFMixPassword(pw,salt); p=eff.get(); }
  Pkcs5HmacSha3_512 kdf; SecureBuffer hk(64); kdf.DeriveKey(hk,*p,salt,5); memcpy(out,hk.Ptr(),64);
}
static bool eq(const uint8*a,const uint8*b){ return memcmp(a,b,64)==0; }
int main(){
  static HKFConfig cfg; memset(&cfg,0,sizeof cfg);
  cfg.backend=HKF_BACKEND_SIMULATOR; cfg.simMac=1; cfg.simSecretLen=20;
  for(int i=0;i<20;i++) cfg.simSecret[i]=(uint8)(i+1);
  cfg.applyPolicy=HKF_APPLY_HIDDEN_ONLY;
  uint8 saltOuter[64],saltHidden[64];
  for(int i=0;i<64;i++){ saltOuter[i]=(uint8)(i+3); saltHidden[i]=(uint8)(i*7+1); }
  VolumePassword pw((const uint8*)"correct horse battery staple",28);

  printf("=== gating unit checks ===\n");
  printf("policy=HIDDEN_ONLY: normal->%d hidden->%d (want 0,1)\n",HKFShouldApply(&cfg,0),HKFShouldApply(&cfg,1));
  HKFConfig all=cfg; all.applyPolicy=HKF_APPLY_ALL;
  printf("policy=ALL:         normal->%d hidden->%d (want 1,1)\n",HKFShouldApply(&all,0),HKFShouldApply(&all,1));
  HKFConfig none; memset(&none,0,sizeof none); none.backend=HKF_BACKEND_NONE;
  printf("backend=NONE:       normal->%d hidden->%d (want 0,0)\n",HKFShouldApply(&none,0),HKFShouldApply(&none,1));

  // creation: outer password-only, hidden password+factor
  HKFSetActiveConfig(&cfg);
  uint8 keyOuter[64],keyHidden[64];
  deriveKey(pw,saltOuter, HKFShouldApply(&cfg,0)!=0, keyOuter);
  deriveKey(pw,saltHidden,HKFShouldApply(&cfg,1)!=0, keyHidden);

  // Scenario A: coerced decoy password, NO token
  HKFSetActiveConfig(0);
  uint8 a_out[64],a_hid[64];
  deriveKey(pw,saltOuter, false, a_out);
  deriveKey(pw,saltHidden,false, a_hid);
  printf("\n=== Scenario A: password only (no token) ===\n");
  printf("opens OUTER (decoy): %s\n", eq(a_out,keyOuter)?"YES":"no");
  printf("opens HIDDEN (real): %s   <- must be 'no'\n", eq(a_hid,keyHidden)?"YES":"no");

  // Scenario B: real user, password + token
  HKFSetActiveConfig(&cfg);
  uint8 b_out[64],b_hid[64];
  deriveKey(pw,saltOuter, HKFShouldApply(&cfg,0)!=0, b_out);
  deriveKey(pw,saltHidden,HKFShouldApply(&cfg,1)!=0, b_hid);
  printf("\n=== Scenario B: password + token (real user) ===\n");
  printf("opens OUTER (decoy): %s\n", eq(b_out,keyOuter)?"YES":"no");
  printf("opens HIDDEN (real): %s\n", eq(b_hid,keyHidden)?"YES":"no");

  bool pass = eq(a_out,keyOuter) && !eq(a_hid,keyHidden) && eq(b_out,keyOuter) && eq(b_hid,keyHidden);
  printf("\n%s\n", pass?"PASS: decoy opens with password alone; real volume requires the token":"FAIL");
  return pass?0:1;
}
