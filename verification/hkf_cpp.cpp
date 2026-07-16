#include "Platform/Platform.h"
#include "Volume/VolumePassword.h"
#include "Volume/Pkcs5Kdf.h"
#include "Volume/HardwareKeyFactorMix.h"
#include <cstdio>
#include <cstring>
using namespace VeraCrypt;
static void hex(const char*l,const uint8*b,size_t n){printf("%s ",l);for(size_t i=0;i<n;i++)printf("%02x",b[i]);printf("\n");}
int main(){
  static HKFConfig cfg; memset(&cfg,0,sizeof cfg);
  cfg.backend=HKF_BACKEND_SIMULATOR; cfg.simMac=1; cfg.simSecretLen=20;
  for(int i=0;i<20;i++) cfg.simSecret[i]=(uint8)(i+1);
  HKFSetActiveConfig(&cfg);                    // as the CLI would, before mount/create

  uint8 saltbytes[64]; for(int i=0;i<64;i++) saltbytes[i]=(uint8)(i*7+1);
  ConstBufferPtr salt(saltbytes,64);
  VolumePassword pw((const uint8*)"correct horse battery staple",28);

  shared_ptr<VolumePassword> eff = HKFMixPassword(pw, salt);   // the real C++ helper used in Decrypt/Creator
  printf("C++ mixed len  = %zu\n",eff->Size());
  hex("C++ mixed_pw32 =",eff->DataPtr(),32);

  Pkcs5HmacSha3_512 kdf; SecureBuffer headerKey(64);
  kdf.DeriveKey(headerKey, *eff, salt, 5);                     // real VeraCrypt C++ KDF
  hex("C++ HEADER KEY =",headerKey.Ptr(),64);
  printf("reference (py) = 628882be5ebded9005315da7f7ed1c16876baca1c9fc258fd4d3d0c2f4ea53d0ec53b71bf81db7c9af9b61a362263e70aa34962bba9f913c68f167f21605868d\n");
  return 0;
}
