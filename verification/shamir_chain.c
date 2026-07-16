#include <stdio.h>
#include <string.h>
#include "Common/Shamir.h"
#include "Common/HardwareKeyFactor.h"
extern void derive_key_sha3_512(const unsigned char*,int,const unsigned char*,int,unsigned int,unsigned char*,int,long volatile*);
static void hex(const char*l,const unsigned char*b,int n){printf("%s ",l);for(int i=0;i<n;i++)printf("%02x",b[i]);printf("\n");}
static void deriveWith(HKFConfig*cfg,const unsigned char*salt,unsigned char out[64]){
  unsigned char pw[256]; memset(pw,0,sizeof pw);
  const char*base="correct horse battery staple"; int plen=(int)strlen(base); memcpy(pw,base,plen);
  HKFSetActiveConfig(cfg);
  HKFApplyIfConfigured(pw,&plen,salt,64);
  derive_key_sha3_512(pw,plen,salt,64,5,out,64,(long volatile*)0);
}
int main(void){
  unsigned char S[32]; for(int i=0;i<32;i++) S[i]=(unsigned char)(0x40+i);
  int T=3,N=5,L=32;
  unsigned char rnd[SHAMIR_MAX_SHARES*SHAMIR_MAX_SECRET]; for(int i=0;i<(T-1)*L;i++) rnd[i]=(unsigned char)(i*13+7);
  ShamirShare sh[SHAMIR_MAX_SHARES]; shamir_split(S,L,T,N,rnd,sh);
  unsigned char salt[64]; for(int i=0;i<64;i++) salt[i]=(unsigned char)(i*7+1);

  ShamirShare good[3]={sh[0],sh[2],sh[4]}; unsigned char Sr[64]; int Sl=0; shamir_combine(good,3,Sr,&Sl);
  HKFConfig cfg; memset(&cfg,0,sizeof cfg); cfg.backend=HKF_BACKEND_RAW_SECRET; memcpy(cfg.rawSecret,Sr,Sl); cfg.rawSecretLen=Sl;
  unsigned char K[64]; deriveWith(&cfg,salt,K);
  printf("reconstructed S == original: %s\n", memcmp(Sr,S,L)==0?"YES":"no");
  hex("HEADER KEY (3 correct shares) =",K,64);

  ShamirShare few[2]={sh[0],sh[1]}; unsigned char Sw[64]; int Swl=0; shamir_combine(few,2,Sw,&Swl);
  HKFConfig c2; memset(&c2,0,sizeof c2); c2.backend=HKF_BACKEND_RAW_SECRET; memcpy(c2.rawSecret,Sw,Swl); c2.rawSecretLen=Swl;
  unsigned char K2[64]; deriveWith(&c2,salt,K2);
  int diff=0; for(int i=0;i<64;i++) if(K[i]!=K2[i]) diff++;
  printf("below-threshold (2 shares) key differs in %d/64 bytes (want ~64 = gated)\n",diff);

  ShamirShare good2[3]={sh[1],sh[3],sh[4]}; unsigned char Sr2[64]; int Sl2=0; shamir_combine(good2,3,Sr2,&Sl2);
  HKFConfig c3; memset(&c3,0,sizeof c3); c3.backend=HKF_BACKEND_RAW_SECRET; memcpy(c3.rawSecret,Sr2,Sl2); c3.rawSecretLen=Sl2;
  unsigned char K3[64]; deriveWith(&c3,salt,K3);
  printf("different valid 3-subset gives SAME key: %s\n", memcmp(K,K3,64)==0?"YES":"no");
  return 0;
}
