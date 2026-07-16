#include <stdio.h>
#include <string.h>
#include "Shamir.c"   /* include impl to KAT the static GF helpers */
int main(void){
  gf_init();
  printf("=== GF(2^8) known-answer tests (AES field) ===\n");
  printf("gf_mul(0x57,0x83)=%02x (want c1)\n", gf_mul(0x57,0x83));
  printf("gf_mul(0x53,0xca)=%02x (want 01)\n", gf_mul(0x53,0xca));
  printf("gf_inv(0x53)=%02x (want ca)\n", gf_inv(0x53));

  unsigned char secret[32]; for(int i=0;i<32;i++) secret[i]=(unsigned char)(0x10+i);
  int T=3,N=5,L=32;
  unsigned char rnd[SHAMIR_MAX_SHARES*SHAMIR_MAX_SECRET];
  for(int i=0;i<(T-1)*L;i++) rnd[i]=(unsigned char)(i*7+1);
  ShamirShare sh[SHAMIR_MAX_SHARES];
  if(shamir_split(secret,L,T,N,rnd,sh)!=SHAMIR_OK){printf("split failed\n");return 1;}
  printf("\n=== split %d-of-%d ===\nsecret[0..3]=%02x%02x%02x%02x\n",T,N,secret[0],secret[1],secret[2],secret[3]);

  unsigned char rec[64]; int rl=0;
  ShamirShare a[3]={sh[0],sh[2],sh[4]}; shamir_combine(a,3,rec,&rl);
  int ok1=memcmp(rec,secret,L)==0;
  ShamirShare b[3]={sh[1],sh[3],sh[4]}; unsigned char rec2[64]; shamir_combine(b,3,rec2,&rl);
  int ok2=memcmp(rec2,secret,L)==0;
  ShamirShare c[2]={sh[0],sh[1]}; unsigned char rec3[64]; shamir_combine(c,2,rec3,&rl);
  int bad=memcmp(rec3,secret,L)==0;
  printf("combine {1,3,5}: recovered secret? %s\n", ok1?"YES":"no");
  printf("combine {2,4,5}: same secret?      %s\n", ok2?"YES":"no");
  printf("combine {1,2} (below threshold):   %s  <- must be 'no'\n", bad?"YES":"no");

  printf("\nSHARES_FOR_PY\n");
  for(int s=0;s<N;s++){ printf("%d:",sh[s].x); for(int i=0;i<L;i++) printf("%02x",sh[s].y[i]); printf("\n"); }
  printf("\n%s\n", (ok1&&ok2&&!bad)?"PASS: any 3 shares reconstruct; 2 shares do not":"FAIL");
  return (ok1&&ok2&&!bad)?0:1;
}
