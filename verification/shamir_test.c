#include <stdio.h>
#include <string.h>
#include "Shamir.c"   /* include impl to KAT the static GF helpers */
/* Independent table-based reference (the pre-fix algorithm) to prove the constant-time gf_mul/gf_inv
   in Shamir.c compute byte-identical field results over the WHOLE input space. */
static unsigned char R_exp[512], R_log[256];
static void ref_init(void){
  unsigned int x=1; for(int i=0;i<255;i++){ R_exp[i]=(unsigned char)x; R_log[x]=(unsigned char)i;
    unsigned int hi=x&0x80; x=(x<<1)&0xff; if(hi)x^=0x1b; x^=R_exp[i]; }
  for(int i=255;i<512;i++) R_exp[i]=R_exp[i-255];
}
static unsigned char ref_mul(unsigned char a,unsigned char b){ return (a==0||b==0)?0:R_exp[R_log[a]+R_log[b]]; }
static unsigned char ref_inv(unsigned char a){ return R_exp[255-R_log[a]]; }

int main(void){
  ref_init();
  printf("=== GF(2^8) known-answer tests (AES field) ===\n");
  printf("gf_mul(0x57,0x83)=%02x (want c1)\n", gf_mul(0x57,0x83));
  printf("gf_mul(0x53,0xca)=%02x (want 01)\n", gf_mul(0x53,0xca));
  printf("gf_inv(0x53)=%02x (want ca)\n", gf_inv(0x53));

  /* constant-time gf_mul/gf_inv (Shamir.c) vs the table reference over all inputs */
  int mul_ok=1, inv_ok=1;
  for(int a=0;a<256;a++) for(int b=0;b<256;b++) if(gf_mul((unsigned char)a,(unsigned char)b)!=ref_mul((unsigned char)a,(unsigned char)b)) mul_ok=0;
  for(int a=1;a<256;a++){ if(gf_inv((unsigned char)a)!=ref_inv((unsigned char)a)) inv_ok=0;
                          if(gf_mul((unsigned char)a,gf_inv((unsigned char)a))!=1) inv_ok=0; }
  printf("CT gf_mul == table reference over all 65536 inputs: %s\n", mul_ok?"YES":"NO");
  printf("CT gf_inv == table + a*inv(a)==1 for all a!=0: %s\n", inv_ok?"YES":"NO");
  if(!mul_ok||!inv_ok){ printf("FAIL: constant-time GF mismatch\n"); return 1; }

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

  /* verifiable reconstruction: the checksum accepts a correct combine and detects a below-threshold one */
  {
    unsigned int cs_secret = shamir_secret_checksum(secret, L);
    unsigned int cs_good = shamir_secret_checksum(rec, L);    /* combine {1,3,5} */
    unsigned int cs_bad  = shamir_secret_checksum(rec3, L);   /* combine {1,2}   */
    printf("checksum verifies correct reconstruction: %s\n", cs_good==cs_secret ? "YES":"NO");
    printf("checksum detects below-threshold garbage:  %s\n", cs_bad !=cs_secret ? "YES":"NO");
    if(cs_good!=cs_secret || cs_bad==cs_secret){ printf("FAIL: checksum\n"); return 1; }
  }

  printf("\nSHARES_FOR_PY\n");
  for(int s=0;s<N;s++){ printf("%d:",sh[s].x); for(int i=0;i<L;i++) printf("%02x",sh[s].y[i]); printf("\n"); }
  printf("\n%s\n", (ok1&&ok2&&!bad)?"PASS: any 3 shares reconstruct; 2 shares do not":"FAIL");
  return (ok1&&ok2&&!bad)?0:1;
}
