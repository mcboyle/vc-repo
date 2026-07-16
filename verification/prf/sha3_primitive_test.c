#include <stdio.h>
#include <string.h>
#include "Sha3.h"

static int chk(const char* label, const unsigned char* md, const char* hex){
    char got[200]; int i; for(i=0;i<64;i++) sprintf(got+2*i,"%02x",md[i]);
    if(strcmp(got,hex)!=0){ printf("  [FAIL] %s\n    got %s\n    exp %s\n",label,got,hex); return 1;}
    printf("  [ OK ] %s\n",label); return 0;
}
static void sha3_512(const unsigned char* in, size_t n, unsigned char* md){
    SHA3_CTX c; sha3_512_init(&c); sha3_512_update(&c,in,n); sha3_512_final(&c,md);
}
int main(void){
    int f=0; unsigned char md[64]; unsigned char buf[200]; int i;
    sha3_512((const unsigned char*)"",0,md);
    f+=chk("SHA3-512(\"\")",md,"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    sha3_512((const unsigned char*)"abc",3,md);
    f+=chk("SHA3-512(\"abc\")",md,"b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
    for(i=0;i<200;i++) buf[i]=(unsigned char)i;
    sha3_512(buf,200,md);
    f+=chk("SHA3-512(0..199) multiblock",md,"ea5d05f19348dd589793354793a15f37a73b4c0bb4e750b9a00757dfce2f8b65a64191bb9b137de00feef6474cfd47abf7880efbc51614a5715df12cfe0caee3");
    memset(buf,0xaa,73);
    sha3_512(buf,71,md); f+=chk("SHA3-512(len=71 rate-1)",md,"788c1e7ba4544a59728005e031d804d57f89b7cc62f14217a6beb36f9884e3fef1b95735ef18485dd0cc8294d0b67bd6a05a1d4e49888b77f0044290c13ce0dc");
    sha3_512(buf,72,md); f+=chk("SHA3-512(len=72 rate)  ",md,"88b6ee71e908852a28c826597a401e39195b56766c80f4b297f3139f72d254d6e278a5c80e58293b50f08ab1d4d665831efee4cde2178580d3f9ff565f9b16d6");
    sha3_512(buf,73,md); f+=chk("SHA3-512(len=73 rate+1)",md,"db06fe4df7f2c3550b803b342947bd7034bf4f465776c3526de9c676db98ac877332024cfb6ebe5b808dd75b4593920657a71fbacdd76a931635b826c2a8b2bb");
    printf(f?"\nPRIMITIVE: %d FAIL\n":"\nPRIMITIVE: ALL FIPS-202 VECTORS PASS\n",f);
    return f?1:0;
}
