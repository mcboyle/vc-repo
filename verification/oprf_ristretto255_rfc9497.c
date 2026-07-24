/*
 * oprf_ristretto255_rfc9497.c — the T2-5 (D-8) libsodium OPRF, proven against the OFFICIAL RFC 9497
 * OPRF(ristretto255, SHA-512) test vectors.
 *
 * CONTEXT. The from-scratch ristretto255 hash-to-group in oprf_ristretto_poc.c diverges from RFC 9496 /
 * RFC 9497 (finding recorded at suite step [94]; docs/OPRF-SPEC.md). ROADMAP item D-8 resolves it by
 * adopting libsodium's ristretto255 for the shipped OPRF / network-share path. This harness is the
 * conformance proof for that swap: it rebuilds the whole OPRF(ristretto255, SHA-512) chain on libsodium
 * primitives and checks it byte-for-byte against the CFRG official vectors (RFC 9497 Appendix A.1.1 /
 * cfrg/draft-irtf-cfrg-voprf poc/vectors/allVectors.json, identifier "ristretto255-SHA512", mode 0).
 *
 * Unlike the two-oracle check that MISSED the original bug (C PoC vs a Python twin sharing one
 * convention), this anchors to an INDEPENDENT authority — the standard's own vectors — so a hash-to-group
 * that is merely self-consistent cannot pass.
 *
 * CHAIN (RFC 9497 §3.3.1, base OPRF mode):
 *   contextString  = "OPRFV1-" || I2OSP(mode=0,1) || "-" || "ristretto255-SHA512"
 *   groupDST       = "HashToGroup-" || contextString                       (the 40-byte DST below)
 *   HashToGroup(x) = ristretto255_from_hash( expand_message_xmd_SHA512(x, groupDST, 64) )
 *   BlindedElement = Blind * HashToGroup(Input)
 *   EvaluationElement = skSm * BlindedElement
 *   N              = ScalarInverse(Blind) * EvaluationElement
 *   Output         = SHA512( I2OSP(len(Input),2) || Input || I2OSP(32,2) || Serialize(N) || "Finalize" )
 *
 * SCOPE. VERIFICATION-only: links libsodium, never the product. Any libsodium whose ristretto255
 * reproduces these vectors is a valid oracle (distro 1.0.18 verified); the D-8 shipping pin is >= 1.0.21.
 */
#include <stdio.h>
#include <string.h>
#include <sodium.h>

static int hx(const char *h, unsigned char *o, size_t max){ size_t n=strlen(h)/2,i; if(n>max)return -1;
	for(i=0;i<n;i++){unsigned v; sscanf(h+2*i,"%2x",&v); o[i]=(unsigned char)v;} return (int)n; }
static void ph(const char*l,const unsigned char*p,int n){printf("%s",l);for(int i=0;i<n;i++)printf("%02x",p[i]);printf("\n");}

/* RFC 9380 Section 5.3.1 expand_message_xmd, SHA-512, len_in_bytes = 64 (ell = 1). */
static void xmd64(const unsigned char*msg,size_t msglen,const unsigned char*dst,size_t dstlen,unsigned char out[64]){
	unsigned char dstp[256]; memcpy(dstp,dst,dstlen); dstp[dstlen]=(unsigned char)dstlen; size_t dstplen=dstlen+1;
	crypto_hash_sha512_state st; unsigned char b0[64],b1[64];
	unsigned char zpad[128]; memset(zpad,0,128);
	unsigned char lib[2]={0x00,0x40};      /* I2OSP(64,2) */
	unsigned char zero1=0x00, one1=0x01;
	crypto_hash_sha512_init(&st);
	crypto_hash_sha512_update(&st,zpad,128);
	crypto_hash_sha512_update(&st,msg,msglen);
	crypto_hash_sha512_update(&st,lib,2);
	crypto_hash_sha512_update(&st,&zero1,1);
	crypto_hash_sha512_update(&st,dstp,dstplen);
	crypto_hash_sha512_final(&st,b0);
	crypto_hash_sha512_init(&st);
	crypto_hash_sha512_update(&st,b0,64);
	crypto_hash_sha512_update(&st,&one1,1);
	crypto_hash_sha512_update(&st,dstp,dstplen);
	crypto_hash_sha512_final(&st,b1);
	memcpy(out,b1,64);
}

struct vec { const char*input,*blind,*be,*ee,*out; };

int main(void){
	if(sodium_init()<0){fprintf(stderr,"sodium_init failed\n");return 2;}
	/* groupDST = HashToGroup-OPRFV1-\x00-ristretto255-SHA512 (RFC 9497 A.1.1). */
	const char*DSThex="48617368546f47726f75702d4f50524656312d002d72697374726574746f3235352d534841353132";
	const char*skSmhex="5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e";
	unsigned char DST[64]; int DSTn=hx(DSThex,DST,sizeof DST);
	unsigned char skSm[32]; hx(skSmhex,skSm,sizeof skSm);

	struct vec V[2]={
	 {"00","64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
	  "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c",
	  "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e",
	  "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6"},
	 {"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a","64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
	  "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418",
	  "b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25",
	  "f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73"}};

	int fail=0;
	ph("groupDST = ",DST,DSTn);
	for(int k=0;k<2;k++){
		unsigned char input[64]; int inlen=hx(V[k].input,input,sizeof input);
		unsigned char blind[32],beExp[32],eeExp[32],outExp[64];
		hx(V[k].blind,blind,32); hx(V[k].be,beExp,32); hx(V[k].ee,eeExp,32); hx(V[k].out,outExp,64);

		unsigned char uni[64],P[32],be[32],ee[32],binv[32],N[32],out[64];
		xmd64(input,inlen,DST,DSTn,uni);
		if(crypto_core_ristretto255_from_hash(P,uni)!=0){printf("v%d from_hash fail\n",k);fail=1;continue;}
		if(crypto_scalarmult_ristretto255(be,blind,P)!=0){printf("v%d blind mult fail\n",k);fail=1;continue;}
		int okBE = memcmp(be,beExp,32)==0;
		if(crypto_scalarmult_ristretto255(ee,skSm,be)!=0){printf("v%d eval mult fail\n",k);fail=1;continue;}
		int okEE = memcmp(ee,eeExp,32)==0;
		crypto_core_ristretto255_scalar_invert(binv,blind);
		if(crypto_scalarmult_ristretto255(N,binv,ee)!=0){printf("v%d unblind fail\n",k);fail=1;continue;}
		crypto_hash_sha512_state st;
		unsigned char li[2]={(unsigned char)(inlen>>8),(unsigned char)(inlen&0xff)}, ln[2]={0x00,0x20};
		crypto_hash_sha512_init(&st);
		crypto_hash_sha512_update(&st,li,2);
		crypto_hash_sha512_update(&st,input,inlen);
		crypto_hash_sha512_update(&st,ln,2);
		crypto_hash_sha512_update(&st,N,32);
		crypto_hash_sha512_update(&st,(const unsigned char*)"Finalize",8);
		crypto_hash_sha512_final(&st,out);
		int okOut = memcmp(out,outExp,64)==0;

		printf("RFC9497 A.1.1 vector %d (Input=%s): BlindedElement %s | EvaluationElement %s | Output %s\n",
			k+1, V[k].input, okBE?"MATCH":"MISMATCH", okEE?"MATCH":"MISMATCH", okOut?"MATCH":"MISMATCH");
		if(!okBE){ph("    got be  ",be,32);ph("    exp be  ",beExp,32);}
		if(!okEE){ph("    got ee  ",ee,32);ph("    exp ee  ",eeExp,32);}
		if(!okOut){ph("    got out ",out,64);ph("    exp out ",outExp,64);}
		if(!(okBE&&okEE&&okOut))fail=1;
	}
	fprintf(stderr,"libsodium %s — RFC 9497 OPRF oracle (D-8; shipping pin >= 1.0.21)\n",sodium_version_string());
	if(fail){ printf("OPRF RISTRETTO255 RFC9497: FAIL\n"); return 1; }
	printf("OPRF RISTRETTO255 RFC9497: ALL MATCH (both official vectors, full Blind/Evaluate/Finalize chain)\n");
	return 0;
}
