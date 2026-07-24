/*
 * voprf_poprf_ristretto255_rfc9497.c — T2-5 (D-8): the VERIFIABLE OPRF family on libsodium, proven
 * against the OFFICIAL RFC 9497 vectors. Companion to oprf_ristretto255_rfc9497.c (mode 0); this covers
 * VOPRF (mode 1) and POPRF (mode 2), including the DLEQ proof (RFC 9497 Sec 2.2) that voprf_ristretto_poc.c
 * implements from scratch — the same bespoke ristretto255 group flagged non-conformant at suite step [94].
 *
 * Anchored to CFRG official vectors (RFC 9497 Appendix A.1.2 VOPRF, A.1.3 POPRF):
 *   VOPRF: HashToGroup + chain reproduce BlindedElement/EvaluationElement/Output; VerifyProof ACCEPTS the
 *          official Proof; GenerateProof(ProofRandomScalar) reproduces the Proof bytes; a tampered
 *          EvaluationElement is REJECTED.
 *   POPRF: the Info-tweaked-key evaluation reproduces BlindedElement/EvaluationElement/Output; the DLEQ
 *          over the tweaked key verifies + regenerates; tamper rejected.
 *
 * Key RFC details pinned here (Sec 2.2 / Sec 4.1):
 *   HashToScalar = expand_message_xmd(SHA-512, msg, "HashToScalar-"||ctx, 64), interpreted LITTLE-endian,
 *                  reduced mod L  (== crypto_core_ristretto255_scalar_reduce, bytes as-is).
 *   compositeTranscript = I2OSP(len(seed),2)||seed || I2OSP(i,2) || I2OSP(32,2)||Ci || I2OSP(32,2)||Di || "Composite".
 *   challengeTranscript = I2OSP(32,2)||Bm(=serialized B) || a0(M)||a1(Z)||a2(t2)||a3(t3) each len-prefixed || "Challenge".
 * VERIFICATION-only (links libsodium, never the product).
 */
#include <stdio.h>
#include <string.h>
#include <sodium.h>

static int hx(const char*h,unsigned char*o,size_t m){size_t n=strlen(h)/2,i;if(n>m)return -1;for(i=0;i<n;i++){unsigned v;sscanf(h+2*i,"%2x",&v);o[i]=(unsigned char)v;}return(int)n;}
static void put2(unsigned char*p,int x){p[0]=(unsigned char)(x>>8);p[1]=(unsigned char)(x&0xff);}

static void xmd64(const unsigned char*msg,size_t ml,const unsigned char*dst,size_t dl,unsigned char out[64]){
	unsigned char dp[256];memcpy(dp,dst,dl);dp[dl]=(unsigned char)dl;size_t dpl=dl+1;
	crypto_hash_sha512_state st;unsigned char b0[64],b1[64],z[128];memset(z,0,128);
	unsigned char lib[2]={0,64},z1=0,o1=1;
	crypto_hash_sha512_init(&st);crypto_hash_sha512_update(&st,z,128);crypto_hash_sha512_update(&st,msg,ml);
	crypto_hash_sha512_update(&st,lib,2);crypto_hash_sha512_update(&st,&z1,1);crypto_hash_sha512_update(&st,dp,dpl);crypto_hash_sha512_final(&st,b0);
	crypto_hash_sha512_init(&st);crypto_hash_sha512_update(&st,b0,64);crypto_hash_sha512_update(&st,&o1,1);crypto_hash_sha512_update(&st,dp,dpl);crypto_hash_sha512_final(&st,b1);
	memcpy(out,b1,64);
}

/* contextString = "OPRFV1-"||I2OSP(mode,1)||"-ristretto255-SHA512" */
static unsigned char CTX[64]; static int CTXn;
static void mkctx(int mode){const char*a="OPRFV1-";const char*b="-ristretto255-SHA512";memcpy(CTX,a,7);CTX[7]=(unsigned char)mode;memcpy(CTX+8,b,strlen(b));CTXn=8+(int)strlen(b);}
static void dstOf(const char*pfx,unsigned char*out,int*ol){int p=(int)strlen(pfx);memcpy(out,pfx,p);memcpy(out+p,CTX,CTXn);*ol=p+CTXn;}

static void h2s(const unsigned char*msg,size_t ml,unsigned char out32[32]){
	unsigned char dst[80];int dl;dstOf("HashToScalar-",dst,&dl);
	unsigned char u[64];xmd64(msg,ml,dst,dl,u);crypto_core_ristretto255_scalar_reduce(out32,u);
}
static void h2g(const unsigned char*msg,size_t ml,unsigned char P[32]){
	unsigned char dst[80];int dl;dstOf("HashToGroup-",dst,&dl);
	unsigned char u[64];xmd64(msg,ml,dst,dl,u);crypto_core_ristretto255_from_hash(P,u);
}

/* ComputeComposites (single element) -> M,Z. B,C,D serialized 32B. */
static void composites(const unsigned char B[32],const unsigned char C[32],const unsigned char D[32],unsigned char M[32],unsigned char Z[32]){
	unsigned char sdst[80];int sl;dstOf("Seed-",sdst,&sl);
	crypto_hash_sha512_state st;unsigned char seed[64],l2[2];
	crypto_hash_sha512_init(&st);put2(l2,32);crypto_hash_sha512_update(&st,l2,2);crypto_hash_sha512_update(&st,B,32);
	put2(l2,sl);crypto_hash_sha512_update(&st,l2,2);crypto_hash_sha512_update(&st,sdst,sl);crypto_hash_sha512_final(&st,seed);
	unsigned char tr[2+64+2+2+32+2+32+9];int t=0;
	put2(tr+t,64);t+=2;memcpy(tr+t,seed,64);t+=64;put2(tr+t,0);t+=2;
	put2(tr+t,32);t+=2;memcpy(tr+t,C,32);t+=32;put2(tr+t,32);t+=2;memcpy(tr+t,D,32);t+=32;memcpy(tr+t,"Composite",9);t+=9;
	unsigned char d0[32];h2s(tr,t,d0);
	crypto_scalarmult_ristretto255(M,d0,C);crypto_scalarmult_ristretto255(Z,d0,D);
}
static void challenge(const unsigned char B[32],const unsigned char M[32],const unsigned char Z[32],const unsigned char t2[32],const unsigned char t3[32],unsigned char c[32]){
	unsigned char tr[5*(2+32)+9];int t=0;unsigned char l2[2];const unsigned char*a[5]={B,M,Z,t2,t3};
	for(int i=0;i<5;i++){put2(l2,32);memcpy(tr+t,l2,2);t+=2;memcpy(tr+t,a[i],32);t+=32;}
	memcpy(tr+t,"Challenge",9);t+=9;h2s(tr,t,c);
}
/* VerifyProof(A=G, B, C, D, proof) */
static int verify_proof(const unsigned char B[32],const unsigned char C[32],const unsigned char D[32],const unsigned char proof[64]){
	unsigned char M[32],Z[32],sG[32],cB[32],t2[32],sM[32],cZ[32],t3[32],ec[32];
	composites(B,C,D,M,Z);
	crypto_scalarmult_ristretto255_base(sG,proof+32);crypto_scalarmult_ristretto255(cB,proof,B);crypto_core_ristretto255_add(t2,sG,cB);
	crypto_scalarmult_ristretto255(sM,proof+32,M);crypto_scalarmult_ristretto255(cZ,proof,Z);crypto_core_ristretto255_add(t3,sM,cZ);
	challenge(B,M,Z,t2,t3,ec);return !memcmp(ec,proof,32);
}
/* GenerateProof(k, A=G, B, C, D, r) -> proof (c||s). B=k*G, D=k*C. */
static void gen_proof(const unsigned char k[32],const unsigned char B[32],const unsigned char C[32],const unsigned char D[32],const unsigned char r[32],unsigned char proof[64]){
	unsigned char M[32],Z[32],t2[32],t3[32],c[32],ck[32],s[32];
	composites(B,C,D,M,Z);
	crypto_scalarmult_ristretto255_base(t2,r);crypto_scalarmult_ristretto255(t3,r,M);
	challenge(B,M,Z,t2,t3,c);crypto_core_ristretto255_scalar_mul(ck,c,k);crypto_core_ristretto255_scalar_sub(s,r,ck);
	memcpy(proof,c,32);memcpy(proof+32,s,32);
}

static int g_fail=0;
static void ck(const char*label,int ok){printf("    %-46s %s\n",label,ok?"MATCH":"FAIL");if(!ok)g_fail=1;}

int main(void){
	if(sodium_init()<0)return 2;
	unsigned char input[1]={0}, info[9]; hx("7465737420696e666f",info,9);

	/* ---------- VOPRF (mode 1), Appendix A.1.2 Test Vector 1 ---------- */
	mkctx(1);
	{
		unsigned char pk[32],sk[32],blind[32],beE[32],eeE[32],outE[64],proof[64],rr[32],P[32],be[32],ee[32],gp[64],out[64];
		hx("c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e",pk,32);
		hx("e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909",sk,32);
		hx("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",blind,32);
		hx("863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945",beE,32);
		hx("aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e",eeE,32);
		hx("b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7da4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c",outE,64);
		hx("ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd066d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d",proof,64);
		hx("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e",rr,32);
		printf("VOPRF (mode 1) RFC 9497 A.1.2 vector 1:\n");
		h2g(input,1,P);crypto_scalarmult_ristretto255(be,blind,P);ck("BlindedElement",!memcmp(be,beE,32));
		crypto_scalarmult_ristretto255(ee,sk,be);ck("EvaluationElement",!memcmp(ee,eeE,32));
		/* pkS = sk*G; VOPRF DLEQ: GenerateProof(sk, G, pkS, blindedElement, evaluatedElement) i.e. B=pk,C=be,D=ee */
		ck("VerifyProof accepts official proof",verify_proof(pk,beE,eeE,proof));
		gen_proof(sk,pk,beE,eeE,rr,gp);ck("GenerateProof reproduces proof bytes",!memcmp(gp,proof,64));
		unsigned char bad[32];memcpy(bad,eeE,32);bad[0]^=1;ck("tampered EvaluationElement rejected",!verify_proof(pk,beE,bad,proof));
		/* Finalize: N=blind^-1*ee; Output=SHA512(len||input||32||N||"Finalize") */
		unsigned char binv[32],N[32];crypto_core_ristretto255_scalar_invert(binv,blind);crypto_scalarmult_ristretto255(N,binv,eeE);
		crypto_hash_sha512_state st;unsigned char li[2]={0,1},ln[2]={0,32};
		crypto_hash_sha512_init(&st);crypto_hash_sha512_update(&st,li,2);crypto_hash_sha512_update(&st,input,1);crypto_hash_sha512_update(&st,ln,2);crypto_hash_sha512_update(&st,N,32);crypto_hash_sha512_update(&st,(const unsigned char*)"Finalize",8);crypto_hash_sha512_final(&st,out);
		ck("Output",!memcmp(out,outE,64));
	}

	/* ---------- POPRF (mode 2), Appendix A.1.3 Test Vector 1 ---------- */
	mkctx(2);
	{
		unsigned char pk[32],sk[32],blind[32],beE[32],eeE[32],outE[64],proof[64],rr[32],P[32],be[32];
		hx("c647bef38497bc6ec077c22af65b696efa43bff3b4a1975a3e8e0a1c5a79d631",pk,32);
		hx("145c79c108538421ac164ecbe131942136d5570b16d8bf41a24d4337da981e07",sk,32);
		hx("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",blind,32);
		hx("c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715",beE,32);
		hx("1a4b860d808ff19624731e67b5eff20ceb2df3c3c03b906f5693e2078450d874",eeE,32);
		hx("ca688351e88afb1d841fde4401c79efebb2eb75e7998fa9737bd5a82a152406d38bd29f680504e54fd4587eddcf2f37a2617ac2fbd2993f7bdf45442ace7d221",outE,64);
		hx("41ad1a291aa02c80b0915fbfbb0c0afa15a57e2970067a602ddb9e8fd6b7100de32e1ecff943a36f0b10e3dae6bd266cdeb8adf825d86ef27dbc6c0e30c52206",proof,64);
		hx("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e",rr,32);
		printf("POPRF (mode 2) RFC 9497 A.1.3 vector 1:\n");
		h2g(input,1,P);crypto_scalarmult_ristretto255(be,blind,P);ck("BlindedElement",!memcmp(be,beE,32));
		/* framedInfo = "Info"||I2OSP(len(info),2)||info ; T=HashToScalar(framedInfo); t=sk+T */
		unsigned char fi[4+2+9];memcpy(fi,"Info",4);put2(fi+4,9);memcpy(fi+6,info,9);
		unsigned char T[32],t[32],tinv[32],ee[32];h2s(fi,sizeof fi,T);crypto_core_ristretto255_scalar_add(t,sk,T);
		crypto_core_ristretto255_scalar_invert(tinv,t);crypto_scalarmult_ristretto255(ee,tinv,beE);ck("EvaluationElement (t^-1*BE)",!memcmp(ee,eeE,32));
		/* tweakedKey = t*G ; DLEQ: B=tweakedKey, C=EvaluationElement, D=BlindedElement (blindedElement = t*evaluatedElement) */
		unsigned char tw[32];crypto_scalarmult_ristretto255_base(tw,t);
		/* client recomputes tweakedKey = T*G + pkS */
		unsigned char TG[32],twc[32];crypto_scalarmult_ristretto255_base(TG,T);crypto_core_ristretto255_add(twc,TG,pk);ck("tweakedKey == T*G+pkS",!memcmp(tw,twc,32));
		ck("VerifyProof accepts official proof",verify_proof(tw,eeE,beE,proof));
		unsigned char gp[64];gen_proof(t,tw,eeE,beE,rr,gp);ck("GenerateProof reproduces proof bytes",!memcmp(gp,proof,64));
		unsigned char bad[32];memcpy(bad,eeE,32);bad[0]^=1;ck("tampered EvaluationElement rejected",!verify_proof(tw,bad,beE,proof));
		/* Finalize: N=blind^-1*ee; Output=SHA512(len||input||len||info||32||N||"Finalize") */
		unsigned char binv[32],N[32];crypto_core_ristretto255_scalar_invert(binv,blind);crypto_scalarmult_ristretto255(N,binv,eeE);
		crypto_hash_sha512_state st;unsigned char li[2]={0,1},lif[2]={0,9},ln[2]={0,32},out[64];
		crypto_hash_sha512_init(&st);crypto_hash_sha512_update(&st,li,2);crypto_hash_sha512_update(&st,input,1);crypto_hash_sha512_update(&st,lif,2);crypto_hash_sha512_update(&st,info,9);crypto_hash_sha512_update(&st,ln,2);crypto_hash_sha512_update(&st,N,32);crypto_hash_sha512_update(&st,(const unsigned char*)"Finalize",8);crypto_hash_sha512_final(&st,out);
		ck("Output",!memcmp(out,outE,64));
	}

	fprintf(stderr,"libsodium %s — RFC 9497 VOPRF/POPRF oracle (D-8; shipping pin >= 1.0.21)\n",sodium_version_string());
	if(g_fail){printf("VOPRF/POPRF RISTRETTO255 RFC9497: FAIL\n");return 1;}
	printf("VOPRF/POPRF RISTRETTO255 RFC9497: ALL MATCH (official vectors: chain + DLEQ verify/generate + tamper-reject)\n");
	return 0;
}
