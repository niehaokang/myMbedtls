#ifndef __UT_PF_CP_H__
#define __UT_PF_CP_H__

#include <ut_sys_type.h>


#ifndef _UT_PF_CP_MACRO_
#define _UT_PF_CP_MACRO_

////////////////////////////////////////////////////////////////////////
// CLASS
#define UT_PF_CP_CLS_MD								0x0001
#define UT_PF_CP_CLS_SC								0x0002
#define UT_PF_CP_CLS_MC								0x0003
#define UT_PF_CP_CLS_AE								0x0004
#define UT_PF_CP_CLS_AC								0x0005
#define UT_PF_CP_CLS_GK								0x0006
#define UT_PF_CP_CLS_RD								0x0007

////////////////////////////////////////////////////////////////////////
// ACTION
#define UT_PF_CP_ACT_MD_MD5							0x1000				// MD[0] {0~32}
#define UT_PF_CP_ACT_MD_SHA1						0x1001
#define UT_PF_CP_ACT_MD_SHA224						0x1002
#define UT_PF_CP_ACT_MD_SHA256						0x1003
#define UT_PF_CP_ACT_MD_SHA384						0x1004
#define UT_PF_CP_ACT_MD_SHA512						0x1005
#define UT_PF_CP_ACT_MD_SM3							0x1006
#define UT_PF_CP_ACT_SC_AES_ECB						0x2000				// SC[0] {0~32}
#define UT_PF_CP_ACT_SC_AES_CBC						0x2001
#define UT_PF_CP_ACT_SC_AES_CTR						0x2002
#define UT_PF_CP_ACT_SC_AES_CTS						0x2003
#define UT_PF_CP_ACT_SC_AES_XTS						0x2004
#define UT_PF_CP_ACT_SC_DES_ECB						0x2005
#define UT_PF_CP_ACT_SC_DES_CBC						0x2006
#define UT_PF_CP_ACT_SC_DS3_ECB						0x2007
#define UT_PF_CP_ACT_SC_DS3_CBC						0x2008
#define UT_PF_CP_ACT_SC_SM4_ECB						0x2009
#define UT_PF_CP_ACT_SC_SM4_CBC						0x200a
#define UT_PF_CP_ACT_MC_HMAC_MD5					0x3000				// MC[0] {0~32}
#define UT_PF_CP_ACT_MC_HMAC_SHA1					0x3001
#define UT_PF_CP_ACT_MC_HMAC_SHA224					0x3002
#define UT_PF_CP_ACT_MC_HMAC_SHA256					0x3003
#define UT_PF_CP_ACT_MC_HMAC_SHA384					0x3004
#define UT_PF_CP_ACT_MC_HMAC_SHA512					0x3005
#define UT_PF_CP_ACT_MC_CMAC_AES					0x3006
#define UT_PF_CP_ACT_MC_CMAC_DES					0x3007
#define UT_PF_CP_ACT_MC_CMAC_DS3					0x3008
#define UT_PF_CP_ACT_MC_CCMC_AES					0x3009
#define UT_PF_CP_ACT_MC_CCMC_DES					0x300A
#define UT_PF_CP_ACT_MC_CCMC_DS3					0x300B
#define UT_PF_CP_ACT_MC_HMAC_SM3					0x300C
#define UT_PF_CP_ACT_AE_AES_GCM						0x4000				// AE[0] {0~32}
#define UT_PF_CP_ACT_AE_AES_CCM						0x4001
#define UT_PF_CP_ACT_AC_RSA_NOPAD					0x5000				// AC[0] {0~32}
#define UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5				0x5001
#define UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA1	0x5002
#define UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA224	0x5003
#define UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA256	0x5004
#define UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA384	0x5005
#define UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA512	0x5006 				// RSA Encrypt/Decrypt
#define UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_MD5			0x5007
#define UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA1			0x5008
#define UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA224		0x5009
#define UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA256		0x500A
#define UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA384		0x500B
#define UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA512		0x500C
#define UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA1		0x500D
#define UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA224	0x500E
#define UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA256	0x500F
#define UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA384	0x5010
#define UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA512	0x5011				// RSA Sign/Verify
#define UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA1			0x5012
#define UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA224		0x5013
#define UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA256		0x5014
#define UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA384		0x5015
#define UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA512		0x5016
#define UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA1			0x5017
#define UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA224		0x5018
#define UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA256		0x5019
#define UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA384		0x501A
#define UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA512		0x501B
#define UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA1			0x501C
#define UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA224		0x501D
#define UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA256		0x501E
#define UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA384		0x501F
#define UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA512		0x5100				// AC[1] {0~32}
#define UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA1			0x5101
#define UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA224		0x5102
#define UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA256		0x5103
#define UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA384		0x5104
#define UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA512		0x5105
#define UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA1			0x5106
#define UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA224		0x5107
#define UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA256		0x5108
#define UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA384		0x5109
#define UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA512		0x510A
#define UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA1			0x510B
#define UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA224		0x510C
#define UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA256		0x510D
#define UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA384		0x510E
#define UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA512		0x510F
#define UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA1			0x5110
#define UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA224		0x5111
#define UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA256		0x5112
#define UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA384		0x5113
#define UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA512		0x5114
#define UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA1			0x5115
#define UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA224		0x5116
#define UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA256		0x5117
#define UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA384		0x5118
#define UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA512		0x5119
#define UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA1			0x511A
#define UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA224		0x511B
#define UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA256		0x511C
#define UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA384		0x511D
#define UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA512		0x511E
#define UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA1			0x511F
#define UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA224		0x5200				// AC[2] {0~32}
#define UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA256		0x5201
#define UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA384		0x5202
#define UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA512		0x5203
#define UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA1			0x5204
#define UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA224		0x5205
#define UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA256		0x5206
#define UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA384		0x5207
#define UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA512		0x5208				// ECC Sign/Verify
#define UT_PF_CP_ACT_AC_SM2_SM3_SIGN				0x5209				// sm2 Sign
#define UT_PF_CP_ACT_AC_SM2_SM3_VERIFY				0x520a				// sm2 Verify
#define UT_PF_CP_ACT_AC_SM2_SM3_ENCRYPT				0x520b				// sm2 encrypt
#define UT_PF_CP_ACT_AC_SM2_SM3_DECRYPT				0x520c				// sm2 decrypt
#define UT_PF_CP_ACT_AC_ECDH_SEP160K1_SHARE_KEY     0x5209  			// ECC DH Share Key
#define UT_PF_CP_ACT_AC_ECDH_SEP160R1_SHARE_KEY     0x520A
#define UT_PF_CP_ACT_AC_ECDH_SEP160R2_SHARE_KEY     0x520B
#define UT_PF_CP_ACT_AC_ECDH_SEP192K1_SHARE_KEY     0x520C
#define UT_PF_CP_ACT_AC_ECDH_SEP192R1_SHARE_KEY     0x520D
#define UT_PF_CP_ACT_AC_ECDH_SEP224K1_SHARE_KEY     0x520E
#define UT_PF_CP_ACT_AC_ECDH_SEP224R1_SHARE_KEY     0x520F
#define UT_PF_CP_ACT_AC_ECDH_SEP256K1_SHARE_KEY     0x5210
#define UT_PF_CP_ACT_AC_ECDH_SEP256R1_SHARE_KEY     0x5211
#define UT_PF_CP_ACT_AC_ECDH_SEP384R1_SHARE_KEY     0x5212
#define UT_PF_CP_ACT_AC_ECDH_SEP521R1_SHARE_KEY     0x5213
#define UT_PF_CP_ACT_AC_DH_SHARE_KEY                0x5214
#define UT_PF_CP_ACT_AC_ECDH_BP224R1_SHARE_KEY                0x5215		// brainpool : https://tools.ietf.org/html/rfc6932
#define UT_PF_CP_ACT_AC_ECDH_BP256R1_SHARE_KEY                0x5216
#define UT_PF_CP_ACT_AC_ECDH_BP384R1_SHARE_KEY                0x5217
#define UT_PF_CP_ACT_AC_ECDH_BP512R1_SHARE_KEY                0x5218
#define UT_PF_CP_ACT_GK_RSA							0x6000				// GK[0] {0~32}
#define UT_PF_CP_ACT_GK_ECC_SEP160K1				0x6002
#define UT_PF_CP_ACT_GK_ECC_SEP160R1				0x6003
#define UT_PF_CP_ACT_GK_ECC_SEP160R2				0x6004
#define UT_PF_CP_ACT_GK_ECC_SEP192K1				0x6005
#define UT_PF_CP_ACT_GK_ECC_SEP192R1				0x6006
#define UT_PF_CP_ACT_GK_ECC_SEP224K1				0x6007
#define UT_PF_CP_ACT_GK_ECC_SEP224R1				0x6008
#define UT_PF_CP_ACT_GK_ECC_SEP256K1				0x6009
#define UT_PF_CP_ACT_GK_ECC_SEP256R1				0x600A
#define UT_PF_CP_ACT_GK_ECC_SEP384R1				0x600B
#define UT_PF_CP_ACT_GK_ECC_SEP521R1				0x600C
#define UT_PF_CP_ACT_GK_SM2_SEP160K1				0x600D
#define UT_PF_CP_ACT_GK_SM2_SEP160R1				0x600E
#define UT_PF_CP_ACT_GK_SM2_SEP160R2				0x600F
#define UT_PF_CP_ACT_GK_SM2_SEP192K1				0x6010
#define UT_PF_CP_ACT_GK_SM2_SEP192R1				0x6011
#define UT_PF_CP_ACT_GK_SM2_SEP224K1				0x6012
#define UT_PF_CP_ACT_GK_SM2_SEP224R1				0x6013
#define UT_PF_CP_ACT_GK_SM2_SEP256K1				0x6014
#define UT_PF_CP_ACT_GK_SM2_SEP256R1				0x6015
#define UT_PF_CP_ACT_GK_SM2_SEP384R1				0x6016
#define UT_PF_CP_ACT_GK_SM2_SEP521R1				0x6017
#define UT_PF_CP_ACT_GK_ECC_BRAINPOOL224R1			0x6018		//brainpool 
#define UT_PF_CP_ACT_GK_ECC_BRAINPOOL256R1			0x6019		//brainpool 
#define UT_PF_CP_ACT_GK_ECC_BRAINPOOL384R1			0x601a		//brainpool 
#define UT_PF_CP_ACT_GK_ECC_BRAINPOOL512R1			0x601b		//brainpool 
#define UT_PF_CP_ACT_RD_INST						0x7000				// RD[0] {0~32}
#define UT_PF_CP_ACT_RD_UNINST						0x7001
#define UT_PF_CP_ACT_RD_ADDDAT						0x7002
#define UT_PF_CP_ACT_RD_RESEED						0x7003
#define UT_PF_CP_ACT_RD_GENVEC						0x7004
#define UT_PF_CP_ACT_RD_GENVEC_RANGE				0x7005

#endif

#ifdef __cplusplus
extern "C" {
#endif

/** cryptographic operation context structure */
typedef struct __ut_pf_cp_context_t ut_pf_cp_context_t;

////////////////////////////////////////////////////////////////////////
ut_int32_t ut_pf_cp_sup_hwc(ut_int32_t action);
ut_int32_t ut_pf_cp_use_hwc(ut_int32_t action, ut_int32_t enable);

////////////////////////////////////////////////////////////////////////
ut_int32_t ut_pf_cp_open(
		ut_pf_cp_context_t **ctx,
		ut_int32_t cls, ut_int32_t act);

ut_int32_t ut_pf_cp_md_starts(
		ut_pf_cp_context_t *ctx);

ut_int32_t ut_pf_cp_md_update(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *src, ut_uint32_t srclen);

ut_int32_t ut_pf_cp_md_finish(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *dst, ut_uint32_t *dstlen);

ut_int32_t ut_pf_cp_sc_starts(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *key, ut_uint32_t keylen,
		ut_uint8_t *vec, ut_uint32_t veclen, ut_int32_t enc);

ut_int32_t ut_pf_cp_sc_update(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *src, ut_uint32_t srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen);

ut_int32_t ut_pf_cp_sc_finish(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *src, ut_uint32_t srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen);

ut_int32_t ut_pf_cp_mc_starts(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *key, ut_uint32_t keylen,
		ut_uint8_t *vec, ut_uint32_t veclen);

ut_int32_t ut_pf_cp_mc_update(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *src, ut_uint32_t srclen);

ut_int32_t ut_pf_cp_mc_finish(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *dst, ut_uint32_t *dstlen);

ut_int32_t ut_pf_cp_ae_starts(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *key, ut_uint32_t keylen,
		ut_uint8_t *vec, ut_uint32_t veclen, ut_int32_t enc,
		ut_uint32_t taglen, ut_uint32_t addlen, ut_uint32_t paylen);

ut_int32_t ut_pf_cp_ae_updadd(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *add, ut_uint32_t addlen);

ut_int32_t ut_pf_cp_ae_update(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *src, ut_uint32_t srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen);

ut_int32_t ut_pf_cp_ae_finish(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *src, ut_uint32_t srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen,
		ut_uint8_t *tag, ut_uint32_t *taglen);

ut_int32_t ut_pf_cp_ac_rsaenc(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__n, ut_uint32_t  __nlen,
		ut_uint8_t *__e, ut_uint32_t  __elen,
		ut_uint8_t *sal, ut_uint32_t  sallen,
		ut_uint8_t *src, ut_uint32_t  srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen);

ut_int32_t ut_pf_cp_ac_rsadec(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__n, ut_uint32_t  __nlen,
		ut_uint8_t *__d, ut_uint32_t  __dlen,
		ut_uint8_t *__e, ut_uint32_t  __elen,
		ut_uint8_t *sal, ut_uint32_t  sallen,
		ut_uint8_t *src, ut_uint32_t  srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen);

ut_int32_t ut_pf_cp_ac_rsadec_crt(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__n, ut_uint32_t  __nlen,
		ut_uint8_t *__e, ut_uint32_t  __elen,
		ut_uint8_t *__p, ut_uint32_t  __plen,
		ut_uint8_t *__q, ut_uint32_t  __qlen,
		ut_uint8_t *_dp, ut_uint32_t  _dplen,
		ut_uint8_t *_dq, ut_uint32_t  _dqlen,
		ut_uint8_t *_qp, ut_uint32_t  _qplen,
		ut_uint8_t *sal, ut_uint32_t  sallen,
		ut_uint8_t *src, ut_uint32_t  srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen);

ut_int32_t ut_pf_cp_ac_rsasig(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__n, ut_uint32_t  __nlen,
		ut_uint8_t *__d, ut_uint32_t  __dlen,
		ut_uint8_t *__e, ut_uint32_t  __elen,
		ut_uint8_t *sal, ut_uint32_t  sallen,
		ut_uint8_t *has, ut_uint32_t  haslen,
		ut_uint8_t *sig, ut_uint32_t *siglen);

ut_int32_t ut_pf_cp_ac_rsasig_crt(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__n, ut_uint32_t  __nlen,
		ut_uint8_t *__e, ut_uint32_t  __elen,
		ut_uint8_t *__p, ut_uint32_t  __plen,
		ut_uint8_t *__q, ut_uint32_t  __qlen,
		ut_uint8_t *_dp, ut_uint32_t  _dplen,
		ut_uint8_t *_dq, ut_uint32_t  _dqlen,
		ut_uint8_t *_qp, ut_uint32_t  _qplen,
		ut_uint8_t *sal, ut_uint32_t  sallen,
		ut_uint8_t *has, ut_uint32_t  haslen,
		ut_uint8_t *sig, ut_uint32_t *siglen);

ut_int32_t ut_pf_cp_ac_rsavfy(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__n, ut_uint32_t __nlen,
		ut_uint8_t *__e, ut_uint32_t __elen,
		ut_uint8_t *sal, ut_uint32_t sallen,
		ut_uint8_t *has, ut_uint32_t haslen,
		ut_uint8_t *sig, ut_uint32_t siglen);

ut_int32_t ut_pf_cp_ac_eccsig(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__k, ut_uint32_t  __klen,
		ut_uint8_t *has, ut_uint32_t  haslen,
		ut_uint8_t *sig, ut_uint32_t *siglen);

ut_int32_t ut_pf_cp_ac_eccvfy(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__x, ut_uint32_t __xlen,
		ut_uint8_t *__y, ut_uint32_t __ylen,
		ut_uint8_t *has, ut_uint32_t haslen,
		ut_uint8_t *sig, ut_uint32_t siglen);

ut_int32_t ut_pf_cp_gk_ecckey(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__x, ut_uint32_t *__xlen,
		ut_uint8_t *__y, ut_uint32_t *__ylen,
		ut_uint8_t *__k, ut_uint32_t *__klen);

 
ut_int32_t ut_pf_cp_gk_rsakey(
		ut_pf_cp_context_t *ctx,
		ut_int32_t bit,
		ut_int32_t exponent,
		ut_uint8_t *__e, ut_uint32_t *__elen,
		ut_uint8_t *__n, ut_uint32_t *__nlen,
		ut_uint8_t *__d, ut_uint32_t *__dlen,
		ut_uint8_t *__p, ut_uint32_t *__plen,
		ut_uint8_t *__q, ut_uint32_t *__qlen,
		ut_uint8_t *_dp, ut_uint32_t *_dplen,
		ut_uint8_t *_dq, ut_uint32_t *_dqlen,
		ut_uint8_t *_qp, ut_uint32_t *_qplen);

ut_int32_t ut_pf_cp_ac_sm2enc(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__k, ut_uint32_t __klen,
		ut_uint8_t *src, ut_uint32_t  srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen);

ut_int32_t ut_pf_cp_ac_sm2dec(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__x, ut_uint32_t __xlen,
		ut_uint8_t *__y, ut_uint32_t __ylen,
		ut_uint8_t *src, ut_uint32_t srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen);

ut_int32_t ut_pf_cp_ac_sm2sig(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__k, ut_uint32_t __klen,
		ut_uint8_t *id,  ut_uint32_t  idlen,
		ut_uint8_t *has, ut_uint32_t haslen,
		ut_uint8_t *sig, ut_uint32_t *siglen);

ut_int32_t ut_pf_cp_ac_sm2vfy(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__x, ut_uint32_t __xlen,
		ut_uint8_t *__y, ut_uint32_t __ylen,
		ut_uint8_t *id,  ut_uint32_t  idlen,
		ut_uint8_t *has, ut_uint32_t haslen,
		ut_uint8_t *sig, ut_uint32_t siglen);

ut_int32_t ut_pf_cp_gk_sm2key(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__x, ut_uint32_t *__xlen,
		ut_uint8_t *__y, ut_uint32_t *__ylen,
		ut_uint8_t *__k, ut_uint32_t *__klen);

ut_int32_t ut_pf_cp_rd_random(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *rnd, ut_uint32_t rndlen);

ut_int32_t ut_pf_cp_close(
		ut_pf_cp_context_t *ctx);

ut_int32_t ut_pf_cp_ac_ecdh   (ut_pf_cp_context_t  *ctx ,
                               ut_uint8_t * k1 ,
                               ut_uint32_t k1len ,
                               ut_uint8_t * x1 ,
                               ut_uint32_t x1len ,
                               ut_uint8_t * y1 ,
                               ut_uint32_t y1len ,
                               ut_uint8_t * x2 ,
                               ut_uint32_t x2len ,
                               ut_uint8_t * y2 ,
                               ut_uint32_t y2len ,
                               ut_uint8_t * sk ,
                               ut_uint32_t * sklen ) ;

#ifdef __cplusplus
}
#endif
#endif
