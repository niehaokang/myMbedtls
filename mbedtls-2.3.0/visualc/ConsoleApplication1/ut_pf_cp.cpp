#include "ut_pf_cp.h"
#include "ut_pf_cp_inner.h"
#include<stdlib.h>
#include<string.h>
#include<time.h>
////////////////////////////////////////////////////////////////////////
/* For CMAC Calculation */
static unsigned char const_Rb[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
};

////////////////////////////////////////////////////////////////////////
static ut_pf_cp_info_t hwc_sup_Alg = {
	0x00000001,
	{
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000 },	// md
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000 },	// sc
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000 },	// mc
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000 },	// ae
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000 },	// ac
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000 },	// gk
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000 }	// rd
	}
};

////////////////////////////////////////////////////////////////////////
static ut_pf_cp_info_t hwc_use_Alg = {
	0x00000001,
	{
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000 },	// md
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000 },	// sc
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000 },	// mc
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000 },	// ae
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000 },	// ac
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000 },	// gk
		{ 0x00000000, 0x00000000, 0x00000000, 0x00000000 }	// rd
	}
};

////////////////////////////////////////////////////////////////////////
static ut_int32_t use_hwc(ut_int32_t action) {
	ut_int32_t cls = 0;
	ut_int32_t idx = 0;
	ut_int32_t ofs = 0;

	cls = ((action & 0xF000) >> 12); // 1 ~ 7
	if ( cls < 1 ) return 0;
	if ( cls > 7 ) return 0;
	idx = ((action & 0x0F00) >>  8); // 0 ~ 4
	if ( idx > 4  )	return 0;
	ofs = ((action & 0x00FF) >>  0); // 0 ~ 31
	if ( idx > 31 )	return 0;

	return ((hwc_use_Alg.cls[cls-1][idx] >> ofs) & 0x0001);
}

ut_int32_t ut_pf_cp_sup_hwc(ut_int32_t action) {
	ut_int32_t cls = 0;
	ut_int32_t idx = 0;
	ut_int32_t ofs = 0;

	cls = ((action & 0xF000) >> 12); // 1 ~ 7
	if ( cls < 1 ) return 0;
	if ( cls > 7 ) return 0;
	idx = ((action & 0x0F00) >> 8); // 0 ~ 4
	if ( idx > 4  )	return 0;
	ofs = ((action & 0x00FF) >> 0); // 0 ~ 31
	if ( idx > 31 )	return 0;

	return ((hwc_sup_Alg.cls[cls-1][idx] >> ofs) & 0x0001);
}

ut_int32_t ut_pf_cp_use_hwc(ut_int32_t action, ut_int32_t enable) {
	ut_int32_t r = 0;
	ut_int32_t cls = 0;
	ut_int32_t idx = 0;
	ut_int32_t ofs = 0;

	cls = ((action & 0xF000) >> 12); // 1 ~ 7
	if ( cls < 1 ) return 0;
	if ( cls > 7 ) return 0;
	idx = ((action & 0x0F00) >> 8); // 0 ~ 4
	if ( idx > 4  )	return 0;
	ofs = ((action & 0x00FF) >> 0); // 0 ~ 31
	if ( idx > 31 )	return 0;

	if ( enable & ut_pf_cp_sup_hwc(action) ) {
		hwc_use_Alg.cls[cls-1][idx] |=  (1<<ofs); r = 1;
	} else {
		hwc_use_Alg.cls[cls-1][idx] &= ~(1<<ofs); r = 0;
	}

	return r;
}
void xts128_init(struct xts128_context *ctx, const unsigned char iv[16],
	void *key1, void *key2, block128_f block)
{
	memset(ctx, 0, sizeof(struct xts128_context));

	/* initialize */
	ctx->key1 = key1;
	ctx->key2 = key2;
	ctx->block1 = 0x00;
	ctx->block2 = block;

	memcpy(ctx->tweak.c, iv, 16);
	(*ctx->block2)(ctx->tweak.c, ctx->tweak.c, ctx->key2);
}
int xts128_encrypt(const struct xts128_context *ctx, const unsigned char iv[16],
	const unsigned char *inp, unsigned char *out, size_t len, int enc)
{
	const union { long one; char little; } is_endian = { 1 };
	union { u64 u[2]; u32 d[4]; u8 c[16]; } tweak, scratch;
	unsigned int i;

	if (len<16) return -1;

	memcpy(tweak.c, iv, 16);

	(*ctx->block2)(tweak.c, tweak.c, ctx->key2);

	if (!enc && (len % 16)) len -= 16;

	while (len >= 16) {

		scratch.u[0] = ((u64*)inp)[0] ^ tweak.u[0];
		scratch.u[1] = ((u64*)inp)[1] ^ tweak.u[1];

		(*ctx->block1)(scratch.c, scratch.c, ctx->key1);

		((u64*)out)[0] = scratch.u[0] ^= tweak.u[0];
		((u64*)out)[1] = scratch.u[1] ^= tweak.u[1];

		inp += 16;
		out += 16;
		len -= 16;

		if (len == 0)	return 0;

		if (is_endian.little) {
			unsigned int carry, res;

			res = 0x87 & (((int)tweak.d[3]) >> 31);
			carry = (unsigned int)(tweak.u[0] >> 63);
			tweak.u[0] = (tweak.u[0] << 1) ^ res;
			tweak.u[1] = (tweak.u[1] << 1) | carry;
		}
		else {
			size_t c;

			for (c = 0, i = 0; i<16; ++i) {
				/*+ substitutes for |, because c is 1 bit */
				c += ((size_t)tweak.c[i]) << 1;
				tweak.c[i] = (u8)c;
				c = c >> 8;
			}
			tweak.c[0] ^= (u8)(0x87 & (0 - c));
		}
	}

	if (enc) {
		for (i = 0; i<len; ++i) {
			u8 c = inp[i];
			out[i] = scratch.c[i];
			scratch.c[i] = c;
		}
		scratch.u[0] ^= tweak.u[0];
		scratch.u[1] ^= tweak.u[1];
		(*ctx->block1)(scratch.c, scratch.c, ctx->key1);
		scratch.u[0] ^= tweak.u[0];
		scratch.u[1] ^= tweak.u[1];
		memcpy(out - 16, scratch.c, 16);
	}
	else {
		union { u64 u[2]; u8 c[16]; } tweak1;

		if (is_endian.little) {
			unsigned int carry, res;

			res = 0x87 & (((int)tweak.d[3]) >> 31);
			carry = (unsigned int)(tweak.u[0] >> 63);
			tweak1.u[0] = (tweak.u[0] << 1) ^ res;
			tweak1.u[1] = (tweak.u[1] << 1) | carry;
		}
		else {
			size_t c;

			for (c = 0, i = 0; i<16; ++i) {
				/*+ substitutes for |, because c is 1 bit */
				c += ((size_t)tweak.c[i]) << 1;
				tweak1.c[i] = (u8)c;
				c = c >> 8;
			}
			tweak1.c[0] ^= (u8)(0x87 & (0 - c));
		}

		scratch.u[0] = ((u64*)inp)[0] ^ tweak1.u[0];
		scratch.u[1] = ((u64*)inp)[1] ^ tweak1.u[1];

		(*ctx->block1)(scratch.c, scratch.c, ctx->key1);
		scratch.u[0] ^= tweak1.u[0];
		scratch.u[1] ^= tweak1.u[1];

		for (i = 0; i<len; ++i) {
			u8 c = inp[16 + i];
			out[16 + i] = scratch.c[i];
			scratch.c[i] = c;
		}
		scratch.u[0] ^= tweak.u[0];
		scratch.u[1] ^= tweak.u[1];
		(*ctx->block1)(scratch.c, scratch.c, ctx->key1);

		((u64*)out)[0] = scratch.u[0] ^ tweak.u[0];
		((u64*)out)[1] = scratch.u[1] ^ tweak.u[1];
	}

	return 0;
}

int xts128_finish(struct xts128_context *ctx,
	const unsigned char *inp, unsigned char *out, size_t len, int enc)
{
	unsigned int i;
	unsigned int carry, res;

	if (len<16) return -1;

	if (!enc && (len % 16)) len -= 16;

	while (len >= 16) {

		ctx->scratch.u[0] = ((u64*)inp)[0] ^ ctx->tweak.u[0];
		ctx->scratch.u[1] = ((u64*)inp)[1] ^ ctx->tweak.u[1];

		(*ctx->block1)(ctx->scratch.c, ctx->scratch.c, ctx->key1);

		((u64*)out)[0] = ctx->scratch.u[0] ^= ctx->tweak.u[0];
		((u64*)out)[1] = ctx->scratch.u[1] ^= ctx->tweak.u[1];

		inp += 16; out += 16; len -= 16;

		if (len == 0)	return 0;

		res = 0x87 & (((int)ctx->tweak.d[3]) >> 31);
		carry = (unsigned int)(ctx->tweak.u[0] >> 63);
		ctx->tweak.u[0] = (ctx->tweak.u[0] << 1) ^ res;
		ctx->tweak.u[1] = (ctx->tweak.u[1] << 1) | carry;
	}

	if (enc) {

		for (i = 0; i < len; ++i) {
			u8 c = inp[i]; out[i] = ctx->scratch.c[i]; ctx->scratch.c[i] = c;
		}

		ctx->scratch.u[0] ^= ctx->tweak.u[0];
		ctx->scratch.u[1] ^= ctx->tweak.u[1];

		(*ctx->block1)(ctx->scratch.c, ctx->scratch.c, ctx->key1);

		ctx->scratch.u[0] ^= ctx->tweak.u[0];
		ctx->scratch.u[1] ^= ctx->tweak.u[1];
		memcpy(out - 16, ctx->scratch.c, 16);
	}
	else {

		union { u64 u[2]; u8 c[16]; } tweak1;

		res = 0x87 & (((int)ctx->tweak.d[3]) >> 31);
		carry = (unsigned int)(ctx->tweak.u[0] >> 63);
		tweak1.u[0] = (ctx->tweak.u[0] << 1) ^ res;
		tweak1.u[1] = (ctx->tweak.u[1] << 1) | carry;

		ctx->scratch.u[0] = ((u64*)inp)[0] ^ tweak1.u[0];
		ctx->scratch.u[1] = ((u64*)inp)[1] ^ tweak1.u[1];

		(*ctx->block1)(ctx->scratch.c, ctx->scratch.c, ctx->key1);

		ctx->scratch.u[0] ^= tweak1.u[0];
		ctx->scratch.u[1] ^= tweak1.u[1];


		for (i = 0; i < len; ++i) {
			u8 c = inp[16 + i]; out[16 + i] = ctx->scratch.c[i]; ctx->scratch.c[i] = c;
		}
		ctx->scratch.u[0] ^= ctx->tweak.u[0];
		ctx->scratch.u[1] ^= ctx->tweak.u[1];
		(*ctx->block1)(ctx->scratch.c, ctx->scratch.c, ctx->key1);

		((u64*)out)[0] = ctx->scratch.u[0] ^ ctx->tweak.u[0];
		((u64*)out)[1] = ctx->scratch.u[1] ^ ctx->tweak.u[1];
	}

	return 0;
}


////////////////////////////////////////////////////////////////////////

static void aes_encrypt(const unsigned char input[16],
                          unsigned char output[16] , mbedtls_aes_context *ctx)
{
	mbedtls_aes_encrypt( ctx,input , output );
}
static void aes_decrypt(const unsigned char input[16],
                          unsigned char output[16] , mbedtls_aes_context *ctx)
{
	mbedtls_aes_decrypt( ctx,input , output );
}

#define _aes_encrypt_block  aes_encrypt
#define _aes_decrypt_block  aes_decrypt
#define _des_encrypt_block  psDesEncryptBlock
#define _des_decrypt_block  psDesDecryptBlock
#define _ds3_encrypt_block	psDes3EncryptBlock
#define _ds3_decrypt_block	psDes3DecryptBlock
#define _sm4_encrypt_block  psSm4EncryptBlock
#define _sm4_decrypt_block  psSm4DecryptBlock

static void _aes_cbc_encrypt(ut_uint8_t *src, ut_uint8_t *dst, ut_uint32_t len,
	void *key, ut_uint8_t vec[16], ut_int32_t enc)
{
	 
}

static void _xor(ut_uint8_t *a, ut_uint8_t *b, ut_uint8_t *dst, ut_int32_t n)
{
	int i;
	for (i = 0; i < n; i++) {
		dst[i] = a[i] ^ b[i];
	}
}

static void _lsh(ut_uint8_t *src, ut_uint8_t *dst, ut_int32_t n)
{
	int i;
	unsigned char of = 0;

	for ( i = n - 1; i >= 0; i-- ) {
		dst[i]  = src[i] << 1;
		dst[i] |= of;
		of = (src[i] & 0x80) ? (1) : (0);
	}
	return;
}

static void _padding(ut_uint8_t *lastb, ut_uint8_t *pad, ut_int32_t length, ut_int32_t n)
{
	int i;

	for ( i = 0; i < n; i++ ) {
		if ( i < length ) {
			pad[i] = lastb[i];
		} else if ( i == length ) {
			pad[i] = 0x80;
		} else {
			pad[i] = 0x00;
		}
	}
}

static ut_int32_t _rand(void *p_rng, ut_uint8_t *rnd, ut_uint32_t rndlen)
{
	ut_int32_t r = 0;
 
	return r;
}

////////////////////////////////////////////////////////////////////////
   
static int init_random(ac_context_t *ctx)
{
	const char * pers = "beanpodtech_rand_for_mask";
	int r=0;
	mbedtls_ctr_drbg_init(&ctx->rsa.rng_ctx);
	mbedtls_entropy_init(&ctx->rsa.entropy_ctx);
	
	MBEDRET(UTPFCP_ERR_RNG_SEED,mbedtls_ctr_drbg_seed(&ctx->rsa.rng_ctx, mbedtls_entropy_func, &ctx->rsa.entropy_ctx,
		(const unsigned char *)pers,
		strlen(pers)));
end:		
	if(r<0)
	{
		mbedtls_ctr_drbg_free(&ctx->rsa.rng_ctx);
		mbedtls_entropy_free(&ctx->rsa.entropy_ctx);
	}
	return r;
}
static ut_int32_t import_rsa_pub_key(ac_context_t *ctx,
	ut_uint8_t *__n, ut_uint32_t  __nlen,
	ut_uint8_t *__e, ut_uint32_t  __elen)
{
	ut_int32_t  r = 0;

	if (__n == NULL || __e == NULL)
		return -UTPFCP_ERR_INVALID_PARAMS;

	mbedtls_rsa_init(&ctx->rsa.key, 0, 0);
	ctx->rsa.key.len = __nlen;
	MBEDRET(UTPFCP_ERR_INVALID_PARAMS, mbedtls_mpi_read_binary(&(ctx->rsa.key.N), __n, __nlen));
	MBEDRET(UTPFCP_ERR_INVALID_PARAMS, mbedtls_mpi_read_binary(&(ctx->rsa.key.E), __e, __elen));
	r = init_random(ctx);
end:
	if (r<0)
	{
		mbedtls_rsa_free(&ctx->rsa.key);
	}
	return r;
}

static ut_int32_t import_rsa_pri_key(ac_context_t *ctx,
	ut_uint8_t *__n, ut_uint32_t  __nlen,
	ut_uint8_t *__d, ut_uint32_t  __dlen,
	ut_uint8_t *__e, ut_uint32_t  __elen,
	ut_uint8_t *__p, ut_uint32_t  __plen,
	ut_uint8_t *__q, ut_uint32_t  __qlen,
	ut_uint8_t *_dp, ut_uint32_t  _dplen,
	ut_uint8_t *_dq, ut_uint32_t  _dqlen,
	ut_uint8_t *_qp, ut_uint32_t  _qplen)
{
	ut_int32_t  r = 0;
	ut_int32_t  optimized = 0;//for CRT

	if (__p != NULL && __q != NULL &&
		_dp != NULL && _dq != NULL && _qp != NULL)
		optimized = 1;
	else
		optimized = 0;
	mbedtls_rsa_init(&ctx->rsa.key, 0, 0);
	ctx->rsa.key.len = __nlen;
	if (__n != NULL && __nlen >0)
		MBEDRET(UTPFCP_ERR_INVALID_PARAMS, mbedtls_mpi_read_binary(&(ctx->rsa.key.N), __n, __nlen));
	if (__e != NULL && __elen >0)
		MBEDRET(UTPFCP_ERR_INVALID_PARAMS, mbedtls_mpi_read_binary(&(ctx->rsa.key.E), __e, __elen));
	if (__d != NULL && __dlen >0)
		MBEDRET(UTPFCP_ERR_INVALID_PARAMS, mbedtls_mpi_read_binary(&(ctx->rsa.key.D), __d, __dlen));

	if (optimized)
	{
		MBEDRET(UTPFCP_ERR_INVALID_PARAMS, mbedtls_mpi_read_binary(&(ctx->rsa.key.P), __p, __plen));
		MBEDRET(UTPFCP_ERR_INVALID_PARAMS, mbedtls_mpi_read_binary(&(ctx->rsa.key.Q), __q, __qlen));
		MBEDRET(UTPFCP_ERR_INVALID_PARAMS, mbedtls_mpi_read_binary(&(ctx->rsa.key.DP), _dp, _dplen));
		MBEDRET(UTPFCP_ERR_INVALID_PARAMS, mbedtls_mpi_read_binary(&(ctx->rsa.key.DQ), _dq, _dqlen));
		MBEDRET(UTPFCP_ERR_INVALID_PARAMS, mbedtls_mpi_read_binary(&(ctx->rsa.key.QP), _qp, _qplen));
	}
	r = init_random(ctx);
end:
	if (r<0)
	{
		mbedtls_rsa_free(&ctx->rsa.key);
	}
	return r;
}

static ut_int32_t rsa_rel_key(ac_context_t *ctx)
{
	mbedtls_rsa_free( &ctx->rsa.key );
	mbedtls_ctr_drbg_free(&ctx->rsa.rng_ctx);
	mbedtls_entropy_free(&ctx->rsa.entropy_ctx);
	return 0;
}


static mbedtls_md_type_t get_hashid(int action)
{
	mbedtls_md_type_t r = MBEDTLS_MD_NONE;
	switch (action)
	{
	case UT_PF_CP_ACT_AC_RSA_NOPAD:break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5:break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA1:r = MBEDTLS_MD_SHA1; break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA224:r = MBEDTLS_MD_SHA224; break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA256:r = MBEDTLS_MD_SHA256; break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA384:r = MBEDTLS_MD_SHA384; break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA512:r = MBEDTLS_MD_SHA512; break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_MD5:r = MBEDTLS_MD_MD5; break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA1:r = MBEDTLS_MD_SHA1; break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA224:r = MBEDTLS_MD_SHA224; break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA256:r = MBEDTLS_MD_SHA256; break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA384:r = MBEDTLS_MD_SHA384; break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA512:r = MBEDTLS_MD_SHA512; break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA1:r = MBEDTLS_MD_SHA1; break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA224:r = MBEDTLS_MD_SHA224; break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA256:r = MBEDTLS_MD_SHA256; break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA384:r = MBEDTLS_MD_SHA384; break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA512:r = MBEDTLS_MD_SHA512; break;
	default:break;
	}
	return r;
}


static ut_int32_t rsa_encrypt(
	ac_context_t *ctx, ut_int32_t action,
	ut_uint8_t *sal, ut_uint32_t  sallen,
	ut_uint8_t *src, ut_uint32_t  srclen,
	ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t  r = 0;
	int i = 0;
	if (*dstlen< ctx->rsa.key.len)
		return -UTPFCP_ERR_TOOSMALLLEN;
	((void)sal);
	sallen = 0;
	switch (action) {
	case UT_PF_CP_ACT_AC_RSA_NOPAD:
		if (srclen != ctx->rsa.key.len)
			return -UTPFCP_ERR_INVALID_PARAMS;
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_public(&ctx->rsa.key,
			(const unsigned char *)src,
			(unsigned char *)dst));
		*dstlen = ctx->rsa.key.len;
		break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5:
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_rsaes_pkcs1_v15_encrypt(&ctx->rsa.key, mbedtls_ctr_drbg_random,
			&ctx->rsa.rng_ctx,
			MBEDTLS_RSA_PUBLIC,
			srclen, src, dst));
		*dstlen = ctx->rsa.key.len;
		break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA1:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA224:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA256:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA384:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA512:
		ctx->rsa.key.hash_id = get_hashid(action);
		ctx->rsa.key.padding = MBEDTLS_RSA_PKCS_V21;
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_rsaes_oaep_encrypt(&ctx->rsa.key, mbedtls_ctr_drbg_random,
			&ctx->rsa.rng_ctx,
			MBEDTLS_RSA_PUBLIC,
			NULL, 0,
			srclen,
			(const unsigned char *)src,
			(unsigned char *)dst
		));
		*dstlen = ctx->rsa.key.len;
		break;
	default:	return -UTPFCP_ERR_UNKNOWN_ACTION;;
	}
end:
	return r;
}

static ut_int32_t rsa_decrypt(
	ac_context_t *ctx, ut_int32_t action,
	ut_uint8_t *sal, ut_uint32_t  sallen,
	ut_uint8_t *src, ut_uint32_t  srclen,
	ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t  r = 0;
	int i = 0;
	size_t outlen = *dstlen;
	((void)sal);
	sallen = 0;
	if (*dstlen< ctx->rsa.key.len)
		return -UTPFCP_ERR_TOOSMALLLEN;
	if (srclen != ctx->rsa.key.len)
		return -UTPFCP_ERR_INVALID_PARAMS;
	switch (action) {
	case UT_PF_CP_ACT_AC_RSA_NOPAD:
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_private(&ctx->rsa.key,
			mbedtls_ctr_drbg_random,
			&ctx->rsa.rng_ctx,
			(const unsigned char *)src,
			(unsigned char *)dst));
		*dstlen = ctx->rsa.key.len;
		break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5:
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_rsaes_pkcs1_v15_decrypt(&ctx->rsa.key,
			mbedtls_ctr_drbg_random,
			&ctx->rsa.rng_ctx,
			MBEDTLS_RSA_PRIVATE, &outlen,
			(const unsigned char *)src,
			(unsigned char *)dst,
			outlen));
		*dstlen = outlen;
		break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA1:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA224:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA256:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA384:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA512:
		ctx->rsa.key.hash_id = get_hashid(action);
		ctx->rsa.key.padding = MBEDTLS_RSA_PKCS_V21;
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_rsaes_oaep_decrypt(&ctx->rsa.key, mbedtls_ctr_drbg_random,
			&ctx->rsa.rng_ctx,
			MBEDTLS_RSA_PRIVATE,
			NULL, 0,
			&outlen,
			(const unsigned char *)src,
			(unsigned char *)dst,
			*dstlen));
		*dstlen = outlen;
		break;
	default:				return -UTPFCP_ERR_UNKNOWN_ACTION;
	}
end:
	return r;
}

static ut_int32_t rsa_sign(
	ac_context_t *ctx, ut_int32_t action,
	ut_uint8_t *sal, ut_uint32_t  sallen,
	ut_uint8_t *hash, ut_uint32_t  hashlen,
	ut_uint8_t *sig, ut_uint32_t *siglen)
{
	ut_int32_t  r = 0;
	ut_uint32_t l = ctx->rsa.key.len;
	((void)sal);
	sallen = 0;
	if (hash == NULL || sig == NULL ||
		siglen == NULL || *siglen < l)
		return -UTPFCP_ERR_INVALID_PARAMS;
	ctx->rsa.key.hash_id = get_hashid(action);
	switch (action) {
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_MD5:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA1:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA224:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA256:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA384:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA512:
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_rsassa_pkcs1_v15_sign(&ctx->rsa.key, mbedtls_ctr_drbg_random,
			&ctx->rsa.rng_ctx,
			MBEDTLS_RSA_PRIVATE,
			(mbedtls_md_type_t)ctx->rsa.key.hash_id,
			(unsigned int)hashlen,
			(const unsigned char *)hash,
			(unsigned char *)sig));
		*siglen = ctx->rsa.key.len;
		break;

	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA1:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA224:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA256:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA384:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA512:
		ctx->rsa.key.padding = MBEDTLS_RSA_PKCS_V21;
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_rsassa_pss_sign(&ctx->rsa.key, mbedtls_ctr_drbg_random,
			&ctx->rsa.rng_ctx,
			MBEDTLS_RSA_PRIVATE,
			(mbedtls_md_type_t)ctx->rsa.key.hash_id,
			(unsigned int)hashlen,
			(const unsigned char *)hash,
			(unsigned char *)sig));
		*siglen = ctx->rsa.key.len;
		break;
	default:				return -UTPFCP_ERR_UNKNOWN_ACTION;
	}
end:
	return r;
}

static ut_int32_t rsa_verify(
	ac_context_t *ctx, ut_int32_t action,
	ut_uint8_t *sal, ut_uint32_t sallen,
	ut_uint8_t *hash, ut_uint32_t hashlen,
	ut_uint8_t *sig, ut_uint32_t siglen)
{
	ut_int32_t  r = 0;
	ut_uint32_t l = ctx->rsa.key.len;
	((void)sal);
	sallen = 0;
	if (hash == NULL || hashlen <= 0 ||
		sig == NULL || siglen != l)
		return -UTPFCP_ERR_INVALID_PARAMS;
	ctx->rsa.key.hash_id = get_hashid(action);
	switch (action) {
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_MD5:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA1:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA224:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA256:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA384:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA512:
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_rsassa_pkcs1_v15_verify(&ctx->rsa.key, mbedtls_ctr_drbg_random,
			&ctx->rsa.rng_ctx,
			MBEDTLS_RSA_PUBLIC,
			(mbedtls_md_type_t)ctx->rsa.key.hash_id,
			(unsigned int)hashlen,
			(const unsigned char *)hash,
			(const unsigned char *)sig));

		break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA1:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA224:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA256:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA384:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA512:
		ctx->rsa.key.padding = MBEDTLS_RSA_PKCS_V21;
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_rsassa_pss_verify(&ctx->rsa.key, mbedtls_ctr_drbg_random,
			&ctx->rsa.rng_ctx,
			MBEDTLS_RSA_PUBLIC,
			(mbedtls_md_type_t)ctx->rsa.key.hash_id,
			(unsigned int)hashlen,
			(const unsigned char *)hash,
			(const unsigned char *)sig));
		break;
	default:				return -UTPFCP_ERR_UNKNOWN_ACTION;
	}
end:
	return r;
}

static int write_mpi( mbedtls_mpi *X,ut_uint8_t* d,ut_uint32_t* dlen)
{
	ut_uint32_t utmp = 0;
	int r = -1;
	utmp = mbedtls_mpi_size( X); 
	if(utmp>*dlen)
		return -UTPFCP_ERR_TOOSMALLLEN;
	*dlen = utmp;
	MBEDRET(UTPFCP_ERR_MPI, mbedtls_mpi_write_binary( X, d, *dlen ) );
end:
	return r;
}

//porting from mbedtls_ctr_drbg_random
static int ut_ctr_drbg_update_internal(mbedtls_ctr_drbg_context *ctx,
	const unsigned char data[MBEDTLS_CTR_DRBG_SEEDLEN])
{
	unsigned char tmp[MBEDTLS_CTR_DRBG_SEEDLEN];
	unsigned char *p = tmp;
	int i, j;

	memset(tmp, 0, MBEDTLS_CTR_DRBG_SEEDLEN);
	for (j = 0; j < MBEDTLS_CTR_DRBG_SEEDLEN; j += MBEDTLS_CTR_DRBG_BLOCKSIZE)
	{
		for (i = MBEDTLS_CTR_DRBG_BLOCKSIZE; i > 0; i--)
			if (++ctx->counter[i - 1] != 0)
				break;
		mbedtls_aes_crypt_ecb(&ctx->aes_ctx, MBEDTLS_AES_ENCRYPT, ctx->counter, p);
		p += MBEDTLS_CTR_DRBG_BLOCKSIZE;
	}
	for (i = 0; i < MBEDTLS_CTR_DRBG_SEEDLEN; i++)
		tmp[i] ^= data[i];
	mbedtls_aes_setkey_enc(&ctx->aes_ctx, tmp, MBEDTLS_CTR_DRBG_KEYBITS);
	memcpy(ctx->counter, tmp + MBEDTLS_CTR_DRBG_KEYSIZE, MBEDTLS_CTR_DRBG_BLOCKSIZE);
	return(0);
}

int ut_ctr_drbg_random(void *p_rng, unsigned char *output, size_t output_len)
{
	mbedtls_ctr_drbg_context *ctx = (mbedtls_ctr_drbg_context *)p_rng;
	unsigned char *p = output;
	unsigned char tmp[MBEDTLS_CTR_DRBG_BLOCKSIZE];
	int i;
	size_t use_len;

	if (output_len > MBEDTLS_CTR_DRBG_MAX_REQUEST)
		return(MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG);
	while (output_len > 0)
	{
		for (i = MBEDTLS_CTR_DRBG_BLOCKSIZE; i > 0; i--)
			if (++ctx->counter[i - 1] != 0)
				break;
		mbedtls_aes_crypt_ecb(&ctx->aes_ctx, MBEDTLS_AES_ENCRYPT, ctx->counter, tmp);
		use_len = (output_len > MBEDTLS_CTR_DRBG_BLOCKSIZE) ? MBEDTLS_CTR_DRBG_BLOCKSIZE :
			output_len;
		memcpy(p, tmp, use_len);
		p += use_len;
		output_len -= use_len;
	}
	if (ctx->reseed_counter>10000)
	{
		ut_ctr_drbg_update_internal(ctx, tmp);
		ctx->reseed_counter = 0;
	}
	ctx->reseed_counter++;
	return(0);
}

static ut_int32_t rsa_gen_key(
	gk_context_t *ctx_na, ut_int32_t action,
	ut_int32_t bit,
	ut_uint8_t *__e, ut_uint32_t *__elen,
	ut_uint8_t *__n, ut_uint32_t *__nlen,
	ut_uint8_t *__d, ut_uint32_t *__dlen,
	ut_uint8_t *__p, ut_uint32_t *__plen,
	ut_uint8_t *__q, ut_uint32_t *__qlen,
	ut_uint8_t *_dp, ut_uint32_t *_dplen,
	ut_uint8_t *_dq, ut_uint32_t *_dqlen,
	ut_uint8_t *_qp, ut_uint32_t *_qplen)
{
	ut_int32_t r = 0;

	mbedtls_rsa_context ctx;
	ut_uint32_t exponent = 65537;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "what_is_this_string :)";

	((void)ctx_na);
	if (__e == NULL || __elen == 0)return -UTPFCP_ERR_INVALID_PARAMS;
	if (__n == NULL || __nlen == 0)return -UTPFCP_ERR_INVALID_PARAMS;
	if (__d == NULL || __dlen == 0)return -UTPFCP_ERR_INVALID_PARAMS;
	if (__p == NULL || __plen == 0)return -UTPFCP_ERR_INVALID_PARAMS;
	if (__q == NULL || __qlen == 0)return -UTPFCP_ERR_INVALID_PARAMS;
	if (_dp == NULL || _dplen == 0)return -UTPFCP_ERR_INVALID_PARAMS;
	if (_dq == NULL || _dqlen == 0)return -UTPFCP_ERR_INVALID_PARAMS;
	if (_qp == NULL || _qplen == 0)return -UTPFCP_ERR_INVALID_PARAMS;

	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	MBEDRET(UTPFCP_ERR_RNG_SEED, mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char *)pers, strlen(pers)));

	mbedtls_rsa_init(&ctx, 0, 0);

	switch (action) {
	case UT_PF_CP_ACT_GK_RSA:
	case UT_PF_CP_ACT_GK_RSA_CRT:
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_gen_key(&ctx, ut_ctr_drbg_random, &ctr_drbg, bit, exponent));
		break;
	default:				return -UTPFCP_ERR_UNKNOWN_ACTION;
	}

	MBEDRET(UTPFCP_ERR_MPI, write_mpi(&ctx.N, __n, __nlen));
	MBEDRET(UTPFCP_ERR_MPI, write_mpi(&ctx.E, __e, __elen));
	MBEDRET(UTPFCP_ERR_MPI, write_mpi(&ctx.P, __p, __plen));
	MBEDRET(UTPFCP_ERR_MPI, write_mpi(&ctx.Q, __q, __qlen));
	MBEDRET(UTPFCP_ERR_MPI, write_mpi(&ctx.DP, _dp, _dplen));
	MBEDRET(UTPFCP_ERR_MPI, write_mpi(&ctx.DQ, _dq, _dqlen));
	MBEDRET(UTPFCP_ERR_MPI, write_mpi(&ctx.QP, _qp, _qplen));
	MBEDRET(UTPFCP_ERR_MPI, write_mpi(&ctx.D, __d, __dlen));

end:
	mbedtls_rsa_free(&ctx);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return r;
}

 
////////////////////////////////////////////////////////////////////////
ut_int32_t ut_pf_cp_open(
		ut_pf_cp_context_t **ctx,
		ut_int32_t cls, ut_int32_t act)
{
	ut_int32_t r = 0;

	switch( cls ) {
	case UT_PF_CP_CLS_MD:
		switch( act ) {
		case UT_PF_CP_ACT_MD_SM3	   :
		case UT_PF_CP_ACT_MD_MD5       : case UT_PF_CP_ACT_MD_SHA1        :
		case UT_PF_CP_ACT_MD_SHA224    : case UT_PF_CP_ACT_MD_SHA256      :
		case UT_PF_CP_ACT_MD_SHA384    : case UT_PF_CP_ACT_MD_SHA512      :
												break;
		default: 	   							return -1;
		}										break;
	case UT_PF_CP_CLS_SC:
		switch( act ) {
		case UT_PF_CP_ACT_SC_AES_ECB   : case UT_PF_CP_ACT_SC_AES_CBC     :
		case UT_PF_CP_ACT_SC_AES_CTR   : case UT_PF_CP_ACT_SC_AES_CTS     :
		case UT_PF_CP_ACT_SC_AES_XTS   : case UT_PF_CP_ACT_SC_DES_ECB     :
		case UT_PF_CP_ACT_SC_DES_CBC   : case UT_PF_CP_ACT_SC_DS3_ECB     :
		case UT_PF_CP_ACT_SC_DS3_CBC   :
		case UT_PF_CP_ACT_SC_SM4_ECB   : case UT_PF_CP_ACT_SC_SM4_CBC     :
												break;
		default: 	   							return -1;
		}										break;
	case UT_PF_CP_CLS_MC:
		switch( act ) {
		case UT_PF_CP_ACT_MC_HMAC_SM3   :
		case UT_PF_CP_ACT_MC_HMAC_MD5   : case UT_PF_CP_ACT_MC_HMAC_SHA1  :
		case UT_PF_CP_ACT_MC_HMAC_SHA224: case UT_PF_CP_ACT_MC_HMAC_SHA256:
		case UT_PF_CP_ACT_MC_HMAC_SHA384: case UT_PF_CP_ACT_MC_HMAC_SHA512:
		case UT_PF_CP_ACT_MC_CMAC_AES   : case UT_PF_CP_ACT_MC_CMAC_DES   :
		case UT_PF_CP_ACT_MC_CMAC_DS3   : case UT_PF_CP_ACT_MC_CCMC_AES   :
		case UT_PF_CP_ACT_MC_CCMC_DES   : case UT_PF_CP_ACT_MC_CCMC_DS3   :
												break;
		default: 	   							return -1;
		}										break;
	case UT_PF_CP_CLS_AE:
		switch( act ) {
		case UT_PF_CP_ACT_AE_AES_GCM    : case UT_PF_CP_ACT_AE_AES_CCM    :
												break;
		default: 	   							return -1;
		}										break;
	case UT_PF_CP_CLS_AC:
		switch( act ) {
		case UT_PF_CP_ACT_AC_RSA_NOPAD									  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5								  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA1					  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA224					  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA256					  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA384					  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA512					  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_MD5							  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA1						  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA224						  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA256						  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA384						  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA512						  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA1						  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA224					  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA256					  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA384					  :
		case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA512					  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA1						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA224						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA256						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA384						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA512						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA1						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA224						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA256						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA384						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA512						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA1						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA224						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA256						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA384						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA512						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA1						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA224						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA256						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA384						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA512						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA1						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA224						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA256						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA384						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA512						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA1						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA224						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA256						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA384						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA512						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA1						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA224						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA256						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA384						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA512						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA1						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA224						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA256						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA384						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA512						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA1						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA224						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA256						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA384						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA512						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA1						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA224						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA256						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA384						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA512						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA1						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA224						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA256						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA384						  :
		case UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA512						  :
												break;
		default: 	   							return -1;
		}										break;
	case UT_PF_CP_CLS_GK:
		switch( act ) {
		case UT_PF_CP_ACT_GK_RSA										  :
		case UT_PF_CP_ACT_GK_RSA_CRT									  :
		case UT_PF_CP_ACT_GK_ECC_SEP160K1								  :
		case UT_PF_CP_ACT_GK_ECC_SEP160R1								  :
		case UT_PF_CP_ACT_GK_ECC_SEP160R2								  :
		case UT_PF_CP_ACT_GK_ECC_SEP192K1								  :
		case UT_PF_CP_ACT_GK_ECC_SEP192R1								  :
		case UT_PF_CP_ACT_GK_ECC_SEP224K1								  :
		case UT_PF_CP_ACT_GK_ECC_SEP224R1								  :
		case UT_PF_CP_ACT_GK_ECC_SEP256K1								  :
		case UT_PF_CP_ACT_GK_ECC_SEP256R1								  :
		case UT_PF_CP_ACT_GK_ECC_SEP384R1								  :
		case UT_PF_CP_ACT_GK_ECC_SEP521R1								  :
		case UT_PF_CP_ACT_GK_ECC_BRAINPOOL224R1								  :
		case UT_PF_CP_ACT_GK_ECC_BRAINPOOL256R1								  :
		case UT_PF_CP_ACT_GK_ECC_BRAINPOOL384R1								  :
		case UT_PF_CP_ACT_GK_ECC_BRAINPOOL512R1								  :

												break;
		default: 	   							return -1;
		}										break;
	case UT_PF_CP_CLS_RD:
		switch( act ) {
		case UT_PF_CP_ACT_RD_INST									  	  :
		case UT_PF_CP_ACT_RD_UNINST									  	  :
		case UT_PF_CP_ACT_RD_ADDDAT									  	  :
		case UT_PF_CP_ACT_RD_RESEED									  	  :
		case UT_PF_CP_ACT_RD_GENVEC									  	  :
		case UT_PF_CP_ACT_RD_GENVEC_RANGE								  :
												break;
		default: 	   							return -1;
		}										break;
	default:
												return -1;
	}

	/* ut_pf_cp_context_t object */
	*ctx = (ut_pf_cp_context_t *)malloc(sizeof(ut_pf_cp_context_t));
	if ( *ctx == NULL ) {
		return -2;
	}

	(*ctx)->cls 	= cls;
	(*ctx)->action 	= act;
	(*ctx)->state	= 0x0;
	(*ctx)->use_hwc	= 0x0;	// no use
 

	return r;
}
 
ut_int32_t ut_pf_cp_ac_rsaenc(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__n, ut_uint32_t  __nlen,
		ut_uint8_t *__e, ut_uint32_t  __elen,
		ut_uint8_t *sal, ut_uint32_t  sallen,
		ut_uint8_t *src, ut_uint32_t  srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->cls != UT_PF_CP_CLS_AC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
 
		break;
	case 0x00:
		r = import_rsa_pub_key(&ctx->cipher.ac,
				__n, __nlen, __e, __elen);
		if ( r < 0 ) break;

		r = rsa_encrypt(&ctx->cipher.ac, ctx->action,
				sal, sallen, src, srclen, dst, dstlen);
		rsa_rel_key(&ctx->cipher.ac);
		break;
	}

	if ( r < 0 ) { return r; }

	return r;
}

ut_int32_t ut_pf_cp_ac_rsadec(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__n, ut_uint32_t  __nlen,
		ut_uint8_t *__d, ut_uint32_t  __dlen,
		ut_uint8_t *__e, ut_uint32_t  __elen,
		ut_uint8_t *sal, ut_uint32_t  sallen,
		ut_uint8_t *src, ut_uint32_t  srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->cls != UT_PF_CP_CLS_AC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
 
		break;
	case 0x00:
		r = import_rsa_pri_key(&ctx->cipher.ac,
				__n, __nlen, __d, __dlen, __e, __elen,
				NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
		if ( r < 0 ) break;

		r = rsa_decrypt(&ctx->cipher.ac, ctx->action,
				sal, sallen, src, srclen, dst, dstlen);
		rsa_rel_key(&ctx->cipher.ac);
		break;
	}

	if ( r < 0 ) { return r; }

	return r;
}

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
	ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t r = -1;

	if (ctx == NULL ||
		ctx->cls != UT_PF_CP_CLS_AC) {
		return -1;
	}

	switch (ctx->use_hwc) {
	case 0x01:

		break;
	case 0x00:
		r = import_rsa_pri_key(&ctx->cipher.ac,
			__n, __nlen, 0, 0, __e, __elen,
			__p, __plen, __q, __qlen,
			_dp, _dplen, _dq, _dqlen, _qp, _qplen);
		if (r < 0) break;

		r = rsa_decrypt(&ctx->cipher.ac, ctx->action,
			sal, sallen, src, srclen, dst, dstlen);
		rsa_rel_key(&ctx->cipher.ac);
		break;
	}

	if (r < 0) { return r; }

	return r;
}

ut_int32_t ut_pf_cp_ac_rsasig(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__n, ut_uint32_t  __nlen,
		ut_uint8_t *__d, ut_uint32_t  __dlen,
		ut_uint8_t *__e, ut_uint32_t  __elen,
		ut_uint8_t *sal, ut_uint32_t  sallen,
		ut_uint8_t *has, ut_uint32_t  haslen,
		ut_uint8_t *sig, ut_uint32_t *siglen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->cls != UT_PF_CP_CLS_AC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
 
		break;
	case 0x00:
		r = import_rsa_pri_key(&ctx->cipher.ac,
				__n, __nlen, __d, __dlen, __e, __elen,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
		if ( r < 0 ) break;

		r = rsa_sign(&ctx->cipher.ac, ctx->action,
				sal, sallen, has, haslen, sig, siglen);
		rsa_rel_key(&ctx->cipher.ac);
		break;
	}

	if ( r < 0 ) { return r; }

	return r;
}

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
	ut_uint8_t *sig, ut_uint32_t *siglen)
{
	ut_int32_t r = -1;

	if (ctx == NULL ||
		ctx->cls != UT_PF_CP_CLS_AC) {
		return -1;
	}

	switch (ctx->use_hwc) {
	case 0x01:

		break;
	case 0x00:
		r = import_rsa_pri_key(&ctx->cipher.ac,
			__n, __nlen, 0, 0, __e, __elen,
			__p, __plen, __q, __qlen,
			_dp, _dplen, _dq, _dqlen, _qp, _qplen);
		if (r < 0) break;

		r = rsa_sign(&ctx->cipher.ac, ctx->action,
			sal, sallen, has, haslen, sig, siglen);
		rsa_rel_key(&ctx->cipher.ac);
		break;
	}

	if (r < 0) { return r; }

	return r;
}
ut_int32_t ut_pf_cp_ac_rsavfy(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__n, ut_uint32_t __nlen,
		ut_uint8_t *__e, ut_uint32_t __elen,
		ut_uint8_t *sal, ut_uint32_t sallen,
		ut_uint8_t *has, ut_uint32_t haslen,
		ut_uint8_t *sig, ut_uint32_t siglen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->cls != UT_PF_CP_CLS_AC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
 
		break;
	case 0x00:
		r = import_rsa_pub_key(&ctx->cipher.ac,
				__n, __nlen, __e, __elen);
		if ( r < 0 ) break;

		r = rsa_verify(&ctx->cipher.ac, ctx->action,
				sal, sallen, has, haslen, sig, siglen);
		rsa_rel_key(&ctx->cipher.ac);
		break;
	}

	if ( r < 0 ) { return r; }

	return r;
}

ut_int32_t ut_pf_cp_gk_rsakey(
	ut_pf_cp_context_t *ctx,
	ut_int32_t bit,
	ut_uint8_t *__e, ut_uint32_t *__elen,
	ut_uint8_t *__n, ut_uint32_t *__nlen,
	ut_uint8_t *__d, ut_uint32_t *__dlen,
	ut_uint8_t *__p, ut_uint32_t *__plen,
	ut_uint8_t *__q, ut_uint32_t *__qlen,
	ut_uint8_t *_dp, ut_uint32_t *_dplen,
	ut_uint8_t *_dq, ut_uint32_t *_dqlen,
	ut_uint8_t *_qp, ut_uint32_t *_qplen)
{
	if (ctx == NULL ||
		ctx->cls != UT_PF_CP_CLS_GK) {
		return -1;
	}
	return rsa_gen_key(&ctx->cipher.gk, ctx->action, bit,
		__e, __elen, __n, __nlen, __d, __dlen,
		__p, __plen, __q, __qlen,
		_dp, _dplen, _dq, _dqlen, _qp, _qplen);
}

ut_int32_t ut_pf_cp_rd_random(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *rnd, ut_uint32_t rndlen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ) {
		r = _rand(NULL, rnd, rndlen);

		if ( r < 0 ) { return -2; }

		return r;
	}

	if ( ctx == NULL ||
		 ctx->cls != UT_PF_CP_CLS_RD ) {
		return -1;
	}
 
	return r;
}

ut_int32_t ut_pf_cp_close(ut_pf_cp_context_t *ctx)
{
	ut_int32_t r = 0;

	if ( ctx != NULL )
	{
		 
		free( ctx );
	}

	return r;
}

  
//port from psGetEntropy
// note: hardware only 
//       timetick should be add 
static int get_entropy(unsigned char *bytes, uint32_t size)
{
	ut_int32_t r = -1;
	 
	ut_uint32_t seconds=0;
	ut_uint32_t million_seconds=0;
	time_t t = time(NULL);
	seconds = t;
	million_seconds = t >> 32;
	if(size>=8){//entropy_gather_internal get MBEDTLS_ENTROPY_MAX_GATHER is 128,then this case always true.
		bytes[0]^=seconds;
		bytes[1]^=seconds>>8;
		bytes[2]^=seconds>>8*2;
		bytes[3]^=seconds>>8*3;
		bytes[4]^=million_seconds;
		bytes[5]^=million_seconds>>8;
		bytes[6]^=million_seconds>>8*2;
		bytes[7]^=million_seconds>>8*3;
	}
	return size;
}
//
//int mbedtls_hardware_poll(void *data,
//	unsigned char *output, size_t len, size_t *olen)
//{
//	int r= get_entropy(output, len);
//	((void)data);
//	if(r>0)
//		*olen = r;
//	else
//		*olen = 0;
//	if(r<0)return r;
//	return 0;
//}
static int set_aes_key(mbedtls_aes_context *ctx, int enc, ut_uint8_t *key, ut_uint32_t keylen)
{
	int r = -1;
	mbedtls_aes_init(ctx);
	MBEDRET(UTPFCP_ERR_SETKEY, mbedtls_aes_gen_mask_bytes(ctx));
	if (enc == UTPFCP_CIPHER_ENC)
		MBEDRET(UTPFCP_ERR_SETKEY, mbedtls_aes_setkey_enc(ctx, key, keylen * 8));
	else
		MBEDRET(UTPFCP_ERR_SETKEY, mbedtls_aes_setkey_dec(ctx, key, keylen * 8));
end:
	return r;
}
void dump2(char* str, unsigned char *d, int dlen)
{
	printf("dump %s (%d) : ", str, dlen);
	for (int i = 0; i < dlen; i++)
		printf("%02x", d[i]);
	printf("\n");
}
static ut_int32_t sc_starts(
	sc_context_t *ctx, ut_int32_t action,
	ut_uint8_t *key, ut_uint32_t keylen,
	ut_uint8_t *vec, ut_uint32_t veclen, ut_int32_t enc)
{
	ut_int32_t r = 0;
	ut_int32_t s = 0;
	memset(ctx, 0, sizeof(sc_context_t));
	switch (action) {
		
	case UT_PF_CP_ACT_SC_AES_XTS:
		memset(ctx->aes.vec, 0x0, sizeof(ctx->aes.vec));
		if (vec != NULL && veclen == 16) {
			memcpy(ctx->aes.vec, vec, veclen);
		}

		s = keylen;
		if (s % 2) break;
		s = s / 2;

			MBEDRET3(set_aes_key(&ctx->aes.key, enc, &key[0], s));
			MBEDRET3(set_aes_key(&ctx->aes.mode.xts.key, 1, &key[s], s));
 
			xts128_init(&ctx->aes.mode.xts.c, ctx->aes.vec, &ctx->aes.key,
				&ctx->aes.mode.xts.key, (block128_f)_aes_encrypt_block);
		break;
 
	default:
		return -1;
	}

	ctx->enc = enc;
end:
	return r;
}
static ut_int32_t sc_finish(
	sc_context_t *ctx, ut_int32_t action,
	ut_uint8_t *src, ut_uint32_t srclen,
	ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t  r = 0;
	ut_uint8_t *p0 = src;
	ut_uint8_t *p1 = dst;
	ut_uint32_t n = srclen;

	switch (action) {
	case UT_PF_CP_ACT_SC_AES_XTS:	// XTS, must be finished.
		if (src == NULL || srclen == 0)	return -1;
		break;
	default:
		if (src == NULL || srclen == 0)	return  0;
		break;
	}

	if (dst == NULL || dstlen == NULL || *dstlen < srclen)
		return -1;

	switch (action) {
	case UT_PF_CP_ACT_SC_AES_ECB: case UT_PF_CP_ACT_SC_AES_CBC:
		if (srclen >  0 && (srclen % 16))	return -1;
		break;
	case UT_PF_CP_ACT_SC_AES_CTS:
		if (srclen > 0 && (srclen <= 16))	return -1;
		break;
	case UT_PF_CP_ACT_SC_AES_XTS:
		if (srclen > 0 && (srclen <  16))	return -1;
		break;
	case UT_PF_CP_ACT_SC_DES_ECB: case UT_PF_CP_ACT_SC_DES_CBC:
	case UT_PF_CP_ACT_SC_DS3_ECB: case UT_PF_CP_ACT_SC_DS3_CBC:
		if (srclen > 0 && (srclen % 8))	return -1;
		break;
	case UT_PF_CP_ACT_SC_SM4_ECB: case UT_PF_CP_ACT_SC_SM4_CBC:
		if (srclen <= 0 || (srclen % 16))
			return -1;
		break;
	default:								return -1;
	}

	switch (action) {
	 
	case UT_PF_CP_ACT_SC_AES_XTS:
		if (ctx->enc) {
			ctx->aes.mode.xts.c.block1 = (block128_f)_aes_encrypt_block;
			xts128_finish(&ctx->aes.mode.xts.c, p0, p1, n, 1);
		}
		else {
			ctx->aes.mode.xts.c.block1 = (block128_f)_aes_decrypt_block;
			xts128_finish(&ctx->aes.mode.xts.c, p0, p1, n, 0);
		}
		break;
		//////////////////////////////////////////////////////////////////////////////////////////////////////////////
 
	default:
		r = -1;
		break;
	}
	*dstlen = n;

	return r;
}

ut_int32_t ut_pf_cp_sc_starts(
	ut_pf_cp_context_t *ctx,
	ut_uint8_t *key, ut_uint32_t keylen,
	ut_uint8_t *vec, ut_uint32_t veclen, ut_int32_t enc)
{
	ut_int32_t r = -1;

	if (ctx == NULL ||
		ctx->cls != UT_PF_CP_CLS_SC) {
		return -1;
	}
 
		r = sc_starts(&ctx->cipher.sc, ctx->action,
			key, keylen, vec, veclen, enc);
 
	if (r < 0) { return r; }

	ctx->state = 0x01;	/* start */
	return r;
}

ut_int32_t ut_pf_cp_sc_finish(
	ut_pf_cp_context_t *ctx,
	ut_uint8_t *src, ut_uint32_t srclen,
	ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t r = -1;

	if (ctx == NULL ||
		ctx->state != 0x01 ||
		ctx->cls != UT_PF_CP_CLS_SC) {
		return -1;
	}

 
		r = sc_finish(&ctx->cipher.sc, ctx->action,
			src, srclen, dst, dstlen);
 
	if (r < 0) { return r; }

	ctx->state = 0x00;	/* finish */
	return r;
}
