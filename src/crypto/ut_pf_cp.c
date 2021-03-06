#include "ut_pf_cp.h"
#include "ut_pf_cp_inner.h"
#include <contrib/lib_tvm_time/ut_pf_time.h>
#include <l4/log/log.h>
#include <sys/time.h>
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
#ifdef PERF_TEST
static size_t get_tick_count(void)
{
struct timeval tv;
struct timezone tz;
//char buf[256]={0};
unsigned char t = 0;
if( gettimeofday(&tv, &tz)!=0)
	return 0;
t = tv.tv_sec;
//strftime(buf,sizeof(buf)-1,"%Y-%m-%d %H:%M:%S", localtime(&tv.tv_sec));
//ut_sys_log("get_tick_count ---------------%s.%09d , %u,%u\n",buf,tv.tv_usec,t,tv.tv_sec);
return (size_t)(tv.tv_usec+t*1000000);
}
#endif
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
if (enc) {
	cbc128_encrypt(src, dst, len, key, vec, (block128_f)_aes_encrypt_block);
} else {
	cbc128_decrypt(src, dst, len, key, vec, (block128_f)_aes_decrypt_block);
}
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

r = psGetPrngData(p_rng, rnd, rndlen);

return r;
}

////////////////////////////////////////////////////////////////////////
static ut_int32_t md_starts(
	md_context_t *ctx, ut_int32_t action)
{
switch( action ) {
case UT_PF_CP_ACT_MD_SM3:    psSm3Init( &ctx->sm3.ctx       ); break;
case UT_PF_CP_ACT_MD_MD5:	 psMd5Init( &ctx->md5.ctx       ); break;
case UT_PF_CP_ACT_MD_SHA1:   psSha1Init( &ctx->sha1.ctx     ); break;
case UT_PF_CP_ACT_MD_SHA224: psSha224Init( &ctx->sha224.ctx ); break;
case UT_PF_CP_ACT_MD_SHA256: psSha256Init( &ctx->sha256.ctx ); break;
case UT_PF_CP_ACT_MD_SHA384: psSha384Init( &ctx->sha384.ctx ); break;
case UT_PF_CP_ACT_MD_SHA512: psSha512Init( &ctx->sha512.ctx ); break;
default: 			   return -1;
}
return 0;
}

static ut_int32_t md_update(
	md_context_t *ctx, ut_int32_t action,
	ut_uint8_t *src, ut_uint32_t srclen)
{
if ( src == NULL )		return -1;

switch( action ) {
case UT_PF_CP_ACT_MD_SM3:    psSm3Update( &ctx->sm3.ctx,       src, srclen ); break;
case UT_PF_CP_ACT_MD_MD5:	 psMd5Update( &ctx->md5.ctx,       src, srclen ); break;
case UT_PF_CP_ACT_MD_SHA1:   psSha1Update( &ctx->sha1.ctx,     src, srclen ); break;
case UT_PF_CP_ACT_MD_SHA224: psSha224Update( &ctx->sha224.ctx, src, srclen ); break;
case UT_PF_CP_ACT_MD_SHA256: psSha256Update( &ctx->sha256.ctx, src, srclen ); break;
case UT_PF_CP_ACT_MD_SHA384: psSha384Update( &ctx->sha384.ctx, src, srclen ); break;
case UT_PF_CP_ACT_MD_SHA512: psSha512Update( &ctx->sha512.ctx, src, srclen ); break;
default: 			  	return -1;
}

return 0;
}

static ut_int32_t md_finish(
	md_context_t *ctx, ut_int32_t action,
	ut_uint8_t *dst, ut_uint32_t *dstlen)
{
if ( dst == NULL || dstlen == NULL ) return -1;

switch( action ) {
case UT_PF_CP_ACT_MD_SM3:    if ( *dstlen < 32 ) return -1; *dstlen = 32; break;
case UT_PF_CP_ACT_MD_MD5:	 if ( *dstlen < 16 ) return -1; *dstlen = 16; break;
case UT_PF_CP_ACT_MD_SHA1:   if ( *dstlen < 20 ) return -1; *dstlen = 20; break;
case UT_PF_CP_ACT_MD_SHA224: if ( *dstlen < 28 ) return -1; *dstlen = 28; break;
case UT_PF_CP_ACT_MD_SHA256: if ( *dstlen < 32 ) return -1; *dstlen = 32; break;
case UT_PF_CP_ACT_MD_SHA384: if ( *dstlen < 48 ) return -1; *dstlen = 48; break;
case UT_PF_CP_ACT_MD_SHA512: if ( *dstlen < 64 ) return -1; *dstlen = 64; break;
default: 			   return -1;
}

switch( action ) {
case UT_PF_CP_ACT_MD_SM3:    psSm3Final( &ctx->sm3.ctx,       dst ); break;
case UT_PF_CP_ACT_MD_MD5:	 psMd5Final( &ctx->md5.ctx,       dst ); break;
case UT_PF_CP_ACT_MD_SHA1:   psSha1Final( &ctx->sha1.ctx,     dst ); break;
case UT_PF_CP_ACT_MD_SHA224: psSha224Final( &ctx->sha224.ctx, dst ); break;
case UT_PF_CP_ACT_MD_SHA256: psSha256Final( &ctx->sha256.ctx, dst ); break;
case UT_PF_CP_ACT_MD_SHA384: psSha384Final( &ctx->sha384.ctx, dst ); break;
case UT_PF_CP_ACT_MD_SHA512: psSha512Final( &ctx->sha512.ctx, dst ); break;
}

return 0;
}

static int set_aes_key(mbedtls_aes_context *ctx,int enc,ut_uint8_t *key, ut_uint32_t keylen)
{
int r = -UTPFCP_ERR_UNKNOWN;
mbedtls_aes_init(ctx);
MBEDRET(UTPFCP_ERR_SETKEY, mbedtls_aes_gen_mask_bytes(ctx));
if(enc==UTPFCP_CIPHER_ENC)
	MBEDRET(UTPFCP_ERR_SETKEY, mbedtls_aes_setkey_enc(ctx,key,keylen*8));
else
	MBEDRET(UTPFCP_ERR_SETKEY, mbedtls_aes_setkey_dec(ctx,key,keylen*8));
end:
return r;
}
////////////////////////////////////////////////////////////////////////

static ut_int32_t sc_starts(
	sc_context_t *ctx, ut_int32_t action,
	ut_uint8_t *key, ut_uint32_t keylen,
	ut_uint8_t *vec, ut_uint32_t veclen, ut_int32_t enc)
{
ut_int32_t r = 0;
ut_int32_t s = 0;

switch( action ) {
case UT_PF_CP_ACT_SC_AES_ECB:
case UT_PF_CP_ACT_SC_AES_CBC:
case UT_PF_CP_ACT_SC_AES_CTS:
	memset(ctx->aes.vec, 0x0, sizeof(ctx->aes.vec));
	if ( vec != NULL && veclen == 16 ) {
		memcpy(ctx->aes.vec, vec, veclen);
	}
	MBEDRET3(set_aes_key(&ctx->aes.key,enc,key,keylen));
	break;

case UT_PF_CP_ACT_SC_AES_CTR:
	ctx->aes.mode.ctr.num = 0;
	memset(ctx->aes.mode.ctr.ecount, 0, 16);
	if ( vec != NULL && veclen == 16 ) {
		memcpy(ctx->aes.vec, vec, veclen);
		memcpy(ctx->aes.mode.ctr.ecount, vec, veclen);
	}
	MBEDRET3(set_aes_key(&ctx->aes.key,UTPFCP_CIPHER_ENC,key,keylen));
	break;

case UT_PF_CP_ACT_SC_AES_XTS:
	memset(ctx->aes.vec, 0x0, sizeof(ctx->aes.vec));
	if ( vec != NULL && veclen == 16 ) {
		memcpy(ctx->aes.vec, vec, veclen);
	}

	s = keylen;
	if ( s % 2 ) break;
	s = s / 2 ;
	
	MBEDRET3(set_aes_key(&ctx->aes.key,enc,&key[0],s));
	MBEDRET3(set_aes_key(&ctx->aes.mode.xts.key,UTPFCP_CIPHER_ENC,&key[s],s));

	xts128_init(&ctx->aes.mode.xts.c, ctx->aes.vec, &ctx->aes.key,
			&ctx->aes.mode.xts.key, (block128_f)_aes_encrypt_block);
	break;
case UT_PF_CP_ACT_SC_DES_ECB:
case UT_PF_CP_ACT_SC_DES_CBC:
	memset(ctx->des.vec, 0x0, sizeof(ctx->des.vec));
	if ( vec != NULL && veclen == 8 ) {
		memcpy(ctx->des.vec, vec, veclen);
	}
	r = psDesInitKey(key, keylen, &ctx->des.key);
	break;

case UT_PF_CP_ACT_SC_DS3_ECB:
case UT_PF_CP_ACT_SC_DS3_CBC:
	memset(ctx->des.vec, 0x0, sizeof(ctx->des.vec));
	if ( vec != NULL && veclen == 8 ) {
		memcpy(ctx->des.vec, vec, veclen);
	}
	r = psDes3InitKey(key, keylen, &ctx->des.key);
	break;
case UT_PF_CP_ACT_SC_SM4_ECB:
case UT_PF_CP_ACT_SC_SM4_CBC:
	memset(ctx->sm4.vec, 0x0, sizeof(ctx->sm4.vec));
	if ( vec != NULL && veclen == 16 ) {
		memcpy(ctx->sm4.vec, vec, veclen);
	}
	r = psSm4InitKey(key, keylen, &ctx->sm4.key);
	break;
default:
	return -1;
}

ctx->enc = enc;
end:	
return r;
}

static ut_int32_t sc_update(
		sc_context_t *ctx, ut_int32_t action,
		ut_uint8_t *src, ut_uint32_t srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t  r  =     0;
	ut_uint8_t *p0 =   src;
	ut_uint8_t *p1 =   dst;
	ut_uint32_t n  = srclen;

	if ( dstlen == NULL || *dstlen < srclen )
		return -1;

	switch( action ) {
	case UT_PF_CP_ACT_SC_AES_ECB:
	case UT_PF_CP_ACT_SC_AES_CBC: case UT_PF_CP_ACT_SC_AES_CTR:
	case UT_PF_CP_ACT_SC_AES_XTS: case UT_PF_CP_ACT_SC_AES_CTS:
		if ( srclen <= 0 || (srclen % 16) )
			return -1;
		break;
	case UT_PF_CP_ACT_SC_DES_ECB: case UT_PF_CP_ACT_SC_DES_CBC:
	case UT_PF_CP_ACT_SC_DS3_ECB: case UT_PF_CP_ACT_SC_DS3_CBC:
		if ( srclen <= 0 || (srclen %  8) )
			return -1;
		break;
	case UT_PF_CP_ACT_SC_SM4_ECB: case UT_PF_CP_ACT_SC_SM4_CBC:
		if ( srclen <= 0 || (srclen % 16) )
			return -1;
		break;
	}

	switch( action ) {
	case UT_PF_CP_ACT_SC_AES_ECB:
		if ( ctx->enc ) {ecb128_encrypt(p0, p1, n, &ctx->aes.key, (block128_f)_aes_encrypt_block);}
		else            {ecb128_decrypt(p0, p1, n, &ctx->aes.key, (block128_f)_aes_decrypt_block);}
		break;
	case UT_PF_CP_ACT_SC_AES_CBC:
		if ( ctx->enc ) {cbc128_encrypt(p0, p1, n, &ctx->aes.key, ctx->aes.vec, (block128_f)_aes_encrypt_block);}
		else            {cbc128_decrypt(p0, p1, n, &ctx->aes.key, ctx->aes.vec, (block128_f)_aes_decrypt_block);}
		break;
	case UT_PF_CP_ACT_SC_AES_CTR:
		ctr128_encrypt(p0, p1, n, &ctx->aes.key, ctx->aes.vec,
				ctx->aes.mode.ctr.ecount, &ctx->aes.mode.ctr.num, (block128_f)_aes_encrypt_block);
		break;
	case UT_PF_CP_ACT_SC_AES_CTS:
		if ( ctx->enc ) {nistcts128_encrypt(p0, p1, n, &ctx->aes.key, ctx->aes.vec, (cbc128_f)_aes_cbc_encrypt);}
		else 			{nistcts128_decrypt(p0, p1, n, &ctx->aes.key, ctx->aes.vec, (cbc128_f)_aes_cbc_encrypt);}
		break;
	case UT_PF_CP_ACT_SC_AES_XTS:
		if ( ctx->enc ) {ctx->aes.mode.xts.c.block1 = (block128_f)_aes_encrypt_block;
		xts128_update(&ctx->aes.mode.xts.c,	p0, p1, n);}
		else 			{ctx->aes.mode.xts.c.block1 = (block128_f)_aes_decrypt_block;
		xts128_update(&ctx->aes.mode.xts.c,	p0, p1, n);}
		break;
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////
	case UT_PF_CP_ACT_SC_DES_ECB:
		if ( ctx->enc ) {ecb64_encrypt(p0, p1, n, &ctx->des.key, (block64_f)_des_encrypt_block);}
		else 			{ecb64_decrypt(p0, p1, n, &ctx->des.key, (block64_f)_des_decrypt_block);}
		break;
	case UT_PF_CP_ACT_SC_DES_CBC:
		if ( ctx->enc ) {cbc64_encrypt(p0, p1, n, &ctx->des.key, ctx->des.vec, (block64_f)_des_encrypt_block);}
		else 			{cbc64_decrypt(p0, p1, n, &ctx->des.key, ctx->des.vec, (block64_f)_des_decrypt_block);}
		break;
	case UT_PF_CP_ACT_SC_DS3_ECB:
		if ( ctx->enc ) {ecb64_encrypt(p0, p1, n, &ctx->des.key, (block64_f)_ds3_encrypt_block);}
		else 			{ecb64_decrypt(p0, p1, n, &ctx->des.key, (block64_f)_ds3_decrypt_block);}
		break;
	case UT_PF_CP_ACT_SC_DS3_CBC:
		if ( ctx->enc ) {cbc64_encrypt(p0, p1, n, &ctx->des.key, ctx->des.vec, (block64_f)_ds3_encrypt_block);}
		else 			{cbc64_decrypt(p0, p1, n, &ctx->des.key, ctx->des.vec, (block64_f)_ds3_decrypt_block);}
		break;
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////
	case UT_PF_CP_ACT_SC_SM4_ECB:
		if ( ctx->enc ) {ecb128_encrypt(p0, p1, n, &ctx->sm4.key, (block128_f)_sm4_encrypt_block);}
		else            {ecb128_decrypt(p0, p1, n, &ctx->sm4.key, (block128_f)_sm4_decrypt_block);}
		break;
	case UT_PF_CP_ACT_SC_SM4_CBC:
		if ( ctx->enc ) {cbc128_encrypt(p0, p1, n, &ctx->sm4.key, ctx->sm4.vec, (block128_f)_sm4_encrypt_block);}
		else            {cbc128_decrypt(p0, p1, n, &ctx->sm4.key, ctx->sm4.vec, (block128_f)_sm4_decrypt_block);}
		break;
	default:
		return -1;
	}
	*dstlen = n;

	return r;
}

static ut_int32_t sc_finish(
		sc_context_t *ctx, ut_int32_t action,
		ut_uint8_t *src, ut_uint32_t srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t  r  =      0;
	ut_uint8_t *p0 =    src;
	ut_uint8_t *p1 =    dst;
	ut_uint32_t n  = srclen;

	switch( action ) {
	case UT_PF_CP_ACT_SC_AES_XTS:	// XTS, must be finished.
		if ( src == NULL || srclen == 0 )	return -1;
		break;
	default:
		if ( src == NULL || srclen == 0 )	return  0;
		break;
	}

	if ( dst == NULL || dstlen == NULL || *dstlen < srclen )
		return -1;

	switch( action ) {
	case UT_PF_CP_ACT_SC_AES_ECB: case UT_PF_CP_ACT_SC_AES_CBC:
		if ( srclen >  0 && (srclen % 16) )	return -1;
		break;
	case UT_PF_CP_ACT_SC_AES_CTR:
		break;
	case UT_PF_CP_ACT_SC_AES_CTS:
		if ( srclen > 0 && (srclen <= 16) )	return -1;
		break;
	case UT_PF_CP_ACT_SC_AES_XTS:
		if ( srclen > 0 && (srclen <  16) )	return -1;
		break;
	case UT_PF_CP_ACT_SC_DES_ECB: case UT_PF_CP_ACT_SC_DES_CBC:
	case UT_PF_CP_ACT_SC_DS3_ECB: case UT_PF_CP_ACT_SC_DS3_CBC:
		if ( srclen > 0 && (srclen %  8) )	return -1;
		break;
	case UT_PF_CP_ACT_SC_SM4_ECB: case UT_PF_CP_ACT_SC_SM4_CBC:
		if ( srclen <= 0 || (srclen % 16) )
			return -1;
		break;
	default:								return -1;
	}

	switch( action ) {
	case UT_PF_CP_ACT_SC_AES_ECB:
		if ( ctx->enc ) {ecb128_encrypt(p0, p1, n, &ctx->aes.key, (block128_f)_aes_encrypt_block);}
		else            {ecb128_decrypt(p0, p1, n, &ctx->aes.key, (block128_f)_aes_decrypt_block);}
		break;
	case UT_PF_CP_ACT_SC_AES_CBC:
		if ( ctx->enc ) {cbc128_encrypt(p0, p1, n, &ctx->aes.key, ctx->aes.vec, (block128_f)_aes_encrypt_block);}
		else            {cbc128_decrypt(p0, p1, n, &ctx->aes.key, ctx->aes.vec, (block128_f)_aes_decrypt_block);}
		break;
	case UT_PF_CP_ACT_SC_AES_CTR:
		ctr128_encrypt(p0, p1, n, &ctx->aes.key, ctx->aes.vec,
				ctx->aes.mode.ctr.ecount, &ctx->aes.mode.ctr.num, (block128_f)_aes_encrypt_block);
		break;
	case UT_PF_CP_ACT_SC_AES_CTS:
		if ( ctx->enc ) {cts128_encrypt(p0, p1, n, &ctx->aes.key, ctx->aes.vec, (cbc128_f)_aes_cbc_encrypt);}
		else 			{cts128_decrypt(p0, p1, n, &ctx->aes.key, ctx->aes.vec, (cbc128_f)_aes_cbc_encrypt);}
		break;
	case UT_PF_CP_ACT_SC_AES_XTS:
		if ( ctx->enc ) {ctx->aes.mode.xts.c.block1 = (block128_f)_aes_encrypt_block;
		xts128_finish(&ctx->aes.mode.xts.c,	p0, p1, n, 1);}
		else 			{ctx->aes.mode.xts.c.block1 = (block128_f)_aes_decrypt_block;
		xts128_finish(&ctx->aes.mode.xts.c,	p0, p1, n, 0);}
		break;
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////
	case UT_PF_CP_ACT_SC_DES_ECB:
		if ( ctx->enc ) {ecb64_encrypt(p0, p1, n, &ctx->des.key, (block64_f)_des_encrypt_block);}
		else 			{ecb64_decrypt(p0, p1, n, &ctx->des.key, (block64_f)_des_decrypt_block);}
		break;
	case UT_PF_CP_ACT_SC_DES_CBC:
		if ( ctx->enc ) {cbc64_encrypt(p0, p1, n, &ctx->des.key, ctx->des.vec, (block64_f)_des_encrypt_block);}
		else 			{cbc64_decrypt(p0, p1, n, &ctx->des.key, ctx->des.vec, (block64_f)_des_decrypt_block);}
		break;
	case UT_PF_CP_ACT_SC_DS3_ECB:
		if ( ctx->enc ) {ecb64_encrypt(p0, p1, n, &ctx->des.key, (block64_f)_ds3_encrypt_block);}
		else 			{ecb64_decrypt(p0, p1, n, &ctx->des.key, (block64_f)_ds3_decrypt_block);}
		break;
	case UT_PF_CP_ACT_SC_DS3_CBC:
		if ( ctx->enc ) {cbc64_encrypt(p0, p1, n, &ctx->des.key, ctx->des.vec, (block64_f)_ds3_encrypt_block);}
		else 			{cbc64_decrypt(p0, p1, n, &ctx->des.key, ctx->des.vec, (block64_f)_ds3_decrypt_block);}
		break;
		//////////////////////////////////////////////////////////////////////////////////////////////////////////////
	case UT_PF_CP_ACT_SC_SM4_ECB:
		if ( ctx->enc ) {ecb128_encrypt(p0, p1, n, &ctx->sm4.key, (block128_f)_sm4_encrypt_block);}
		else            {ecb128_decrypt(p0, p1, n, &ctx->sm4.key, (block128_f)_sm4_decrypt_block);}
		break;
	case UT_PF_CP_ACT_SC_SM4_CBC:
		if ( ctx->enc ) {cbc128_encrypt(p0, p1, n, &ctx->sm4.key, ctx->sm4.vec, (block128_f)_sm4_encrypt_block);}
		else            {cbc128_decrypt(p0, p1, n, &ctx->sm4.key, ctx->sm4.vec, (block128_f)_sm4_decrypt_block);}
		break;
	default:
		r = -1;
		break;
	}
	*dstlen = n;

	return r;
}

////////////////////////////////////////////////////////////////////////
static ut_int32_t mc_starts(
		mc_context_t *ctx, ut_int32_t action,
		ut_uint8_t *key, ut_uint32_t keylen,
		ut_uint8_t *vec, ut_uint32_t veclen)
{
	ut_int32_t r = 0;
	ut_uint32_t  n = 0;
	ut_int32_t cp_action = 0;
	ut_uint32_t  blocksize = 0;
	ut_uint32_t  mackeylen = 0;
	ut_uint8_t mackey[128] = {0};
	ut_uint32_t  i =  0;

	unsigned char L[16] = {0};
	unsigned char Z[16] = {0};
	unsigned char tmp[16] = {0};

	switch( action ) {
	case UT_PF_CP_ACT_MC_HMAC_SM3:		blocksize =  64; cp_action = UT_PF_CP_ACT_MD_SM3;	 break;
	case UT_PF_CP_ACT_MC_HMAC_MD5:		blocksize =  64; cp_action = UT_PF_CP_ACT_MD_MD5;	 break;
	case UT_PF_CP_ACT_MC_HMAC_SHA1:		blocksize =  64; cp_action = UT_PF_CP_ACT_MD_SHA1;	 break;
	case UT_PF_CP_ACT_MC_HMAC_SHA224:	blocksize =  64; cp_action = UT_PF_CP_ACT_MD_SHA224; break;
	case UT_PF_CP_ACT_MC_HMAC_SHA256:	blocksize =  64; cp_action = UT_PF_CP_ACT_MD_SHA256; break;
	case UT_PF_CP_ACT_MC_HMAC_SHA384:	blocksize = 128; cp_action = UT_PF_CP_ACT_MD_SHA384; break;
	case UT_PF_CP_ACT_MC_HMAC_SHA512:	blocksize = 128; cp_action = UT_PF_CP_ACT_MD_SHA512; break;
	}

	switch( action ) {
	case UT_PF_CP_ACT_MC_HMAC_SM3:
	case UT_PF_CP_ACT_MC_HMAC_MD5:		case UT_PF_CP_ACT_MC_HMAC_SHA1:
	case UT_PF_CP_ACT_MC_HMAC_SHA224:	case UT_PF_CP_ACT_MC_HMAC_SHA256:
	case UT_PF_CP_ACT_MC_HMAC_SHA384:	case UT_PF_CP_ACT_MC_HMAC_SHA512:
		if ( key == NULL || keylen == 0 )
			return -1;

		if ( keylen > blocksize ) {
			mackeylen = sizeof(mackey);
			md_starts(&ctx->hmac.md, cp_action);
			md_update(&ctx->hmac.md, cp_action, key, keylen);
			md_finish(&ctx->hmac.md, cp_action, mackey, &mackeylen);
		} else { memcpy( mackey, key, keylen ); }

		ctx->hmac.blocksize = blocksize;
		for ( i = 0; i < blocksize; i++ ) {
			ctx->hmac.ipad[i] = mackey[i] ^ 0x36;
		}
		for ( i = 0; i < blocksize; i++ ) {
			ctx->hmac.opad[i] = mackey[i] ^ 0x5C;
		}

		md_starts(&ctx->hmac.md, cp_action);
		md_update(&ctx->hmac.md, cp_action, ctx->hmac.ipad, blocksize);
		break;
	}

	switch( action ) {
	case UT_PF_CP_ACT_MC_CMAC_AES:
	case UT_PF_CP_ACT_MC_CMAC_DES:
	case UT_PF_CP_ACT_MC_CMAC_DS3:
		ctx->cmac.last_len = 0;
		memset(ctx->cmac.last, 0x00, 16);

		/* generate k1 & k2 */
		switch( action ) {
		case UT_PF_CP_ACT_MC_CMAC_AES: { n = 16; cp_action = UT_PF_CP_ACT_SC_AES_ECB; break; }
		case UT_PF_CP_ACT_MC_CMAC_DES: { n =  8; cp_action = UT_PF_CP_ACT_SC_DES_ECB; break; }
		case UT_PF_CP_ACT_MC_CMAC_DS3: { n =  8; cp_action = UT_PF_CP_ACT_SC_DS3_ECB; break; }
		}

		r = sc_starts(&ctx->cmac.sc, cp_action,
				key, keylen, vec, veclen, 1);
		if ( r < 0 ) break;
		r = sc_update(&ctx->cmac.sc, cp_action, Z, n, L, &n);
		if ( r < 0 ) break;

		if ( (L[0] & 0x80) == 0 ) { /* If MSB(L) = 0, then K1 = L << 1 */
			_lsh(L, ctx->cmac.k1, n);
		} else { /* Else K1 = ( L << 1 ) (+) Rb */
			_lsh(L, tmp, n);
			_xor(tmp, const_Rb, ctx->cmac.k1, n);
		}
		if ( (ctx->cmac.k1[0] & 0x80) == 0 ) {
			_lsh(ctx->cmac.k1, ctx->cmac.k2, n);
		} else {
			_lsh(ctx->cmac.k1, tmp, n);
			_xor(tmp, const_Rb, ctx->cmac.k2, n);
		}
		break;

	case UT_PF_CP_ACT_MC_CCMC_AES:
	case UT_PF_CP_ACT_MC_CCMC_DES:
	case UT_PF_CP_ACT_MC_CCMC_DS3:
		ctx->ccmc.last_len = 0;
		memset(ctx->ccmc.last, 0x00, 16);

		switch( action ) {
		case UT_PF_CP_ACT_MC_CCMC_AES: { n = 16; cp_action = UT_PF_CP_ACT_SC_AES_ECB; break; }
		case UT_PF_CP_ACT_MC_CCMC_DES: { n =  8; cp_action = UT_PF_CP_ACT_SC_DES_ECB; break; }
		case UT_PF_CP_ACT_MC_CCMC_DS3: { n =  8; cp_action = UT_PF_CP_ACT_SC_DS3_ECB; break; }
		}

		r = sc_starts(&ctx->ccmc.sc, cp_action,
				key, keylen, vec, veclen, 1);
		break;
	}

	return r;
}

static ut_int32_t mc_update(
		mc_context_t *ctx, ut_int32_t action,
		ut_uint8_t *src, ut_uint32_t srclen)
{
	ut_int32_t r =  0;
	ut_uint32_t  c1 = 0;
	ut_uint32_t  n =  0;
	ut_int32_t cp_action = 0;
	unsigned char Y[16] = {0};

	switch( action ) {
	case UT_PF_CP_ACT_MC_HMAC_SM3:
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SM3,    src, srclen);
		break;
	case UT_PF_CP_ACT_MC_HMAC_MD5:
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_MD5,    src, srclen);
		break;
	case UT_PF_CP_ACT_MC_HMAC_SHA1:
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA1,   src, srclen);
		break;
	case UT_PF_CP_ACT_MC_HMAC_SHA224:
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA224, src, srclen);
		break;
	case UT_PF_CP_ACT_MC_HMAC_SHA256:
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA256, src, srclen);
		break;
	case UT_PF_CP_ACT_MC_HMAC_SHA384:
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA384, src, srclen);
		break;
	case UT_PF_CP_ACT_MC_HMAC_SHA512:
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA512, src, srclen);
		break;

	case UT_PF_CP_ACT_MC_CMAC_AES:
	case UT_PF_CP_ACT_MC_CMAC_DES:
	case UT_PF_CP_ACT_MC_CMAC_DS3:
		switch( action ) {
		case UT_PF_CP_ACT_MC_CMAC_AES:
			n = 16; cp_action = UT_PF_CP_ACT_SC_AES_ECB; break;
		case UT_PF_CP_ACT_MC_CMAC_DES:
			n =  8; cp_action = UT_PF_CP_ACT_SC_DES_ECB; break;
		case UT_PF_CP_ACT_MC_CMAC_DS3:
			n =  8; cp_action = UT_PF_CP_ACT_SC_DS3_ECB; break;
		}

		if (ctx->cmac.last_len > 0) {
			c1 = n - ctx->cmac.last_len;
			if (srclen < c1)  c1 = srclen;
			memcpy(&ctx->cmac.last[ctx->cmac.last_len], src, c1);

			srclen -= c1; ctx->cmac.last_len += c1;
			if (srclen == 0) return 0;

			src += c1;

			if (n == 16) {
				/* Y := Mi (+) X */
				_xor(ctx->cmac.sc.aes.vec, ctx->cmac.last, Y, n);
				/* X := AES-128(KEY, Y); */
				r = sc_update(&ctx->cmac.sc, cp_action,
						Y, n, ctx->cmac.sc.aes.vec, &n);
				if ( r < 0 ) return -1;
			} else {
				/* Y := Mi (+) X */
				_xor(ctx->cmac.sc.des.vec, ctx->cmac.last, Y, n);
				/* X := AES-128(KEY, Y); */
				r = sc_update(&ctx->cmac.sc, cp_action,
						Y, n, ctx->cmac.sc.des.vec, &n);
				if ( r < 0 ) return -1;
			}
		}

		/* Encrypt all but one of the complete blocks left */
		while (srclen > n) {
			if (n == 16) {
				/* Y := Mi (+) X */
				_xor(ctx->cmac.sc.aes.vec, src, Y, n);
				/* X := AES-128(KEY, Y); */
				r = sc_update(&ctx->cmac.sc, cp_action,
					Y, n, ctx->cmac.sc.aes.vec, &n);
				if ( r < 0 ) return -1;
			} else {
				/* Y := Mi (+) X */
				_xor(ctx->cmac.sc.des.vec, src, Y, n);
				/* X := AES-128(KEY, Y); */
				r = sc_update(&ctx->cmac.sc, cp_action,
					Y, n, ctx->cmac.sc.des.vec, &n);
				if ( r < 0 ) return -1;
			}

			src += n; srclen -= n;
		}

		/* Copy any data left to last block buffer */
		memcpy(ctx->cmac.last, src, srclen);
		ctx->cmac.last_len = srclen;

		break;

	case UT_PF_CP_ACT_MC_CCMC_AES:
	case UT_PF_CP_ACT_MC_CCMC_DES:
	case UT_PF_CP_ACT_MC_CCMC_DS3:
		switch( action ) {
		case UT_PF_CP_ACT_MC_CCMC_AES:
			n = 16; cp_action = UT_PF_CP_ACT_SC_AES_ECB; break;
		case UT_PF_CP_ACT_MC_CCMC_DES:
			n =  8; cp_action = UT_PF_CP_ACT_SC_DES_ECB; break;
		case UT_PF_CP_ACT_MC_CCMC_DS3:
			n =  8; cp_action = UT_PF_CP_ACT_SC_DS3_ECB; break;
		}

		if (ctx->ccmc.last_len > 0) {
			c1 = n - ctx->ccmc.last_len;
			if (srclen < c1)  c1 = srclen;
			memcpy(&ctx->ccmc.last[ctx->ccmc.last_len], src, c1);

			srclen -= c1; ctx->ccmc.last_len += c1;
			if (srclen == 0) return 0;

			src += c1;

			/* CBC: will auto use vector */
			r = sc_update(&ctx->ccmc.sc, cp_action,
					ctx->ccmc.last, n, Y, &n);
			if ( r < 0 ) return -1;
		}

		/* Encrypt all but one of the complete blocks left */
		while (srclen > n) {
			r = sc_update(&ctx->ccmc.sc, cp_action,
					ctx->ccmc.last, n, Y, &n);
			if ( r < 0 ) return -1;

			src += n; srclen -= n;
		}

		/* Copy any data left to last block buffer */
		memcpy(ctx->ccmc.last, src, srclen);
		ctx->ccmc.last_len = srclen;
		break;
	}

	return r;
}

static ut_int32_t mc_finish(
		mc_context_t *ctx, ut_int32_t action,
		ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t r = 0;
	ut_uint32_t  i = 0;
	ut_uint32_t  n = 0;
	ut_int32_t cp_action = 0;
	unsigned char Y[16] = {0};
	unsigned char M_last[16] = {0};
	unsigned char padded[16] = {0};

	switch( action ) {
	case UT_PF_CP_ACT_MC_HMAC_SM3:
		r = md_finish(&ctx->hmac.md, UT_PF_CP_ACT_MD_SM3,
				dst, dstlen);
		r = md_starts(&ctx->hmac.md, UT_PF_CP_ACT_MD_SM3);
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SM3,
				ctx->hmac.opad, ctx->hmac.blocksize);
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SM3,
				dst, *dstlen);
		r = md_finish(&ctx->hmac.md, UT_PF_CP_ACT_MD_SM3,
				dst,  dstlen);
		break;
	case UT_PF_CP_ACT_MC_HMAC_MD5:
		r = md_finish(&ctx->hmac.md, UT_PF_CP_ACT_MD_MD5,
				dst, dstlen);
		r = md_starts(&ctx->hmac.md, UT_PF_CP_ACT_MD_MD5);
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_MD5,
				ctx->hmac.opad, ctx->hmac.blocksize);
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_MD5,
				dst, *dstlen);
		r = md_finish(&ctx->hmac.md, UT_PF_CP_ACT_MD_MD5,
				dst,  dstlen);
		break;
	case UT_PF_CP_ACT_MC_HMAC_SHA1:
		r = md_finish(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA1,
				dst, dstlen);
		r = md_starts(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA1);
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA1,
				ctx->hmac.opad, ctx->hmac.blocksize);
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA1,
				dst, *dstlen);
		r = md_finish(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA1,
				dst,  dstlen);
		break;
	case UT_PF_CP_ACT_MC_HMAC_SHA224:
		r = md_finish(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA224,
				dst, dstlen);
		r = md_starts(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA224);
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA224,
				ctx->hmac.opad, ctx->hmac.blocksize);
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA224,
				dst, *dstlen);
		r = md_finish(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA224,
				dst,  dstlen);
		break;
	case UT_PF_CP_ACT_MC_HMAC_SHA256:
		r = md_finish(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA256,
				dst, dstlen);
		r = md_starts(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA256);
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA256,
				ctx->hmac.opad, ctx->hmac.blocksize);
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA256,
				dst, *dstlen);
		r = md_finish(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA256,
				dst,  dstlen);
		break;
	case UT_PF_CP_ACT_MC_HMAC_SHA384:
		r = md_finish(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA384,
				dst, dstlen);
		r = md_starts(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA384);
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA384,
				ctx->hmac.opad, ctx->hmac.blocksize);
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA384,
				dst, *dstlen);
		r = md_finish(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA384,
				dst,  dstlen);
		break;
	case UT_PF_CP_ACT_MC_HMAC_SHA512:
		r = md_finish(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA512,
				dst, dstlen);
		r = md_starts(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA512);
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA512,
				ctx->hmac.opad, ctx->hmac.blocksize);
		r = md_update(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA512,
				dst, *dstlen);
		r = md_finish(&ctx->hmac.md, UT_PF_CP_ACT_MD_SHA512,
				dst,  dstlen);
		break;
	case UT_PF_CP_ACT_MC_CMAC_AES:
	case UT_PF_CP_ACT_MC_CMAC_DES:
	case UT_PF_CP_ACT_MC_CMAC_DS3:
		switch( action ) {
		case UT_PF_CP_ACT_MC_CMAC_AES:
			n = 16; cp_action = UT_PF_CP_ACT_SC_AES_ECB; break;
		case UT_PF_CP_ACT_MC_CMAC_DES:
			n =  8; cp_action = UT_PF_CP_ACT_SC_DES_ECB; break;
		case UT_PF_CP_ACT_MC_CMAC_DS3:
			n =  8; cp_action = UT_PF_CP_ACT_SC_DS3_ECB; break;
		}

		if ( dstlen == NULL || *dstlen < n )
			return -1;

		if (ctx->cmac.last_len == n) {
			_xor(ctx->cmac.last, ctx->cmac.k1, M_last, n);
		} else {
			_padding(ctx->cmac.last, padded, ctx->cmac.last_len, n);
			_xor(padded, ctx->cmac.k2, M_last, n);
		}

		if (n == 16) {
			/* Y := Mi (+) X */
			_xor(ctx->cmac.sc.aes.vec, M_last, Y, n);

			/* X := AES-128(KEY, Y); */
			r = sc_finish(&ctx->cmac.sc, cp_action,
					Y, n, ctx->cmac.sc.aes.vec, &n);
			if ( r < 0 ) return -1;

			for (i = 0; i < n; i++) {
				dst[i] = ctx->cmac.sc.aes.vec[i];
			}

			*dstlen = n;
		} else {
			/* Y := Mi (+) X */
			_xor(ctx->cmac.sc.des.vec, M_last, Y, n);

			/* X := AES-128(KEY, Y); */
			r = sc_finish(&ctx->cmac.sc, cp_action,
					Y, n, ctx->cmac.sc.des.vec, &n);
			if ( r < 0 ) return -1;

			for (i = 0; i < n; i++) {
				dst[i] = ctx->cmac.sc.des.vec[i];
			}

			*dstlen = n;
		}
		break;

	case UT_PF_CP_ACT_MC_CCMC_AES:
	case UT_PF_CP_ACT_MC_CCMC_DES:
	case UT_PF_CP_ACT_MC_CCMC_DS3:
		switch( action ) {
		case UT_PF_CP_ACT_MC_CCMC_AES:
			n = 16; cp_action = UT_PF_CP_ACT_SC_AES_ECB; break;
		case UT_PF_CP_ACT_MC_CCMC_DES:
			n =  8; cp_action = UT_PF_CP_ACT_SC_DES_ECB; break;
		case UT_PF_CP_ACT_MC_CCMC_DS3:
			n =  8; cp_action = UT_PF_CP_ACT_SC_DS3_ECB; break;
		}

		if ( dstlen == NULL || *dstlen < n )
			return -1;

		/* CBC: will auto use vector */
		r = sc_finish(&ctx->ccmc.sc, cp_action,
				ctx->ccmc.last, n, Y, &n);
		if ( r < 0 ) return -1;
		break;
	}

	return r;
}

static ut_int32_t ae_starts(
		ae_context_t *ctx, ut_int32_t action,
		ut_uint8_t *key, ut_uint32_t keylen,
		ut_uint8_t *vec, ut_uint32_t veclen,
		ut_uint32_t taglen, ut_uint32_t addlen, ut_uint32_t paylen)
{
	ut_int32_t r = 0;
	unsigned int M, L;
	MBEDRET3(set_aes_key(&ctx->aes.key,UTPFCP_CIPHER_ENC,key,keylen));
	
	switch( action ) {
	case UT_PF_CP_ACT_AE_AES_GCM:
		ctx->aes.mode.gcm.taglen = taglen;
		gcm128_init(&ctx->aes.mode.gcm.c, &ctx->aes.key,
			(block128_f)_aes_encrypt_block);
		gcm128_setiv(&ctx->aes.mode.gcm.c, vec, veclen);
		break;

	case UT_PF_CP_ACT_AE_AES_CCM:
		ctx->aes.mode.ccm.taglen = taglen;
		ctx->aes.mode.ccm.addlen = addlen;
		ctx->aes.mode.ccm.curlen =      0;
		if ( addlen > 0 ) {
			ctx->aes.mode.ccm.add= (unsigned char *)malloc(addlen);
			if ( !ctx->aes.mode.ccm.add ) {
				return -1;
			}
		}

		M = taglen; L = (15 - veclen);
		ccm128_init(&ctx->aes.mode.ccm.c, M, L, &ctx->aes.key,
			(block128_f)_aes_encrypt_block );
		ccm128_setiv(&ctx->aes.mode.ccm.c, vec, veclen, paylen);
		break;
	default:						return -1;
	}
end:
	return r;
}

static ut_int32_t ae_updadd(
		ae_context_t *ctx, ut_int32_t action,
		ut_uint8_t *add, ut_uint32_t addlen)
{
	ut_int32_t r = 0;

	switch( action ) {
	case UT_PF_CP_ACT_AE_AES_GCM:
		//gcm128_aad(&ctx->aes.mode.gcm.c, add, addlen);
		break;
	case UT_PF_CP_ACT_AE_AES_CCM:
		if (ctx->aes.mode.ccm.curlen +  addlen <= ctx->aes.mode.ccm.addlen) {
			memcpy(&ctx->aes.mode.ccm.add[ctx->aes.mode.ccm.curlen], add, addlen);
			ctx->aes.mode.ccm.curlen += addlen;
		} else {
			if ( ctx->aes.mode.ccm.add ) { free(ctx->aes.mode.ccm.add); }
			ctx->aes.mode.ccm.add = NULL;
			return -1;
		}

		if (ctx->aes.mode.ccm.curlen == ctx->aes.mode.ccm.addlen) {
			ccm128_aad(&ctx->aes.mode.ccm.c, ctx->aes.mode.ccm.add, ctx->aes.mode.ccm.addlen);
		}
		break;
	default:		return -1;
	}

	return r;
}

static ut_int32_t ae_update(
		ae_context_t *ctx, ut_int32_t action,
		ut_uint8_t *src, ut_uint32_t srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen, ut_int32_t enc)
{
	ut_int32_t r = 0;

	if (src == NULL || srclen == 0 ||
		dst == NULL || dstlen == NULL || *dstlen < srclen) {
		return -1;
	}

	if (srclen % 16)	return -1;

	switch( action ) {
	case UT_PF_CP_ACT_AE_AES_GCM:
		if ( enc )	{ r = gcm128_encrypt(&ctx->aes.mode.gcm.c, src, dst, srclen); }
		else		{ r = gcm128_decrypt(&ctx->aes.mode.gcm.c, src, dst, srclen); }
		if ( r == 0 ) { *dstlen = srclen; }
		break;
	case UT_PF_CP_ACT_AE_AES_CCM:
		if ( enc )	{ r = nistccm128_encrypt_block(&ctx->aes.mode.ccm.c, src, dst, srclen); }
		else		{ r = nistccm128_encrypt_block(&ctx->aes.mode.ccm.c, src, dst, srclen); }
		if ( r == 0 ) { *dstlen = srclen; }
		break;
	default:			return -1;
	}

	return r;
}

static ut_int32_t ae_finish(
		ae_context_t *ctx, ut_int32_t action,
		ut_uint8_t *src, ut_uint32_t srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen,
		ut_uint8_t *tag, ut_uint32_t *taglen,
		ut_int32_t enc)
{
	ut_int32_t r = 0;

	switch( action ) {
	case UT_PF_CP_ACT_AE_AES_GCM:
		if (src != NULL && srclen > 0) {
			if (dst == NULL || dstlen == NULL || *dstlen < srclen)
				return -1;
			if ( enc )	{ r = gcm128_encrypt(&ctx->aes.mode.gcm.c, src, dst, srclen); }
			else		{ r = gcm128_decrypt(&ctx->aes.mode.gcm.c, src, dst, srclen); }

			if ( r < 0 )	break;
			*dstlen =	   srclen;
		}

		if (tag != NULL && taglen != NULL) {
			unsigned char mac[32];

			gcm128_tag(&ctx->aes.mode.gcm.c, mac,
					ctx->aes.mode.gcm.taglen);

			if ( enc )	{
				if (*taglen < ctx->aes.mode.gcm.taglen)
					return -1;

				*taglen = ctx->aes.mode.gcm.taglen;
				memcpy(tag, mac, ctx->aes.mode.gcm.taglen);
			}
			else		{
				if (*taglen != ctx->aes.mode.gcm.taglen)
					return -1;

				if ( memcmp(mac, tag, *taglen) )
					return -1;
			}
		}
		break;

	case UT_PF_CP_ACT_AE_AES_CCM:
		if (src != NULL && srclen > 0) {
			if (dst == NULL || dstlen == NULL || *dstlen < srclen)
				return -1;
			if ( enc )	{ r = nistccm128_encrypt_finish(&ctx->aes.mode.ccm.c, src, dst, srclen); }
			else		{ r = nistccm128_decrypt_finish(&ctx->aes.mode.ccm.c, src, dst, srclen); }

			if ( r < 0 )	break;
			*dstlen =	   srclen;
		}

		if (tag != NULL && taglen != NULL) {
			unsigned char mac[32];

			ccm128_tag(&ctx->aes.mode.ccm.c, mac,
					ctx->aes.mode.ccm.taglen );
			if ( enc )	{
				if (*taglen < ctx->aes.mode.ccm.taglen)
					return -1;

				*taglen = ctx->aes.mode.ccm.taglen;
				memcpy(tag, mac, ctx->aes.mode.ccm.taglen);
			}
			else		{
				if (*taglen != ctx->aes.mode.ccm.taglen)
					return -1;

				if ( memcmp(mac, tag, *taglen) )
					return -1;
			}
		}
		break;
	default:			return -1;
	}

	return r;
}


static int init_random(ac_context_t *ctx)
{
	const char * pers = "beanpodtech_rand_for_mask";
	int r=-UTPFCP_ERR_UNKNOWN;
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
	
	mbedtls_rsa_init(&ctx->rsa.key, 0, 0 );
    ctx->rsa.key.len = __nlen;
	MBEDRET(UTPFCP_ERR_INVALID_PARAMS,mbedtls_mpi_read_binary(&(ctx->rsa.key.N),__n,__nlen));
	MBEDRET(UTPFCP_ERR_INVALID_PARAMS,mbedtls_mpi_read_binary(&(ctx->rsa.key.E),__e,__elen));
	r = init_random(ctx);
end:	
	if(r<0)
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

	if ( __p != NULL && __q != NULL &&
		 _dp != NULL && _dq != NULL && _qp != NULL)
		optimized = 1;
	else
		optimized = 0;
	mbedtls_rsa_init(&ctx->rsa.key, 0, 0 ); 
    ctx->rsa.key.len = __nlen;
	if(__n!=NULL && __nlen >0 )
		MBEDRET(UTPFCP_ERR_INVALID_PARAMS,mbedtls_mpi_read_binary(&(ctx->rsa.key.N),__n,__nlen));
	if(__e!=NULL && __elen >0 )
		MBEDRET(UTPFCP_ERR_INVALID_PARAMS,mbedtls_mpi_read_binary(&(ctx->rsa.key.E),__e,__elen));	
	if(__d!=NULL && __dlen >0 )
		MBEDRET(UTPFCP_ERR_INVALID_PARAMS,mbedtls_mpi_read_binary(&(ctx->rsa.key.D),__d,__dlen));
  
	if(optimized)
	{
		MBEDRET(UTPFCP_ERR_INVALID_PARAMS,mbedtls_mpi_read_binary(&(ctx->rsa.key.P),__p,__plen));
		MBEDRET(UTPFCP_ERR_INVALID_PARAMS,mbedtls_mpi_read_binary(&(ctx->rsa.key.Q),__q,__qlen));	
		MBEDRET(UTPFCP_ERR_INVALID_PARAMS,mbedtls_mpi_read_binary(&(ctx->rsa.key.DP),_dp,_dplen));
		MBEDRET(UTPFCP_ERR_INVALID_PARAMS,mbedtls_mpi_read_binary(&(ctx->rsa.key.DQ),_dq,_dqlen));
		MBEDRET(UTPFCP_ERR_INVALID_PARAMS,mbedtls_mpi_read_binary(&(ctx->rsa.key.QP),_qp,_qplen));	
	}
	r = init_random(ctx);
end:	
	if(r<0)
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
		ac_context_t *ctx,  ut_int32_t action,
		ut_uint8_t *sal, ut_uint32_t  sallen,
		ut_uint8_t *src, ut_uint32_t  srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t  r = 0;
	if(*dstlen< ctx->rsa.key.len)
			return -UTPFCP_ERR_TOOSMALLLEN;
	((void)sal);
	sallen=0;
	switch( action ) {
	case UT_PF_CP_ACT_AC_RSA_NOPAD:
		if(srclen!=ctx->rsa.key.len )
			return -UTPFCP_ERR_INVALID_PARAMS;
		 MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_public( &ctx->rsa.key,
                (const unsigned char *)src,
                (unsigned char *)dst ));
		*dstlen =ctx->rsa.key.len;
		break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5:
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_rsaes_pkcs1_v15_encrypt( &ctx->rsa.key, mbedtls_ctr_drbg_random,
			&ctx->rsa.rng_ctx,
			MBEDTLS_RSA_PUBLIC,
			srclen,src, dst ));
		*dstlen=ctx->rsa.key.len;									
		break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA1:  
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA224: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA256: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA384: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA512: 
		ctx->rsa.key.padding = MBEDTLS_RSA_PKCS_V21;
		ctx->rsa.key.hash_id = get_hashid(action);
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_rsaes_oaep_encrypt( &ctx->rsa.key,mbedtls_ctr_drbg_random,
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
		ac_context_t *ctx,  ut_int32_t action,
		ut_uint8_t *sal, ut_uint32_t  sallen,
		ut_uint8_t *src, ut_uint32_t  srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t  r = 0;
	size_t outlen = *dstlen;
	((void)sal);
	sallen=0;
	if(*dstlen< ctx->rsa.key.len)
			return -UTPFCP_ERR_TOOSMALLLEN;
	if(srclen!=ctx->rsa.key.len)
		return -UTPFCP_ERR_INVALID_PARAMS;
	switch( action ) {
	case UT_PF_CP_ACT_AC_RSA_NOPAD:
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_private( &ctx->rsa.key,
			mbedtls_ctr_drbg_random,
			&ctx->rsa.rng_ctx,
			(const unsigned char *)src,
			(unsigned char *)dst ));
		*dstlen = ctx->rsa.key.len;
		break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5:
		MBEDRET(UTPFCP_ERR_RSA,  mbedtls_rsa_rsaes_pkcs1_v15_decrypt( &ctx->rsa.key,
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
		ctx->rsa.key.padding = MBEDTLS_RSA_PKCS_V21;
		ctx->rsa.key.hash_id = get_hashid(action);
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_rsaes_oaep_decrypt( &ctx->rsa.key,mbedtls_ctr_drbg_random,
					&ctx->rsa.rng_ctx,
					MBEDTLS_RSA_PRIVATE,
					NULL, 0,
					&outlen,
					(const unsigned char *)src,
					(unsigned char *)dst,
					*dstlen ));
		*dstlen = outlen;
		break;
	default:				return -UTPFCP_ERR_UNKNOWN_ACTION;
	}
end:
	return r;
}

static ut_int32_t rsa_sign(
		ac_context_t *ctx,  ut_int32_t action,
		ut_uint8_t *sal, ut_uint32_t  sallen,
		ut_uint8_t *hash, ut_uint32_t  hashlen,
		ut_uint8_t *sig, ut_uint32_t *siglen)
{
	ut_int32_t  r = 0;
	ut_uint32_t l = ctx->rsa.key.len;
	((void)sal);
	sallen=0;
	if ( hash == NULL || sig == NULL ||
		 siglen == NULL || *siglen < l )
		return -UTPFCP_ERR_INVALID_PARAMS;
	ctx->rsa.key.hash_id = get_hashid(action);
	switch( action ) {
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_MD5: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA1: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA224: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA256: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA384: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA512: 
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_rsassa_pkcs1_v15_sign( &ctx->rsa.key,mbedtls_ctr_drbg_random,
				&ctx->rsa.rng_ctx,
				MBEDTLS_RSA_PRIVATE,
				ctx->rsa.key.hash_id,
				(unsigned int )hashlen,
				(const unsigned char *)hash,
				(unsigned char *)sig ));
		*siglen	= ctx->rsa.key.len;						   
		break;

	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA1: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA224: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA256: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA384: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA512: 
		ctx->rsa.key.padding = MBEDTLS_RSA_PKCS_V21;
		 MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_rsassa_pss_sign(  &ctx->rsa.key,mbedtls_ctr_drbg_random,
				&ctx->rsa.rng_ctx,
				MBEDTLS_RSA_PRIVATE,
				ctx->rsa.key.hash_id,
				(unsigned int )hashlen,
				(const unsigned char *)hash,
				(unsigned char *)sig ));
		*siglen	= ctx->rsa.key.len;			
		break;
	default:				return -UTPFCP_ERR_UNKNOWN_ACTION;
	}
end:
	return r;
}

static ut_int32_t rsa_verify(
		ac_context_t *ctx,  ut_int32_t action,
		ut_uint8_t *sal, ut_uint32_t sallen,
		ut_uint8_t *hash, ut_uint32_t hashlen,
		ut_uint8_t *sig, ut_uint32_t siglen)
{
	ut_int32_t  r = 0;
	ut_uint32_t l = ctx->rsa.key.len;
	((void)sal);
	sallen=0;
	if ( hash == NULL || hashlen <= 0 ||
		 sig == NULL || siglen != l )
		return -UTPFCP_ERR_INVALID_PARAMS;
	ctx->rsa.key.hash_id = get_hashid(action);
	switch( action ) {
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_MD5: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA1: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA224: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA256: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA384: 
	case UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA512: 
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_rsassa_pkcs1_v15_verify( &ctx->rsa.key,mbedtls_ctr_drbg_random,
				&ctx->rsa.rng_ctx,
				MBEDTLS_RSA_PUBLIC,
				ctx->rsa.key.hash_id,
				( unsigned int )hashlen,
				( const unsigned char *)hash,
				( const unsigned char *)sig ));
			
		break;
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA1:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA224:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA256:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA384:
	case UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA512:
		ctx->rsa.key.padding = MBEDTLS_RSA_PKCS_V21;
		MBEDRET(UTPFCP_ERR_RSA, mbedtls_rsa_rsassa_pss_verify( &ctx->rsa.key,mbedtls_ctr_drbg_random,
				&ctx->rsa.rng_ctx,
				MBEDTLS_RSA_PUBLIC,
				ctx->rsa.key.hash_id,
				( unsigned int )hashlen,
				( const unsigned char *)hash,
				( const unsigned char *)sig ));
		break;
	default:				return -UTPFCP_ERR_UNKNOWN_ACTION;
	}
end:
	return r;
}

static ut_int32_t ecc_ecdsa_sign(
		ac_context_t *ctx,  ut_int32_t action,
		ut_uint8_t *__k, ut_uint32_t  __klen,
		ut_uint8_t *has, ut_uint32_t  haslen,
		ut_uint8_t *sig, ut_uint32_t *siglen)
{
	ut_int32_t r = 0;

	psEccSet_t *ecc_set = NULL;
	psEccKey_t *ecc_key = NULL;

	switch( action ) {
	case UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA512:
		{ getEccParamByName("ECC-192", &ecc_set ); } break; /* secp192r1 */
	case UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA512:
		{ getEccParamByName("ECC-224", &ecc_set ); } break; /* secp224r1 */
	case UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA512:
		{ getEccParamByName("ECC-256", &ecc_set ); } break; /* secp256r1 */
	case UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA512:
		{ getEccParamByName("ECC-384", &ecc_set ); } break; /* secp384r1 */
	case UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA512:
		{ getEccParamByName("ECC-521", &ecc_set ); } break; /* secp521r1 */
		break;
	case UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA512:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA512:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA512:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA512:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA512:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA512:
	default:				return -1;
	}

	ecc_key = (psEccKey_t *)psMalloc(0, sizeof(psEccKey_t));
	if ( ecc_key == NULL )	return -1;

	ecc_key->pool	= NULL;
	ecc_key->type	= PS_ECC;
	ecc_key->dp 	= ecc_set;

	pstm_init_size(NULL, &ecc_key->pubkey.z, 1);
	pstm_set(&ecc_key->pubkey.z, 1);
	pstm_init_for_read_unsigned_bin(NULL, &ecc_key->k, __klen);
	pstm_read_unsigned_bin(&ecc_key->k, __k, __klen);

	pstm_init_for_read_unsigned_bin(NULL, &ecc_key->pubkey.x, 0);
	pstm_init_for_read_unsigned_bin(NULL, &ecc_key->pubkey.y, 0/*__klen*/);
	r = psEccSignHash(NULL, has, haslen, sig, *siglen, ecc_key, siglen, 0, NULL);

	psEccFreeKey(&ecc_key);
	ecc_key = NULL;
	return r;
}

static ut_int32_t ecc_ecdsa_verify(
		ac_context_t *ctx,  ut_int32_t action,
		ut_uint8_t *__x, ut_uint32_t  __xlen,
		ut_uint8_t *__y, ut_uint32_t  __ylen,
		ut_uint8_t *has, ut_uint32_t  haslen,
		ut_uint8_t *sig, ut_uint32_t  siglen)
{
	ut_int32_t r = 0;
	ut_int32_t stat = 0;

	psEccSet_t *ecc_set = NULL;
	psEccKey_t *ecc_key = NULL;

	switch( action ) {
	case UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192R1_SHA512:
		{ getEccParamByName("ECC-192", &ecc_set ); } break; /* secp192r1 */
	case UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224R1_SHA512:
		{ getEccParamByName("ECC-224", &ecc_set ); } break; /* secp224r1 */
	case UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256R1_SHA512:
		{ getEccParamByName("ECC-256", &ecc_set ); } break; /* secp256r1 */
	case UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP384R1_SHA512:
		{ getEccParamByName("ECC-384", &ecc_set ); } break; /* secp384r1 */
	case UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP521R1_SHA512:
		{ getEccParamByName("ECC-521", &ecc_set ); } break; /* secp521r1 */
		break;
	case UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160K1_SHA512:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R1_SHA512:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP160R2_SHA512:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP192K1_SHA512:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP224K1_SHA512:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA1:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA224:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA256:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA384:
	case UT_PF_CP_ACT_AC_ECDSA_SEP256K1_SHA512:
	default:				return -1;
	}

	ecc_key = (psEccKey_t *)psMalloc(0, sizeof(psEccKey_t));
	if ( ecc_key == NULL )	return -1;

	ecc_key->pool	= NULL;
	ecc_key->type	= PS_ECC;
	ecc_key->dp 	= ecc_set;

	pstm_init_size(NULL, &ecc_key->pubkey.z, 1);
	pstm_set(&ecc_key->pubkey.z, 1);
	pstm_init_for_read_unsigned_bin(NULL, &ecc_key->pubkey.x, __xlen);
	pstm_read_unsigned_bin(&ecc_key->pubkey.x, __x, __xlen);
	pstm_init_for_read_unsigned_bin(NULL, &ecc_key->pubkey.y, __ylen);
	pstm_read_unsigned_bin(&ecc_key->pubkey.y, __y, __ylen);

	pstm_init_for_read_unsigned_bin(NULL, &ecc_key->k, 0);
	r = psEcDsaValidateSignature(NULL, ecc_key, sig, siglen, has, haslen, &stat, NULL);
	psEccFreeKey(&ecc_key);

	if ( stat > 0 )	r =  0;	// success.
	else			r = -1; // fail.

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

static void NEON_256_mul_256(const unsigned *a, const unsigned *b, unsigned *r)
{

	asm volatile (													\
				"vmov.u32 q8, #0 \n\t"								\
				"vmov.u32 q9, #0 \n\t"								\
				"vmov.u32 q10, #0 \n\t"								\
				"vmov.u32 q11, #0 \n\t"								\
				"vld1.32 {d0, d1, d2, d3}, [%2] \n\t"

				"vld4.32 {d4, d5, d6, d7}, [%1]! \n\t"				\
				"vld1.32 {d24, d25, d26, d27}, [%0] \n\t"			\
				"vswp d25, d26 \n\t"								\
				"vtrn.32 q12, q13 \n\t"								\
				"vmov.u32 q14, #0 \n\t"								\
				"vtrn.u32 q12, q14 \n\t"							\
				"vmov.u32 q15, #0 \n\t"								\
				"vtrn.u32 q13, q15 \n\t"							\
				"vadd.u64 q8, q8, q12 \n\t"							\
				"vadd.u64 q9, q9, q13 \n\t"							\
				"vadd.u64 q10, q10, q14 \n\t"						\
				"vadd.u64 q11, q11, q15 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q8, q4 \n\t"								\
				"vadd.u64 q9, q9, q4 \n\t"							\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q9, q4 \n\t"								\
				"vadd.u64 q10, q10, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q10, q4 \n\t"								\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vmov.u32 q12, #0 \n\t"								\
				"vtrn.32 q11, q12 \n\t"								\
				"vdup.32 d8, d0[0] \n\t"							\
				"vmlal.u32 q8, d4, d8 \n\t"							\
				"vmlal.u32 q9, d5, d8 \n\t"							\
				"vmlal.u32 q10, d6, d8 \n\t"						\
				"vmlal.u32 q11, d7, d8 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q8, q4 \n\t"								\
				"vadd.u64 q9, q9, q4 \n\t"							\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q9, q4 \n\t"								\
				"vadd.u64 q10, q10, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q10, q4 \n\t"								\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.u32 q11, q4 \n\t"								\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vmov.u32 q13, #0 \n\t"								\
				"vtrn.u32 q12, q13 \n\t"							\
				"vadd.u64 d24, d24, d17 \n\t"						\
				"vmov.u32 d8, #0 \n\t"								\
				"vtrn.u32 d24, d8 \n\t"								\
				"vadd.u64 d19, d19, d8 \n\t"						\
				"vdup.32 d8, d0[1] \n\t"							\
				"vmlal.u32 q9, d4, d8 \n\t"							\
				"vmlal.u32 q10, d5, d8 \n\t"						\
				"vmlal.u32 q11, d6, d8 \n\t"						\
				"vmlal.u32 q12, d7, d8 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q9, q4 \n\t"								\
				"vadd.u64 q10, q10, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q10, q4 \n\t"								\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q11, q4 \n\t"								\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.u32 q12, q4 \n\t"								\
				"vadd.u64 q13, q13, q4 \n\t"						\
				"vmov.u32 q14, #0 \n\t"								\
				"vtrn.u32 q13, q14 \n\t"							\
				"vadd.u64 d26, d26, d19 \n\t"						\
				"vmov.u32 d8, #0 \n\t"								\
				"vtrn.u32 d26, d8 \n\t"								\
				"vadd.u64 d21, d21, d8 \n\t"						\
				"vtrn.u32 d16, d18 \n\t"							\
				"vst1.64 d16, [%0]! \n\t"							\
				"vdup.32 d8, d1[0] \n\t"							\
				"vmlal.u32 q10, d4, d8 \n\t"						\
				"vmlal.u32 q11, d5, d8 \n\t"						\
				"vmlal.u32 q12, d6, d8 \n\t"						\
				"vmlal.u32 q13, d7, d8 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q10, q4 \n\t"								\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q11, q4 \n\t"								\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q12, q4 \n\t"								\
				"vadd.u64 q13, q13, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.u32 q13, q4 \n\t"								\
				"vadd.u64 q14, q14, q4 \n\t"						\
				"vmov.u32 q15, #0 \n\t"								\
				"vtrn.u32 q14, q15 \n\t"							\
				"vadd.u64 d28, d28, d21 \n\t"						\
				"vmov.u32 d8, #0 \n\t"								\
				"vtrn.u32 d28, d8 \n\t"								\
				"vadd.u64 d23, d23, d8 \n\t"						\
				"vdup.32 d8, d1[1] \n\t"							\
				"vmlal.u32 q11, d4, d8 \n\t"						\
				"vmlal.u32 q12, d5, d8 \n\t"						\
				"vmlal.u32 q13, d6, d8 \n\t"						\
				"vmlal.u32 q14, d7, d8 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q11, q4 \n\t"								\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q12, q4 \n\t"								\
				"vadd.u64 q13, q13, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q13, q4 \n\t"								\
				"vadd.u64 q14, q14, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.u32 q14, q4 \n\t"								\
				"vadd.u64 q15, q15, q4 \n\t"						\
				"vmov.u32 q8, #0 \n\t"								\
				"vtrn.u32 q15, q8 \n\t"								\
				"vadd.u64 d30, d30, d23 \n\t"						\
				"vmov.u32 d8, #0 \n\t"								\
				"vtrn.u32 d30, d8 \n\t"								\
				"vadd.u64 d25, d25, d8 \n\t"						\
				"vtrn.u32 d20, d22 \n\t"							\
				"vst1.64 d20, [%0]! \n\t"							\
				"vdup.32 d8, d2[0] \n\t"							\
				"vmlal.u32 q12, d4, d8 \n\t"						\
				"vmlal.u32 q13, d5, d8 \n\t"						\
				"vmlal.u32 q14, d6, d8 \n\t"						\
				"vmlal.u32 q15, d7, d8 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q12, q4 \n\t"								\
				"vadd.u64 q13, q13, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q13, q4 \n\t"								\
				"vadd.u64 q14, q14, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q14, q4 \n\t"								\
				"vadd.u64 q15, q15, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.u32 q15, q4 \n\t"								\
				"vadd.u64 q8, q8, q4 \n\t"							\
				"vmov.u32 q9, #0 \n\t"								\
				"vtrn.u32 q8, q9 \n\t"								\
				"vadd.u64 d16, d16, d25 \n\t"						\
				"vmov.u32 d8, #0 \n\t"								\
				"vtrn.u32 d16, d8 \n\t"								\
				"vadd.u64 d27, d27, d8 \n\t"						\
				"vdup.32 d8, d2[1] \n\t"							\
				"vmlal.u32 q13, d4, d8 \n\t"						\
				"vmlal.u32 q14, d5, d8 \n\t"						\
				"vmlal.u32 q15, d6, d8 \n\t"						\
				"vmlal.u32 q8, d7, d8 \n\t"							\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q13, q4 \n\t"								\
				"vadd.u64 q14, q14, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q14, q4 \n\t"								\
				"vadd.u64 q15, q15, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q15, q4 \n\t"								\
				"vadd.u64 q8, q8, q4 \n\t"							\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.u32 q8, q4 \n\t"								\
				"vadd.u64 q9, q9, q4 \n\t"							\
				"vmov.u32 q10, #0 \n\t"								\
				"vtrn.u32 q9, q10 \n\t"								\
				"vadd.u64 d18, d18, d27 \n\t"						\
				"vmov.u32 d8, #0 \n\t"								\
				"vtrn.u32 d18, d8 \n\t"								\
				"vadd.u64 d29, d29, d8 \n\t"						\
				"vtrn.u32 d24, d26 \n\t"							\
				"vst1.64 d24, [%0]! \n\t"							\
				"vdup.32 d8, d3[0] \n\t"							\
				"vmlal.u32 q14, d4, d8 \n\t"						\
				"vmlal.u32 q15, d5, d8 \n\t"						\
				"vmlal.u32 q8, d6, d8 \n\t"							\
				"vmlal.u32 q9, d7, d8 \n\t"							\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q14, q4 \n\t"								\
				"vadd.u64 q15, q15, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q15, q4 \n\t"								\
				"vadd.u64 q8, q8, q4 \n\t"							\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q8, q4 \n\t"								\
				"vadd.u64 q9, q9, q4 \n\t"							\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.u32 q9, q4 \n\t"								\
				"vadd.u64 q10, q10, q4 \n\t"						\
				"vmov.u32 q11, #0 \n\t"								\
				"vtrn.u32 q10, q11 \n\t"							\
				"vadd.u64 d20, d20, d29 \n\t"						\
				"vmov.u32 d8, #0 \n\t"								\
				"vtrn.u32 d20, d8 \n\t"								\
				"vadd.u64 d31, d31, d8 \n\t"						\
				"vdup.32 d8, d3[1] \n\t"							\
				"vmlal.u32 q15, d4, d8 \n\t"						\
				"vmlal.u32 q8, d5, d8 \n\t"							\
				"vmlal.u32 q9, d6, d8 \n\t"							\
				"vmlal.u32 q10, d7, d8 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q15, q4 \n\t"								\
				"vadd.u64 q8, q8, q4 \n\t"							\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q8, q4 \n\t"								\
				"vadd.u64 q9, q9, q4 \n\t"							\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.32 q9, q4 \n\t"								\
				"vadd.u64 q10, q10, q4 \n\t"						\
				"vmov.u32 q4, #0 \n\t"								\
				"vtrn.u32 q10, q4 \n\t"								\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vmov.u32 q12, #0 \n\t"								\
				"vtrn.u32 q11, q12 \n\t"							\
				"vadd.u64 d22, d22, d31 \n\t"						\
				"vmov.u32 d8, #0 \n\t"								\
				"vtrn.u32 d22, d8 \n\t"								\
				"vadd.u64 d17, d17, d8 \n\t"						\
				"vmov.u32 d8, #0 \n\t"								\
				"vtrn.u32 d17, d8 \n\t"								\
				"vadd.u64 d19, d19, d8 \n\t"						\
				"vmov.u32 d8, #0 \n\t"								\
				"vtrn.u32 d19, d8 \n\t"								\
				"vadd.u64 d21, d21, d8 \n\t"						\
				"vmov.u32 d8, #0 \n\t"								\
				"vtrn.u32 d21, d8 \n\t"								\
				"vadd.u64 d23, d23, d8 \n\t"						\
				"vtrn.u32 d28, d30 \n\t"							\
				"vst1.64 d28, [%0]! \n\t"

				"vld1.32 {d24, d25, d26, d27}, [%0] \n\t"			\
				"vswp d25, d26 \n\t"								\
				"vtrn.32 q12, q13 \n\t"								\
				"vmov.u32 q14, #0 \n\t"								\
				"vmov.u32 q15, #0 \n\t"								\
				"vtrn.u32 q12, q14 \n\t"							\
				"vtrn.u32 q13, q15 \n\t"							\

				"vadd.u64 q8, q8, q12 \n\t"							\
				"vadd.u64 q9, q9, q13 \n\t"							\
				"vadd.u64 q10, q10, q14 \n\t"						\
				"vadd.u64 q11, q11, q15 \n\t"						\
				
				"vshr.u64 d8, d16, #32 \n\t"						\
				"vadd.u64 d18, d18, d8 \n\t"						\
				"vshr.u64 d8, d18, #32 \n\t"						\
				"vadd.u64 d20, d20, d8 \n\t"						\
				"vshr.u64 d8, d20, #32 \n\t"						\
				"vadd.u64 d22, d22, d8 \n\t"						\
				"vshr.u64 d8, d22, #32 \n\t"						\
				"vadd.u64 d17, d17, d8 \n\t"						\
				"vshr.u64 d8, d17, #32 \n\t"						\
				"vadd.u64 d19, d19, d8 \n\t"						\
				"vshr.u64 d8, d19, #32 \n\t"						\
				"vadd.u64 d21, d21, d8 \n\t"						\
				"vshr.u64 d8, d21, #32 \n\t"						\
				"vadd.u64 d23, d23, d8 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vand q8, q8, q4 \n\t"								\
				"vand q9, q9, q4 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vtrn.u32 q8, q10 \n\t"								\
				"vtrn.u32 q9, q11 \n\t"								\
				"vtrn.u32 q8, q9 \n\t"								\
				"vswp d17, d18 \n\t"								\
				"vst1.32 {d16, d17, d18, d19}, [%0] \n\t"			\
				:: "r"(r), "r"(a), "r"(b)							\
				: "q0", "q1", "q2", "q3", "q4", "q8", "q9", "q10",	\
				"q11", "q12", "q13", "q14", "q15", "memory"			\
				);
}

#define NEON_256_MUL_256_START										\
	asm volatile (													\
				"vmov.u32 q8, #0 \n\t"								\
				"vmov.u32 q9, #0 \n\t"								\
				"vmov.u32 q10, #0 \n\t"								\
				"vmov.u32 q11, #0 \n\t"								\
				"vld1.32 {d0, d1, d2, d3}, [%2] \n\t"
#define NEON_256_MUL_256_CORE										\
				"vld4.32 {d4, d5, d6, d7}, [%1]! \n\t"				\
				"vld1.32 {d24, d25, d26, d27}, [%0] \n\t"			\
				"vswp d25, d26 \n\t"								\
				"vtrn.32 q12, q13 \n\t"								\
				"vshr.u64 q14, q12, #32 \n\t"						\
				"vshr.u64 q15, q13, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand.u64 q12, q12, q4 \n\t"						\
				"vand.u64 q13, q13, q4 \n\t"						\
				"vadd.u64 q8, q8, q12 \n\t"							\
				"vadd.u64 q9, q9, q13 \n\t"							\
				"vadd.u64 q10, q10, q14 \n\t"						\
				"vadd.u64 q11, q11, q15 \n\t"						\
				"vshr.u64 q4, q8, #32 \n\t"							\
				"vadd.u64 q9, q9, q4 \n\t"							\
				"vshr.u64 q4, q9, #32 \n\t"							\
				"vadd.u64 q10, q10, q4 \n\t"						\
				"vshr.u64 q4, q10, #32 \n\t"						\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vshr.u64 q12, q11, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q8, q8, q4 \n\t"								\
				"vand q9, q9, q4 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vdup.32 d8, d0[0] \n\t"							\
				"vmlal.u32 q8, d4, d8 \n\t"							\
				"vmlal.u32 q9, d5, d8 \n\t"							\
				"vmlal.u32 q10, d6, d8 \n\t"						\
				"vmlal.u32 q11, d7, d8 \n\t"						\
				"vshr.u64 q4, q8, #32 \n\t"							\
				"vadd.u64 q9, q9, q4 \n\t"							\
				"vshr.u64 q4, q9, #32 \n\t"							\
				"vadd.u64 q10, q10, q4 \n\t"						\
				"vshr.u64 q4, q10, #32 \n\t"						\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vshr.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vshr.u64 q13, q12, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q8, q8, q4 \n\t"								\
				"vand q9, q9, q4 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vand q12, q12, q4 \n\t"							\
				"vadd.u64 d24, d24, d17 \n\t"						\
				"vshr.u64 d8, d24, #32 \n\t"						\
				"vadd.u64 d19, d19, d8 \n\t"						\
				"vand d24, d24, d9 \n\t"							\
				"vdup.32 d8, d0[1] \n\t"							\
				"vmlal.u32 q9, d4, d8 \n\t"							\
				"vmlal.u32 q10, d5, d8 \n\t"						\
				"vmlal.u32 q11, d6, d8 \n\t"						\
				"vmlal.u32 q12, d7, d8 \n\t"						\
				"vshr.u64 q4, q9, #32 \n\t"							\
				"vadd.u64 q10, q10, q4 \n\t"						\
				"vshr.u64 q4, q10, #32 \n\t"						\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vshr.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vshr.u64 q4, q12, #32 \n\t"						\
				"vadd.u64 q13, q13, q4 \n\t"						\
				"vshr.u64 q14, q13, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q9, q9, q4 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vand q12, q12, q4 \n\t"							\
				"vand q13, q13, q4 \n\t"							\
				"vadd.u64 d26, d26, d19 \n\t"						\
				"vshr.u64 d8, d26, #32 \n\t"						\
				"vadd.u64 d21, d21, d8 \n\t"						\
				"vand d26, d26, d9 \n\t"							\
				"vshl.u64 d18, #32 \n\t"							\
				"vadd.u64 d16, d16, d18 \n\t"						\
				"vst1.64 d16, [%0]! \n\t"							\
				"vdup.32 d8, d1[0] \n\t"							\
				"vmlal.u32 q10, d4, d8 \n\t"						\
				"vmlal.u32 q11, d5, d8 \n\t"						\
				"vmlal.u32 q12, d6, d8 \n\t"						\
				"vmlal.u32 q13, d7, d8 \n\t"						\
				"vshr.u64 q4, q10, #32 \n\t"						\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vshr.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vshr.u64 q4, q12, #32 \n\t"						\
				"vadd.u64 q13, q13, q4 \n\t"						\
				"vshr.u64 q4, q13, #32 \n\t"						\
				"vadd.u64 q14, q14, q4 \n\t"						\
				"vshr.u64 q15, q14, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vand q12, q12, q4 \n\t"							\
				"vand q13, q13, q4 \n\t"							\
				"vand q14, q14, q4 \n\t"							\
				"vadd.u64 d28, d28, d21 \n\t"						\
				"vshr.u64 d8, d28, #32 \n\t"						\
				"vadd.u64 d23, d23, d8 \n\t"						\
				"vand d28, d28, d9 \n\t"							\
				"vdup.32 d8, d1[1] \n\t"							\
				"vmlal.u32 q11, d4, d8 \n\t"						\
				"vmlal.u32 q12, d5, d8 \n\t"						\
				"vmlal.u32 q13, d6, d8 \n\t"						\
				"vmlal.u32 q14, d7, d8 \n\t"						\
				"vshr.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vshr.u64 q4, q12, #32 \n\t"						\
				"vadd.u64 q13, q13, q4 \n\t"						\
				"vshr.u64 q4, q13, #32 \n\t"						\
				"vadd.u64 q14, q14, q4 \n\t"						\
				"vshr.u64 q4, q14, #32 \n\t"						\
				"vadd.u64 q15, q15, q4 \n\t"						\
				"vshr.u64 q8, q15, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q11, q11, q4 \n\t"							\
				"vand q12, q12, q4 \n\t"							\
				"vand q13, q13, q4 \n\t"							\
				"vand q14, q14, q4 \n\t"							\
				"vand q15, q15, q4 \n\t"							\
				"vadd.u64 d30, d30, d23 \n\t"						\
				"vshr.u64 d8, d30, #32 \n\t"						\
				"vadd.u64 d25, d25, d8 \n\t"						\
				"vand d30, d30, d9 \n\t"							\
				"vshl.u64 d22, #32 \n\t"							\
				"vadd.u64 d20, d20, d22 \n\t"						\
				"vst1.64 d20, [%0]! \n\t"							\
				"vdup.32 d8, d2[0] \n\t"							\
				"vmlal.u32 q12, d4, d8 \n\t"						\
				"vmlal.u32 q13, d5, d8 \n\t"						\
				"vmlal.u32 q14, d6, d8 \n\t"						\
				"vmlal.u32 q15, d7, d8 \n\t"						\
				"vshr.u64 q4, q12, #32 \n\t"						\
				"vadd.u64 q13, q13, q4 \n\t"						\
				"vshr.u64 q4, q13, #32 \n\t"						\
				"vadd.u64 q14, q14, q4 \n\t"						\
				"vshr.u64 q4, q14, #32 \n\t"						\
				"vadd.u64 q15, q15, q4 \n\t"						\
				"vshr.u64 q4, q15, #32 \n\t"						\
				"vadd.u64 q8, q8, q4 \n\t"							\
				"vshr.u64 q9, q8, #32 \n\t"							\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q12, q12, q4 \n\t"							\
				"vand q13, q13, q4 \n\t"							\
				"vand q14, q14, q4 \n\t"							\
				"vand q15, q15, q4 \n\t"							\
				"vand q8, q8, q4 \n\t"								\
				"vadd.u64 d16, d16, d25 \n\t"						\
				"vshr.u64 d8, d16, #32 \n\t"						\
				"vadd.u64 d27, d27, d8 \n\t"						\
				"vand d16, d16, d9 \n\t"							\
				"vdup.32 d8, d2[1] \n\t"							\
				"vmlal.u32 q13, d4, d8 \n\t"						\
				"vmlal.u32 q14, d5, d8 \n\t"						\
				"vmlal.u32 q15, d6, d8 \n\t"						\
				"vmlal.u32 q8, d7, d8 \n\t"							\
				"vshr.u64 q4, q13, #32 \n\t"						\
				"vadd.u64 q14, q14, q4 \n\t"						\
				"vshr.u64 q4, q14, #32 \n\t"						\
				"vadd.u64 q15, q15, q4 \n\t"						\
				"vshr.u64 q4, q15, #32 \n\t"						\
				"vadd.u64 q8, q8, q4 \n\t"							\
				"vshr.u64 q4, q8, #32 \n\t"							\
				"vadd.u64 q9, q9, q4 \n\t"							\
				"vshr.u64 q10, q9, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q13, q13, q4 \n\t"							\
				"vand q14, q14, q4 \n\t"							\
				"vand q15, q15, q4 \n\t"							\
				"vand q8, q8, q4 \n\t"								\
				"vand q9, q9, q4 \n\t"								\
				"vadd.u64 d18, d18, d27 \n\t"						\
				"vshr.u64 d8, d18, #32 \n\t"						\
				"vadd.u64 d29, d29, d8 \n\t"						\
				"vand d18, d18, d9 \n\t"							\
				"vshl.u64 d26, #32 \n\t"							\
				"vadd.u64 d24, d24, d26 \n\t"						\
				"vst1.64 d24, [%0]! \n\t"							\
				"vdup.32 d8, d3[0] \n\t"							\
				"vmlal.u32 q14, d4, d8 \n\t"						\
				"vmlal.u32 q15, d5, d8 \n\t"						\
				"vmlal.u32 q8, d6, d8 \n\t"							\
				"vmlal.u32 q9, d7, d8 \n\t"							\
				"vshr.u64 q4, q14, #32 \n\t"						\
				"vadd.u64 q15, q15, q4 \n\t"						\
				"vshr.u64 q4, q15, #32 \n\t"						\
				"vadd.u64 q8, q8, q4 \n\t"							\
				"vshr.u64 q4, q8, #32 \n\t"							\
				"vadd.u64 q9, q9, q4 \n\t"							\
				"vshr.u64 q4, q9, #32 \n\t"							\
				"vadd.u64 q10, q10, q4 \n\t"						\
				"vshr.u64 q11, q10, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q14, q14, q4 \n\t"							\
				"vand q15, q15, q4 \n\t"							\
				"vand q8, q8, q4 \n\t"								\
				"vand q9, q9, q4 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vadd.u64 d20, d20, d29 \n\t"						\
				"vshr.u64 d8, d20, #32 \n\t"						\
				"vadd.u64 d31, d31, d8 \n\t"						\
				"vand d20, d20, d9 \n\t"							\
				"vdup.32 d8, d3[1] \n\t"							\
				"vmlal.u32 q15, d4, d8 \n\t"						\
				"vmlal.u32 q8, d5, d8 \n\t"							\
				"vmlal.u32 q9, d6, d8 \n\t"							\
				"vmlal.u32 q10, d7, d8 \n\t"						\
				"vshr.u64 q4, q15, #32 \n\t"						\
				"vadd.u64 q8, q8, q4 \n\t"							\
				"vshr.u64 q4, q8, #32 \n\t"							\
				"vadd.u64 q9, q9, q4 \n\t"							\
				"vshr.u64 q4, q9, #32 \n\t"							\
				"vadd.u64 q10, q10, q4 \n\t"						\
				"vshr.u64 q4, q10, #32 \n\t"						\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q15, q15, q4 \n\t"							\
				"vand q8, q8, q4 \n\t"								\
				"vand q9, q9, q4 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vadd.u64 d22, d22, d31 \n\t"						\
				"vshr.u64 d8, d22, #32 \n\t"						\
				"vadd.u64 d17, d17, d8 \n\t"						\
				"vshr.u64 d8, d17, #32 \n\t"						\
				"vadd.u64 d19, d19, d8 \n\t"						\
				"vshr.u64 d8, d19, #32 \n\t"						\
				"vadd.u64 d21, d21, d8 \n\t"						\
				"vshr.u64 d8, d21, #32 \n\t"						\
				"vadd.u64 d23, d23, d8 \n\t"						\
				"vand d22, d22, d9 \n\t"							\
				"vand d17, d17, d9 \n\t"							\
				"vand d19, d19, d9 \n\t"							\
				"vand d21, d21, d9 \n\t"							\
				"vshl.u64 d30, #32 \n\t"							\
				"vadd.u64 d28, d28, d30 \n\t"						\
				"vst1.64 d28, [%0]! \n\t"
#define NEON_256_MUL_256_END										\
				"vld1.32 {d24, d25, d26, d27}, [%0] \n\t"			\
				"vswp d25, d26 \n\t"								\
				"vtrn.32 q12, q13 \n\t"								\
				"vshr.u64 q14, q12, #32 \n\t"						\
				"vshr.u64 q15, q13, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand.u64 q12, q12, q4 \n\t"						\
				"vand.u64 q13, q13, q4 \n\t"						\
				"vadd.u64 q8, q8, q12 \n\t"							\
				"vadd.u64 q9, q9, q13 \n\t"							\
				"vadd.u64 q10, q10, q14 \n\t"						\
				"vadd.u64 q11, q11, q15 \n\t"						\
				"vshr.u64 d8, d16, #32 \n\t"						\
				"vadd.u64 d18, d18, d16 \n\t"						\
				"vshr.u64 d8, d18, #32 \n\t"						\
				"vadd.u64 d20, d20, d8 \n\t"						\
				"vshr.u64 d8, d20, #32 \n\t"						\
				"vadd.u64 d22, d22, d20 \n\t"						\
				"vshr.u64 d8, d22, #32 \n\t"						\
				"vadd.u64 d17, d17, d8 \n\t"						\
				"vshr.u64 d8, d17, #32 \n\t"						\
				"vadd.u64 d19, d19, d8 \n\t"						\
				"vshr.u64 d8, d19, #32 \n\t"						\
				"vadd.u64 d21, d21, d8 \n\t"						\
				"vshr.u64 d8, d21, #32 \n\t"						\
				"vadd.u64 d23, d23, d8 \n\t"						\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vand q8, q8, q4 \n\t"								\
				"vand q9, q9, q4 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vshl.u64 q4, q10, #32 \n\t"						\
				"vadd.u64 q8, q8, q4 \n\t"							\
				"vshl.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q9, q9, q4 \n\t"							\
				"vtrn.32 q8, q9 \n\t"								\
				"vswp d17, d18 \n\t"								\
				"vst1.32 {d16, d17, d18, d19}, [%0] \n\t"			\
				:: "r"(r), "r"(a), "r"(b), "r"(c)					\
				: "q0", "q1", "q2", "q3", "q4", "q8", "q9", "q10",	\
				"q11", "q12", "q13", "q14", "q15", "memory"			\
				);

static void NEON_128_mul_256(const unsigned *a, const unsigned *b, unsigned *r)
{
	asm volatile (													\
				"vmov.u32 q8, #0 \n\t"								\
				"vmov.u32 q9, #0 \n\t"								\
				"vmov.u32 q10, #0 \n\t"								\
				"vmov.u32 q11, #0 \n\t"								\
				"vld1.32 {d0, d1}, [%1] \n\t"

				"vld4.32 {d4, d5, d6, d7}, [%2] \n\t"				\
				"vld1.32 {d16, d17}, [%0] \n\t"						\
				"vtrn.32 q8, q9 \n\t"								\
				"vswp d17, d20 \n\t"								\
				"vswp d19, d22 \n\t"								\
				"vdup.32 d8, d0[0] \n\t"							\
				"vmlal.u32 q8, d4, d8 \n\t"							\
				"vmlal.u32 q9, d5, d8 \n\t"							\
				"vmlal.u32 q10, d6, d8 \n\t"						\
				"vmlal.u32 q11, d7, d8 \n\t"						\
				"vshr.u64 q4, q8, #32 \n\t"							\
				"vadd.u64 q9, q9, q4 \n\t"							\
				"vshr.u64 q4, q9, #32 \n\t"							\
				"vadd.u64 q10, q10, q4 \n\t"						\
				"vshr.u64 q4, q10, #32 \n\t"						\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vshr.u64 q12, q11, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q8, q8, q4 \n\t"								\
				"vand q9, q9, q4 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vadd.u64 d24, d24, d17 \n\t"						\
				"vshr.u64 d8, d24, #32 \n\t"						\
				"vadd.u64 d19, d19, d8 \n\t"						\
				"vand d24, d24, d9 \n\t"							\

				"vdup.32 d8, d0[1] \n\t"							\
				"vmlal.u32 q9, d4, d8 \n\t"							\
				"vmlal.u32 q10, d5, d8 \n\t"						\
				"vmlal.u32 q11, d6, d8 \n\t"						\
				"vmlal.u32 q12, d7, d8 \n\t"						\
				"vshr.u64 q4, q9, #32 \n\t"							\
				"vadd.u64 q10, q10, q4 \n\t"						\
				"vshr.u64 q4, q10, #32 \n\t"						\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vshr.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vshr.u64 q13, q12, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q9, q9, q4 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vand q12, q12, q4 \n\t"							\
				"vadd.u64 d26, d26, d19 \n\t"						\
				"vshr.u64 d8, d26, #32 \n\t"						\
				"vadd.u64 d21, d21, d8 \n\t"						\
				"vand d26, d26, d9 \n\t"							\
				"vshl.u64 d18, #32 \n\t"							\
				"vadd.u64 d16, d16, d18 \n\t"						\
				"vst1.64 d16, [%0]! \n\t"							\
				"vdup.32 d8, d1[0] \n\t"							\
				"vmlal.u32 q10, d4, d8 \n\t"						\
				"vmlal.u32 q11, d5, d8 \n\t"						\
				"vmlal.u32 q12, d6, d8 \n\t"						\
				"vmlal.u32 q13, d7, d8 \n\t"						\
				"vshr.u64 q4, q10, #32 \n\t"						\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vshr.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vshr.u64 q4, q12, #32 \n\t"						\
				"vadd.u64 q13, q13, q4 \n\t"						\
				"vshr.u64 q14, q13, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vand q12, q12, q4 \n\t"							\
				"vand q13, q13, q4 \n\t"							\
				"vadd.u64 d28, d28, d21 \n\t"						\
				"vshr.u64 d8, d28, #32 \n\t"						\
				"vadd.u64 d23, d23, d8 \n\t"						\
				"vand d28, d28, d9 \n\t"							\
				"vdup.32 d8, d1[1] \n\t"							\
				"vmlal.u32 q11, d4, d8 \n\t"						\
				"vmlal.u32 q12, d5, d8 \n\t"						\
				"vmlal.u32 q13, d6, d8 \n\t"						\
				"vmlal.u32 q14, d7, d8 \n\t"						\
				"vshr.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vshr.u64 q4, q12, #32 \n\t"						\
				"vadd.u64 q13, q13, q4 \n\t"						\
				"vshr.u64 q4, q13, #32 \n\t"						\
				"vadd.u64 q14, q14, q4 \n\t"						\
				"vshr.u64 q15, q14, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q11, q11, q4 \n\t"							\
				"vand q12, q12, q4 \n\t"							\
				"vand q13, q13, q4 \n\t"							\
				"vand q14, q14, q4 \n\t"							\
				"vadd.u64 d30, d30, d23 \n\t"						\
				"vshr.u64 d8, d30, #32 \n\t"						\
				"vadd.u64 d25, d25, d8 \n\t"						\
				"vand d30, d30, d9 \n\t"							\
				"vshl.u64 d22, #32 \n\t"							\
				"vadd.u64 d20, d20, d22 \n\t"						\
				"vst1.64 d20, [%0]! \n\t"

				"vld1.32 {d16, d17, d18, d19}, [%0] \n\t"			\
				"vswp d17, d18 \n\t"								\
				"vtrn.32 q8, q9 \n\t"								\
				"vshr.u64 q10, q8, #32 \n\t"						\
				"vshr.u64 q11, q9, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand.u64 q8, q8, q4 \n\t"							\
				"vand.u64 q9, q9, q4 \n\t"							\
				"vadd.u64 q8, q8, q12 \n\t"							\
				"vadd.u64 q9, q9, q13 \n\t"							\
				"vadd.u64 q10, q10, q14 \n\t"						\
				"vadd.u64 q11, q11, q15 \n\t"						\
				"vshr.u64 d8, d16, #32 \n\t"						\
				"vadd.u64 d18, d18, d8 \n\t"						\
				"vshr.u64 d8, d18, #32 \n\t"						\
				"vadd.u64 d20, d20, d8 \n\t"						\
				"vshr.u64 d8, d20, #32 \n\t"						\
				"vadd.u64 d22, d22, d8 \n\t"						\
				"vshr.u64 d8, d22, #32 \n\t"						\
				"vadd.u64 d17, d17, d8 \n\t"						\
				"vshr.u64 d8, d17, #32 \n\t"						\
				"vadd.u64 d19, d19, d8 \n\t"						\
				"vshr.u64 d8, d19, #32 \n\t"						\
				"vadd.u64 d21, d21, d8 \n\t"						\
				"vshr.u64 d8, d21, #32 \n\t"						\
				"vadd.u64 d23, d23, d8 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q8, q8, q4 \n\t"								\
				"vand q9, q9, q4 \n\t"								\
				"vshl.u64 q10, q10, #32 \n\t"						\
				"vadd.u64 q8, q8, q10 \n\t"							\
				"vshl.u64 q11, q11, #32 \n\t"						\
				"vadd.u64 q9, q9, q11 \n\t"							\
				"vtrn.32 q8, q9 \n\t"								\
				"vswp d17, d18 \n\t"								\
				"vst1.32 {d16, d17, d18, d19}, [%0] \n\t"			\
				:: "r"(r), "r"(a), "r"(b)							\
				: "q0", "q1", "q2", "q3", "q4", "q8", "q9", "q10",	\
				"q11", "q12", "q13", "q14", "q15", "memory"			\
				);
}

#define NEON_256_MUL_128_START										\
	asm volatile (													\
				"vmov.u32 q8, #0 \n\t"								\
				"vmov.u32 q9, #0 \n\t"								\
				"vmov.u32 q10, #0 \n\t"								\
				"vmov.u32 q11, #0 \n\t"								\
				"vld1.32 {d0, d1}, [%1] \n\t"
#define NEON_256_MUL_128_CORE										\
				"vld4.32 {d4, d5, d6, d7}, [%2] \n\t"				\
				"vld1.32 {d16, d17}, [%0] \n\t"						\
				"vtrn.32 q8, q9 \n\t"								\
				"vswp d17, d20 \n\t"								\
				"vswp d19, d22 \n\t"								\
				"vdup.32 d8, d0[0] \n\t"							\
				"vmlal.u32 q8, d4, d8 \n\t"							\
				"vmlal.u32 q9, d5, d8 \n\t"							\
				"vmlal.u32 q10, d6, d8 \n\t"						\
				"vmlal.u32 q11, d7, d8 \n\t"						\
				"vshr.u64 q4, q8, #32 \n\t"							\
				"vadd.u64 q9, q9, q4 \n\t"							\
				"vshr.u64 q4, q9, #32 \n\t"							\
				"vadd.u64 q10, q10, q4 \n\t"						\
				"vshr.u64 q4, q10, #32 \n\t"						\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vshr.u64 q12, q11, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q8, q8, q4 \n\t"								\
				"vand q9, q9, q4 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vadd.u64 d24, d24, d17 \n\t"						\
				"vshr.u64 d8, d24, #32 \n\t"						\
				"vadd.u64 d19, d19, d8 \n\t"						\
				"vand d24, d24, d9 \n\t"							\
				"vdup.32 d8, d0[1] \n\t"							\
				"vmlal.u32 q9, d4, d8 \n\t"							\
				"vmlal.u32 q10, d5, d8 \n\t"						\
				"vmlal.u32 q11, d6, d8 \n\t"						\
				"vmlal.u32 q12, d7, d8 \n\t"						\
				"vshr.u64 q4, q9, #32 \n\t"							\
				"vadd.u64 q10, q10, q4 \n\t"						\
				"vshr.u64 q4, q10, #32 \n\t"						\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vshr.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vshr.u64 q13, q12, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q9, q9, q4 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vand q12, q12, q4 \n\t"							\
				"vadd.u64 d26, d26, d19 \n\t"						\
				"vshr.u64 d8, d26, #32 \n\t"						\
				"vadd.u64 d21, d21, d8 \n\t"						\
				"vand d26, d26, d9 \n\t"							\
				"vshl.u64 d18, #32 \n\t"							\
				"vadd.u64 d16, d16, d18 \n\t"						\
				"vst1.64 d16, [%0]! \n\t"							\
				"vdup.32 d8, d1[0] \n\t"							\
				"vmlal.u32 q10, d4, d8 \n\t"						\
				"vmlal.u32 q11, d5, d8 \n\t"						\
				"vmlal.u32 q12, d6, d8 \n\t"						\
				"vmlal.u32 q13, d7, d8 \n\t"						\
				"vshr.u64 q4, q10, #32 \n\t"						\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vshr.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vshr.u64 q4, q12, #32 \n\t"						\
				"vadd.u64 q13, q13, q4 \n\t"						\
				"vshr.u64 q14, q13, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vand q12, q12, q4 \n\t"							\
				"vand q13, q13, q4 \n\t"							\
				"vadd.u64 d28, d28, d21 \n\t"						\
				"vshr.u64 d8, d28, #32 \n\t"						\
				"vadd.u64 d23, d23, d8 \n\t"						\
				"vand d28, d28, d9 \n\t"							\
				"vdup.32 d8, d1[1] \n\t"							\
				"vmlal.u32 q11, d4, d8 \n\t"						\
				"vmlal.u32 q12, d5, d8 \n\t"						\
				"vmlal.u32 q13, d6, d8 \n\t"						\
				"vmlal.u32 q14, d7, d8 \n\t"						\
				"vshr.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vshr.u64 q4, q12, #32 \n\t"						\
				"vadd.u64 q13, q13, q4 \n\t"						\
				"vshr.u64 q4, q13, #32 \n\t"						\
				"vadd.u64 q14, q14, q4 \n\t"						\
				"vshr.u64 q15, q14, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q11, q11, q4 \n\t"							\
				"vand q12, q12, q4 \n\t"							\
				"vand q13, q13, q4 \n\t"							\
				"vand q14, q14, q4 \n\t"							\
				"vadd.u64 d30, d30, d23 \n\t"						\
				"vshr.u64 d8, d30, #32 \n\t"						\
				"vadd.u64 d25, d25, d8 \n\t"						\
				"vand d30, d30, d9 \n\t"							\
				"vshl.u64 d22, #32 \n\t"							\
				"vadd.u64 d20, d20, d22 \n\t"						\
				"vst1.64 d20, [%0]! \n\t"
#define NEON_128_MUL_256_END										\
				"vld1.32 {d16, d17, d18, d19}, [%0] \n\t"			\
				"vswp d17, d18 \n\t"								\
				"vtrn.32 q8, q9 \n\t"								\
				"vshr.u64 q10, q8, #32 \n\t"						\
				"vshr.u64 q11, q9, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand.u64 q8, q8, q4 \n\t"							\
				"vand.u64 q9, q9, q4 \n\t"							\
				"vadd.u64 q8, q8, q12 \n\t"							\
				"vadd.u64 q9, q9, q13 \n\t"							\
				"vadd.u64 q10, q10, q14 \n\t"						\
				"vadd.u64 q11, q11, q15 \n\t"						\
				"vshr.u64 d8, d16, #32 \n\t"						\
				"vadd.u64 d18, d18, d8 \n\t"						\
				"vshr.u64 d8, d18, #32 \n\t"						\
				"vadd.u64 d20, d20, d8 \n\t"						\
				"vshr.u64 d8, d20, #32 \n\t"						\
				"vadd.u64 d22, d22, d8 \n\t"						\
				"vshr.u64 d8, d22, #32 \n\t"						\
				"vadd.u64 d17, d17, d8 \n\t"						\
				"vshr.u64 d8, d17, #32 \n\t"						\
				"vadd.u64 d19, d19, d8 \n\t"						\
				"vshr.u64 d8, d19, #32 \n\t"						\
				"vadd.u64 d21, d21, d8 \n\t"						\
				"vshr.u64 d8, d21, #32 \n\t"						\
				"vadd.u64 d23, d23, d8 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q8, q8, q4 \n\t"								\
				"vand q9, q9, q4 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vshl.u64 q4, q10, #32 \n\t"						\
				"vadd.u64 q8, q8, q4 \n\t"							\
				"vshl.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q9, q9, q4 \n\t"							\
				"vtrn.32 q8, q9 \n\t"								\
				"vswp d17, d18 \n\t"								\
				"vst1.32 {d16, d17, d18, d19}, [%0] \n\t"			\
				:: "r"(r), "r"(a), "r"(b)							\
				: "q0", "q1", "q2", "q3", "q4", "q8", "q9", "q10",	\
				"q11", "q12", "q13", "q14", "q15", "memory"			\
				);

static void NEON_64_mul_256(const unsigned *a, const unsigned *b, unsigned *r)
{
	asm volatile (													\
				"vmov.u32 q10, #0 \n\t"								\
				"vmov.u32 q11, #0 \n\t"								\
				"vld1.32 {d0}, [%1] \n\t"

				"vld4.32 {d4, d5, d6, d7}, [%2]! \n\t"				\
				"vld1.32 {d20}, [%0] \n\t"							\
				"vtrn.32 q10, q11 \n\t"								\
				"vdup.32 d8, d0[0] \n\t"							\
				"vmlal.u32 q10, d4, d8 \n\t"						\
				"vmlal.u32 q11, d5, d8 \n\t"						\
				"vmull.u32 q12, d6, d8 \n\t"						\
				"vmull.u32 q13, d7, d8 \n\t"						\
				"vshr.u64 q4, q10, #32 \n\t"						\
				"vadd.u64 q11, q11, q4 \n\t"						\
				"vshr.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vshr.u64 q4, q12, #32 \n\t"						\
				"vadd.u64 q13, q13, q4 \n\t"						\
				"vshr.u64 q14, q13, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vand q12, q12, q4 \n\t"							\
				"vand q13, q13, q4 \n\t"							\
				"vadd.u64 d28, d28, d21 \n\t"						\
				"vshr.u64 d8, d28, #32 \n\t"						\
				"vadd.u64 d23, d23, d8 \n\t"						\
				"vand d28, d28, d9 \n\t"							\
				"vdup.32 d8, d0[1] \n\t"							\
				"vmlal.u32 q11, d4, d8 \n\t"						\
				"vmlal.u32 q12, d5, d8 \n\t"						\
				"vmlal.u32 q13, d6, d8 \n\t"						\
				"vmlal.u32 q14, d7, d8 \n\t"						\
				"vshr.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vshr.u64 q4, q12, #32 \n\t"						\
				"vadd.u64 q13, q13, q4 \n\t"						\
				"vshr.u64 q4, q13, #32 \n\t"						\
				"vadd.u64 q14, q14, q4 \n\t"						\
				"vshr.u64 q15, q14, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q11, q11, q4 \n\t"							\
				"vand q12, q12, q4 \n\t"							\
				"vand q13, q13, q4 \n\t"							\
				"vand q14, q14, q4 \n\t"							\
				"vadd.u64 d30, d30, d23 \n\t"						\
				"vshr.u64 d8, d30, #32 \n\t"						\
				"vadd.u64 d25, d25, d8 \n\t"						\
				"vand d30, d30, d9 \n\t"							\
				"vshl.u64 d22, #32 \n\t"							\
				"vadd.u64 d20, d20, d22 \n\t"						\
				"vst1.64 d20, [%0]! \n\t"							\

				"vld1.32 {d16, d17, d18, d19}, [%0] \n\t"			\
				"vswp d17, d18 \n\t"								\
				"vtrn.32 q8, q9 \n\t"								\
				"vshr.u64 q10, q8, #32 \n\t"						\
				"vshr.u64 q11, q9, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand.u64 q8, q8, q4 \n\t"							\
				"vand.u64 q9, q9, q4 \n\t"							\
				"vadd.u64 q8, q8, q12 \n\t"							\
				"vadd.u64 q9, q9, q13 \n\t"							\
				"vadd.u64 q10, q10, q14 \n\t"						\
				"vadd.u64 q11, q11, q15 \n\t"						\
				"vshr.u64 d8, d16, #32 \n\t"						\
				"vadd.u64 d18, d18, d8 \n\t"						\
				"vshr.u64 d8, d18, #32 \n\t"						\
				"vadd.u64 d20, d20, d8 \n\t"						\
				"vshr.u64 d8, d20, #32 \n\t"						\
				"vadd.u64 d22, d22, d8 \n\t"						\
				"vshr.u64 d8, d22, #32 \n\t"						\
				"vadd.u64 d17, d17, d8 \n\t"						\
				"vshr.u64 d8, d17, #32 \n\t"						\
				"vadd.u64 d19, d19, d8 \n\t"						\
				"vshr.u64 d8, d19, #32 \n\t"						\
				"vadd.u64 d21, d21, d8 \n\t"						\
				"vshr.u64 d8, d21, #32 \n\t"						\
				"vadd.u64 d23, d23, d8 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q8, q8, q4 \n\t"								\
				"vand q9, q9, q4 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vshl.u64 q4, q10, #32 \n\t"						\
				"vadd.u64 q8, q8, q4 \n\t"							\
				"vshl.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q9, q9, q4 \n\t"							\
				"vtrn.32 q8, q9 \n\t"								\
				"vswp d17, d18 \n\t"								\
				"vst1.32 {d16, d17, d18, d19}, [%0] \n\t"			\
				:: "r"(r), "r"(a), "r"(b)							\
				: "q0", "q1", "q2", "q3", "q4", "q8", "q9", "q10",	\
				"q11", "q12", "q13", "q14", "q15", "memory"			\
				);
}

static void NEON_32_mul_256(const unsigned *a, const unsigned *b, unsigned *r)
{
	asm volatile (													\
				"vmov.u32 q11, #0 \n\t"								\
				"vld1.32 d0[0], [%1] \n\t"

				"vld4.32 {d4, d5, d6, d7}, [%2]! \n\t"				\
				"vld1.32 d22[0], [%0] \n\t"							\
				"vdup.32 d8, d0[0] \n\t"							\
				"vmlal.u32 q11, d4, d8 \n\t"						\
				"vmull.u32 q12, d5, d8 \n\t"						\
				"vmull.u32 q13, d6, d8 \n\t"						\
				"vmull.u32 q14, d7, d8 \n\t"						\
				"vshr.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q12, q12, q4 \n\t"						\
				"vshr.u64 q4, q12, #32 \n\t"						\
				"vadd.u64 q13, q13, q4 \n\t"						\
				"vshr.u64 q4, q13, #32 \n\t"						\
				"vadd.u64 q14, q14, q4 \n\t"						\
				"vshr.u64 q15, q14, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q11, q11, q4 \n\t"							\
				"vand q12, q12, q4 \n\t"							\
				"vand q13, q13, q4 \n\t"							\
				"vand q14, q14, q4 \n\t"							\
				"vadd.u64 d30, d30, d23 \n\t"						\
				"vshr.u64 d8, d30, #32 \n\t"						\
				"vadd.u64 d25, d25, d8 \n\t"						\
				"vand d30, d30, d9 \n\t"							\
				"vmov.u32 r0, d22[0] \n\t"							\
				"str r0, [%0], #4  \n\t"

				"vld1.32 {d16, d17, d18, d19}, [%0] \n\t"			\
				"vswp d17, d18 \n\t"								\
				"vtrn.32 q8, q9 \n\t"								\
				"vshr.u64 q10, q8, #32 \n\t"						\
				"vshr.u64 q11, q9, #32 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand.u64 q8, q8, q4 \n\t"							\
				"vand.u64 q9, q9, q4 \n\t"							\
				"vadd.u64 q8, q8, q12 \n\t"							\
				"vadd.u64 q9, q9, q13 \n\t"							\
				"vadd.u64 q10, q10, q14 \n\t"						\
				"vadd.u64 q11, q11, q15 \n\t"						\
				"vshr.u64 d8, d16, #32 \n\t"						\
				"vadd.u64 d18, d18, d8 \n\t"						\
				"vshr.u64 d8, d18, #32 \n\t"						\
				"vadd.u64 d20, d20, d8 \n\t"						\
				"vshr.u64 d8, d20, #32 \n\t"						\
				"vadd.u64 d22, d22, d8 \n\t"						\
				"vshr.u64 d8, d22, #32 \n\t"						\
				"vadd.u64 d17, d17, d8 \n\t"						\
				"vshr.u64 d8, d17, #32 \n\t"						\
				"vadd.u64 d19, d19, d8 \n\t"						\
				"vshr.u64 d8, d19, #32 \n\t"						\
				"vadd.u64 d21, d21, d8 \n\t"						\
				"vshr.u64 d8, d21, #32 \n\t"						\
				"vadd.u64 d23, d23, d8 \n\t"						\
				"vmov.u32 q4, #0xffffffff \n\t"						\
				"vshr.u64 q4, #32 \n\t"								\
				"vand q8, q8, q4 \n\t"								\
				"vand q9, q9, q4 \n\t"								\
				"vand q10, q10, q4 \n\t"							\
				"vand q11, q11, q4 \n\t"							\
				"vshl.u64 q4, q10, #32 \n\t"						\
				"vadd.u64 q8, q8, q4 \n\t"							\
				"vshl.u64 q4, q11, #32 \n\t"						\
				"vadd.u64 q9, q9, q4 \n\t"							\
				"vtrn.32 q8, q9 \n\t"								\
				"vswp d17, d18 \n\t"								\
				"vst1.32 {d16, d17, d18, d19}, [%0] \n\t"			\
				:: "r"(r), "r"(a), "r"(b)							\
				: "q0", "q1", "q2", "q3", "q4", "q8", "q9", "q10",	\
				"q11", "q12", "q13", "q14", "q15", "memory"			\
				);
}

#define NEON_32_MUL_256_START										\
	asm volatile (													\
				"vmov.u32 q9, #0 \n\t"								\
				"vld1.32 d19[0], [%2] \n\t"							\
				"vdup.32 d19, d19[0] \n\t"							\
				"vld1.32 d18[0], [%3] \n\t"
#define NEON_32_MUL_256_CORE										\
				"vld1.32 {d0, d1, d2, d3}, [%0] \n\t"				\
				"vld4.32 {d20, d21, d22, d23}, [%1]! \n\t"			\
				"vswp d1, d2 \n\t"									\
				"vtrn.32 q0, q1 \n\t"								\
				"vshr.u64 q2, q0, #32 \n\t"							\
				"vshr.u64 q3, q1, #32 \n\t"							\
				"vmov.u32 q8, #0xffffffff \n\t"						\
				"vshr.u64 q8, #32 \n\t"								\
				"vand.u64 q0, q0, q8 \n\t"							\
				"vand.u64 q1, q1, q8 \n\t"							\
				"vadd.u64 d0, d0, d18 \n\t"							\
				"vmlal.u32 q0, d20, d19 \n\t"						\
				"vmlal.u32 q1, d21, d19 \n\t"						\
				"vmlal.u32 q2, d22, d19 \n\t"						\
				"vmlal.u32 q3, d23, d19 \n\t"						\
				"vshr.u64 d18, d0, #32 \n\t"						\
				"vadd.u64 d2, d2, d18 \n\t"							\
				"vshr.u64 d18, d2, #32 \n\t"						\
				"vadd.u64 d4, d4, d18 \n\t"							\
				"vshr.u64 d18, d4, #32 \n\t"						\
				"vadd.u64 d6, d6, d18 \n\t"							\
				"vshr.u64 d18, d6, #32 \n\t"						\
				"vadd.u64 d1, d1, d18 \n\t"							\
				"vshr.u64 d18, d1, #32 \n\t"						\
				"vadd.u64 d3, d3, d18 \n\t"							\
				"vshr.u64 d18, d3, #32 \n\t"						\
				"vadd.u64 d5, d5, d18 \n\t"							\
				"vshr.u64 d18, d5, #32 \n\t"						\
				"vadd.u64 d7, d7, d18 \n\t"							\
				"vand.u64 q0, q0, q8 \n\t"							\
				"vand.u64 q1, q1, q8 \n\t"							\
				"vshl.u64 q8, q2, #32 \n\t"							\
				"vadd.u64 q0, q0, q8 \n\t"							\
				"vshl.u64 q8, q3, #32 \n\t"							\
				"vadd.u64 q1, q1, q8 \n\t"							\
				"vtrn.32 q0, q1 \n\t"								\
				"vswp d1, d2 \n\t"									\
				"vshr.u64 d18, d7, #32 \n\t"						\
				"vst1.64 {d0, d1, d2, d3}, [%0]! \n\t"
#define NEON_32_MUL_256_END											\
				"vmov.u32 r0, d18[0] \n\t"							\
				"str r0, [%3] \n\t"									\
				:: "r"(r), "r"(a), "r"(b), "r"(c)					\
				: "q0", "q1", "q2", "q3", "q8", "q9",				\
				"q10", "q11", "memory"								\
				);

#define NEON_32_MUL_64_START										\
	asm volatile (													\
				"vmov.u32 q0, #0 \n\t"								\
				"vmov.u32 q1, #0 \n\t"								\
				"vmov.u32 q2, #0 \n\t"								\
				"vld1.32 d2[0], [%2] \n\t"							\
				"vdup.32 d2, d2[0] \n\t"							\
				"vld1.32 d3[0], [%3] \n\t"
#define NEON_32_MUL_64_CORE											\
				"vld1.32 d0, [%0] \n\t"								\
				"vtrn.32 d0, d1 \n\t"								\
				"vld1.32 d4, [%1]! \n\t"							\
				"vadd.u64 d0, d0, d3 \n\t"							\
				"vmlal.u32 q0, d2, d4 \n\t"							\
				"vshr.u64 d5, d0, #32 \n\t"							\
				"vadd.u64 d1, d1, d5 \n\t"							\
				"vmov.u32 r0, d1[0] \n\t"							\
				"vmov.u32 d0[1], r0 \n\t"							\
				"vshr.u64 d3, d1, #32 \n\t"							\
				"vst1.64 d0, [%0]! \n\t"
#define NEON_32_MUL_64_END											\
				"vmov.u32 r0, d3[0] \n\t"							\
				"str r0, [%3] \n\t"									\
				:: "r"(r), "r"(a), "r"(b), "r"(c)					\
				: "q0", "q1", "q2", "memory"						\
				);

#define NEON_32_MUL_32_START										\
	asm volatile (													\
				"vmov.u32 q0, #0 \n\t"								\
				"vmov.u32 q1, #0 \n\t"								\
				"vmov.u32 q2, #0 \n\t"								\
				"vld1.32 d2[0], [%2] \n\t"							\
				"vld1.32 d3[0], [%3] \n\t"
#define NEON_32_MUL_32_CORE											\
				"vld1.32 d0[0], [%0] \n\t"							\
				"vld1.32 d4[0], [%1]! \n\t"							\
				"vadd.u64 d0, d0, d3 \n\t"							\
				"vmlal.u32 q0, d2, d4 \n\t"							\
				"vmov.u32 r0, d0[0] \n\t"							\
				"str r0, [%0], #4 \n\t"								\
				"vshr.u64 d3, d0, #32 \n\t"
#define NEON_32_MUL_32_END											\
				"vmov.u32 r0, d3[0] \n\t"							\
				"str r0, [%3] \n\t"									\
				:: "r"(r), "r"(a), "r"(b), "r"(c)					\
				: "q0", "q1", "q2", "memory"						\
				);

static void neon_256_mul_256_hlp(int j, mbedtls_mpi_uint *a, mbedtls_mpi_uint *b, mbedtls_mpi_uint *r)
{
    mbedtls_mpi_uint c[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    NEON_256_MUL_256_START
    NEON_256_MUL_256_CORE   NEON_256_MUL_256_CORE
    NEON_256_MUL_256_CORE   NEON_256_MUL_256_CORE
    NEON_256_MUL_256_CORE   NEON_256_MUL_256_CORE
    NEON_256_MUL_256_CORE   NEON_256_MUL_256_CORE
    NEON_256_MUL_256_END
}

static void neon_256_mul_256_help(mbedtls_mpi_uint *a, mbedtls_mpi_uint *b, mbedtls_mpi_uint *r)
{
    mbedtls_mpi_uint c[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    NEON_256_MUL_256_START
    NEON_256_MUL_256_CORE
    NEON_256_MUL_256_END
}

static void neon_mul_hlp(int i, mbedtls_mpi_uint *r, mbedtls_mpi_uint *a, mbedtls_mpi_uint *b)
{
    mbedtls_mpi_uint c[1] = {0};
    for( ; i >= 128; i -= 128 )
    {
        NEON_32_MUL_256_START
        NEON_32_MUL_256_CORE   NEON_32_MUL_256_CORE
        NEON_32_MUL_256_CORE   NEON_32_MUL_256_CORE
        NEON_32_MUL_256_CORE   NEON_32_MUL_256_CORE
        NEON_32_MUL_256_CORE   NEON_32_MUL_256_CORE
        NEON_32_MUL_256_CORE   NEON_32_MUL_256_CORE
        NEON_32_MUL_256_CORE   NEON_32_MUL_256_CORE
        NEON_32_MUL_256_CORE   NEON_32_MUL_256_CORE
        NEON_32_MUL_256_CORE   NEON_32_MUL_256_CORE
        NEON_32_MUL_256_END LOG_ERR("run to 128 ...");
    }
    for( ; i >= 64; i -= 64 )
    {
        NEON_32_MUL_256_START
        NEON_32_MUL_256_CORE   NEON_32_MUL_256_CORE
        NEON_32_MUL_256_CORE   NEON_32_MUL_256_CORE
        NEON_32_MUL_256_CORE   NEON_32_MUL_256_CORE
        NEON_32_MUL_256_CORE   NEON_32_MUL_256_CORE
        NEON_32_MUL_256_END
    }
    for( ; i >= 32; i -= 32 )
    {
        NEON_32_MUL_256_START
        NEON_32_MUL_256_CORE   NEON_32_MUL_256_CORE
        NEON_32_MUL_256_CORE   NEON_32_MUL_256_CORE
        NEON_32_MUL_256_END
    }
    for( ; i >= 16; i -= 16 )
    {
        NEON_32_MUL_256_START
        NEON_32_MUL_256_CORE   NEON_32_MUL_256_CORE
        NEON_32_MUL_256_END
    }
    for( ; i >= 8; i -= 8 )
    {
        NEON_32_MUL_256_START
        NEON_32_MUL_256_CORE
        NEON_32_MUL_256_END LOG_ERR("run to 8 ...");
    }
    for( ; i >= 2; i -= 2 )
    {
        NEON_32_MUL_64_START
        NEON_32_MUL_64_CORE
        NEON_32_MUL_64_END LOG_ERR("run to 2 ...");
    }
    for( ; i > 0; i-- )
    {
        NEON_32_MUL_32_START
        NEON_32_MUL_32_CORE
        NEON_32_MUL_32_END LOG_ERR("run to 1 ...");
    }

    do {
        *r += *c; *c = ( *r < *c ); r++;
    }
    while( *c != 0 );
}

static ut_int32_t rsa_gen_key(
		gk_context_t *ctx_na, 
		ut_int32_t bit,
		ut_int32_t exponent,
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
	mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "what_is_this_string :)";
	struct timeval tv1, tv2;
	ut_int32_t i, j, k, tmptime;
	mbedtls_mpi A, B, X;
	mbedtls_mpi_init(&A);
	mbedtls_mpi_init(&B);
	mbedtls_mpi_init(&X);
	char *s0 =
		"e794375241f7ca2a08fc8f846f984ea85ca59eb82d43434328b4bbc7de3d7e6e" \
		"bfebcdd34252cd468fb7c6fe5df41931272761f2575e4aa49de892029f0a80d2" \
		"aab89e5ddde17e1f1129136e800f547f3335c10af8d50b3f806d1142b874d42f" \
		"85eac988a00a511d02935cffed7f859f2477097f5f0c2fb644d078b66af4672e" \
		"0e4c515e4fa212818f80875b692ee7cf15236c13b7ba6412234bcc26d60e1c7c" \
		"f28042b78c7255e621052ae1d38df90821309c3bdfea5eaa682747f87ec99540" \
		"a2380d959717f6a1e634f4af4765b3d811927b2d1c6156cb0687d30ccd8902e2" \
		"35575f4294534a74d45923b7d273607b2a8d609a8d239748a6b370ecf1f210a5";
	char *s1 =
		"c12c35e97bf5c2c1c5b547d265745b48bddfb9c2509f67204278609b9c9b1738" \
		"3307f42d6189c88a2fa0517225d5549e57d6d6315d07dea3eac4f1e715dba112" \
		"1a2ede8bd6661edab369dc37b4c314ecf63ec4c4ee44689993fb67068cef8780" \
		"0ce9892b5ab4c06cbe954662862e75bc06a2f55d365fe7fcd6f23f7f8b404c3f" \
		"dc9be08225ae0aeadc2a6d20340702b97613232d30bb7729fdd567d8c204b6dd" \
		"e18a75d0994c75cc05ef1a629d7be8b2126c07975dddc65f96245e48e2eae3bb" \
		"134ac209fb1687c226cfdfc9b1993fee5efab83a2f2e7295e63e994bc0959f9b" \
		"c653e3a396ebf7e5cbac4f713f73c7e7e3189c23bb29745f08f9693c2fd4c711";
	mbedtls_mpi_read_string( &A, 16, s0 );

	mbedtls_mpi_read_string( &B, 16, s1 );

	for( i = A.n; i > 0; i-- )
		if( A.p[i - 1] != 0 )
			break;

	for( j = B.n; j > 0; j-- )
		if( B.p[j - 1] != 0 )
			break;

	mbedtls_mpi_grow( &X, i + j );
	mbedtls_mpi_lset( &X, 0 );

	gettimeofday(&tv1, 0);
for( k = 0; k < 1024000; k++)
{
	for ( i = 0, j = A.n ; i < B.n; i++ )
		neon_mul_hlp(j, X.p + i, A.p, B.p + i);
}

	mbedtls_mpi_lset( &X, 0 );
	for ( i = 0, j = A.n ; i < B.n; i++ )
		neon_mul_hlp(j, X.p + i, A.p, B.p + i);
	gettimeofday(&tv2, 0);
	tmptime = ( tv2.tv_sec - tv1.tv_sec ) * 1000 + ( tv2.tv_usec - tv1.tv_usec ) / 1000;
	LOG_ERR("neon_mul_hlp usetime: %d ms\n", tmptime);

	for( i = 0; i < X.n; i += 8)
	{
		LOG_ERR("X->p[00 - 07] = %x, %x, %x, %x, %x, %x, %x, %x\n",
		X.p[i + 0], X.p[i + 1], X.p[i + 2], X.p[i + 3], X.p[i + 4], X.p[i + 5], X.p[i + 6], X.p[i + 7]);
	}
#if 0
	mbedtls_mpi_lset( &X, 0 );
	gettimeofday(&tv1, 0);

/*	NEON_256_mul_256(A.p, B.p, X.p);*/
/*	NEON_128_mul_256(A.p + 8, B.p, X.p + 8);*/
/*	NEON_64_mul_256(A.p + 12, B.p, X.p + 12);*/
/*	NEON_32_mul_256(A.p + 14, B.p, X.p + 14);*/

	gettimeofday(&tv2, 0);
	tmptime = ( tv2.tv_sec - tv1.tv_sec ) * 1000 + ( tv2.tv_usec - tv1.tv_usec ) / 1000;
	LOG_ERR("NEON_128_mul_256 usetime: %d ms\n", tmptime);

	for( i = 0; i < X.n; i += 8)
	{
		LOG_ERR("X->p[00 - 07] = %x, %x, %x, %x, %x, %x, %x, %x\n",
		X.p[i + 0], X.p[i + 1], X.p[i + 2], X.p[i + 3], X.p[i + 4], X.p[i + 5], X.p[i + 6], X.p[i + 7]);
	}

	gettimeofday(&tv1, 0);

for( k = 0; k < 1024000; k++)
{
	NEON_256_mul_256(A.p, B.p, X.p);
}
	gettimeofday(&tv2, 0);
	tmptime = ( tv2.tv_sec - tv1.tv_sec ) * 1000 + ( tv2.tv_usec - tv1.tv_usec ) / 1000;
	LOG_ERR("NEON_256_mul_256 usetime: %d ms\n", tmptime);

	for( i = 0; i < X.n; i += 8)
	{
		LOG_ERR("X->p[00 - 07] = %x, %x, %x, %x, %x, %x, %x, %x\n",
		X.p[i + 0], X.p[i + 1], X.p[i + 2], X.p[i + 3], X.p[i + 4], X.p[i + 5], X.p[i + 6], X.p[i + 7]);
	}

	gettimeofday(&tv1, 0);

for( k = 0; k < 1024000; k++)
{
	neon_256_mul_256_help(A.p, B.p, X.p);
}
	gettimeofday(&tv2, 0);
	tmptime = ( tv2.tv_sec - tv1.tv_sec ) * 1000 + ( tv2.tv_usec - tv1.tv_usec ) / 1000;
	LOG_ERR("NEON_256_mul_256_help usetime: %d ms\n", tmptime);

	for( i = 0; i < X.n; i += 8)
	{
		LOG_ERR("X->p[00 - 07] = %x, %x, %x, %x, %x, %x, %x, %x\n",
		X.p[i + 0], X.p[i + 1], X.p[i + 2], X.p[i + 3], X.p[i + 4], X.p[i + 5], X.p[i + 6], X.p[i + 7]);
	}
#endif

	mbedtls_mpi_lset( &X, 0 );
	gettimeofday(&tv1, 0);
for( k = 0; k < 1024000; k++)
{
	neon_256_mul_256_hlp(i, A.p, B.p, X.p);
	neon_256_mul_256_hlp(i, A.p, B.p + 8, X.p + 8);
	neon_256_mul_256_hlp(i, A.p, B.p + 16, X.p + 16);
	neon_256_mul_256_hlp(i, A.p, B.p + 24, X.p + 24);
	neon_256_mul_256_hlp(i, A.p, B.p + 32, X.p + 32);
	neon_256_mul_256_hlp(i, A.p, B.p + 40, X.p + 40);
	neon_256_mul_256_hlp(i, A.p, B.p + 48, X.p + 48);
	neon_256_mul_256_hlp(i, A.p, B.p + 56, X.p + 56);
}
	mbedtls_mpi_lset( &X, 0 );
	neon_256_mul_256_hlp(i, A.p, B.p, X.p);
	neon_256_mul_256_hlp(i, A.p, B.p + 8, X.p + 8);
	neon_256_mul_256_hlp(i, A.p, B.p + 16, X.p + 16);
	neon_256_mul_256_hlp(i, A.p, B.p + 24, X.p + 24);
	neon_256_mul_256_hlp(i, A.p, B.p + 32, X.p + 32);
	neon_256_mul_256_hlp(i, A.p, B.p + 40, X.p + 40);
	neon_256_mul_256_hlp(i, A.p, B.p + 48, X.p + 48);
	neon_256_mul_256_hlp(i, A.p, B.p + 56, X.p + 56);
	gettimeofday(&tv2, 0);
	tmptime = ( tv2.tv_sec - tv1.tv_sec ) * 1000 + ( tv2.tv_usec - tv1.tv_usec ) / 1000;
	LOG_ERR("neon_256_mul_256_hlp usetime: %d ms\n", tmptime);

	for( i = 0; i < X.n; i += 8)
	{
		LOG_ERR("X->p[00 - 07] = %x, %x, %x, %x, %x, %x, %x, %x\n",
		X.p[i + 0], X.p[i + 1], X.p[i + 2], X.p[i + 3], X.p[i + 4], X.p[i + 5], X.p[i + 6], X.p[i + 7]);
	}


	mbedtls_mpi_lset( &X, 0 );
	gettimeofday(&tv1, 0);
for( k = 0; k < 1024000; k++ )
{
	mbedtls_mpi_mul_mpi( &X, &A, &B);
}
	mbedtls_mpi_mul_mpi( &X, &A, &B);
	gettimeofday(&tv2, 0);
	tmptime = ( tv2.tv_sec - tv1.tv_sec ) * 1000 + ( tv2.tv_usec - tv1.tv_usec ) / 1000;
	LOG_ERR("mbedtls_mpi_mul_mpi usetime: %d ms\n", tmptime);

	for( i = 0; i < X.n; i += 8)
	{
		LOG_ERR("X->p[00 - 07] = %x, %x, %x, %x, %x, %x, %x, %x\n",
		X.p[i + 0], X.p[i + 1], X.p[i + 2], X.p[i + 3], X.p[i + 4], X.p[i + 5], X.p[i + 6], X.p[i + 7]);
	}

/*	for( i = 0; i < X.n; i += 8)*/
/*	{*/
/*		LOG_ERR("X->p[00 - 07] = %x, %x, %x, %x, %x, %x, %x, %x\n",*/
/*		X.p[i + 0], X.p[i + 1], X.p[i + 2], X.p[i + 3], X.p[i + 4], X.p[i + 5], X.p[i + 6], X.p[i + 7]);*/
/*	}*/
#if 0
#ifdef PERF_TEST
	size_t starttime =0; 
	size_t endtime =0; 
	starttime=get_tick_count();
#endif	
	((void)ctx_na);
	if(__e==NULL || __elen==0)return -UTPFCP_ERR_INVALID_PARAMS;
	if(__n==NULL || __nlen==0)return -UTPFCP_ERR_INVALID_PARAMS;
	if(__d==NULL || __dlen==0)return -UTPFCP_ERR_INVALID_PARAMS;
	if(__p==NULL || __plen==0)return -UTPFCP_ERR_INVALID_PARAMS;
	if(__q==NULL || __qlen==0)return -UTPFCP_ERR_INVALID_PARAMS;
	if(_dp==NULL || _dplen==0)return -UTPFCP_ERR_INVALID_PARAMS;
	if(_dq==NULL || _dqlen==0)return -UTPFCP_ERR_INVALID_PARAMS;
	if(_qp==NULL || _qplen==0)return -UTPFCP_ERR_INVALID_PARAMS;

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    MBEDRET(UTPFCP_ERR_RNG_SEED, mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *) pers, strlen( pers ) )) ;
								
	mbedtls_rsa_init( &ctx, 0, 0 );
	
	MBEDRET(UTPFCP_ERR_RSA,mbedtls_rsa_gen_key( &ctx, mbedtls_ctr_drbg_random, &ctr_drbg, bit, exponent ) );
	
	MBEDRET(UTPFCP_ERR_MPI, write_mpi( &ctx.N, __n, __nlen ) );
	MBEDRET(UTPFCP_ERR_MPI, write_mpi( &ctx.E, __e, __elen ) );
	MBEDRET(UTPFCP_ERR_MPI, write_mpi( &ctx.P, __p, __plen ) ); 
	MBEDRET(UTPFCP_ERR_MPI, write_mpi( &ctx.Q, __q, __qlen ) ); 
	MBEDRET(UTPFCP_ERR_MPI, write_mpi( &ctx.DP, _dp, _dplen ) ); 
	MBEDRET(UTPFCP_ERR_MPI, write_mpi( &ctx.DQ, _dq, _dqlen ) ); 
	MBEDRET(UTPFCP_ERR_MPI, write_mpi( &ctx.QP, _qp, _qplen ) );
	MBEDRET(UTPFCP_ERR_MPI, write_mpi( &ctx.D, __d, __dlen ) );
#ifdef PERF_TEST
	endtime = get_tick_count();
	ut_sys_log("rsa key starttime  %u   \n",starttime);
	ut_sys_log("rsa key endtime  %u   \n",endtime);
	ut_sys_log("rsa key gen time take %u   \n", endtime-starttime);
#endif
#endif
/*end:*/
/*	mbedtls_rsa_free(&ctx);*/
/*	mbedtls_ctr_drbg_free(&ctr_drbg);*/
/*	mbedtls_entropy_free(&entropy);*/
	return r;
}

static ut_int32_t ecc_gen_key(
		gk_context_t *ctx,  ut_int32_t action,
		ut_uint8_t *__x, ut_uint32_t *__xlen,
		ut_uint8_t *__y, ut_uint32_t *__ylen,
		ut_uint8_t *__k, ut_uint32_t *__klen)
{
	ut_int32_t r = 0;

	psEccSet_t *ecc_set = NULL;
	psEccKey_t *ecc_key = NULL;

	switch( action ) {
	case UT_PF_CP_ACT_GK_ECC_SEP192R1:
		{ getEccParamByName("ECC-192", &ecc_set ); } break; /* secp192r1 */
	case UT_PF_CP_ACT_GK_ECC_SEP224R1:
		{ getEccParamByName("ECC-224", &ecc_set ); } break; /* secp224r1 */
	case UT_PF_CP_ACT_GK_ECC_SEP256R1:
		{ getEccParamByName("ECC-256", &ecc_set ); } break; /* secp256r1 */
	case UT_PF_CP_ACT_GK_ECC_SEP384R1:
		{ getEccParamByName("ECC-384", &ecc_set ); } break; /* secp384r1 */
	case UT_PF_CP_ACT_GK_ECC_SEP521R1:
		{ getEccParamByName("ECC-521", &ecc_set ); } break; /* secp521r1 */
	case UT_PF_CP_ACT_GK_ECC_BRAINPOOL224R1:
		{ getEccParamByName("BP-224", &ecc_set ); } break; 
	case UT_PF_CP_ACT_GK_ECC_BRAINPOOL256R1:
		{ getEccParamByName("BP-256", &ecc_set ); } break; 
	case UT_PF_CP_ACT_GK_ECC_BRAINPOOL384R1:
		{ getEccParamByName("BP-384", &ecc_set ); } break; 
	case UT_PF_CP_ACT_GK_ECC_BRAINPOOL512R1:
		{ getEccParamByName("BP-512", &ecc_set ); } break; 

	///////////////////////////////////////////////////////////////////////
	case UT_PF_CP_ACT_GK_ECC_SEP160K1:
	case UT_PF_CP_ACT_GK_ECC_SEP160R1:
	case UT_PF_CP_ACT_GK_ECC_SEP160R2:
	case UT_PF_CP_ACT_GK_ECC_SEP192K1:
	case UT_PF_CP_ACT_GK_ECC_SEP224K1:
	case UT_PF_CP_ACT_GK_ECC_SEP256K1:
	default:				return -1;
	}

	r = psEccMakeKeyEx(NULL, &ecc_key, ecc_set, NULL);
	if ( r < 0 ) { return  r; }

	if (__x != NULL && __xlen != NULL) {
		*__xlen = pstm_unsigned_bin_size(&ecc_key->pubkey.x);
		pstm_to_unsigned_bin(NULL, &ecc_key->pubkey.x, __x);
	}
	if (__y != NULL && __ylen != NULL) {
		*__ylen = pstm_unsigned_bin_size(&ecc_key->pubkey.y);
		pstm_to_unsigned_bin(NULL, &ecc_key->pubkey.y, __y);
	}
	if (__k != NULL && __klen != NULL) {
		*__klen = pstm_unsigned_bin_size(&ecc_key->k);
		pstm_to_unsigned_bin(NULL, &ecc_key->k, __k);
	}

	psEccFreeKey(&ecc_key);
	return r;
}

static ut_int32_t sm2_gen_key(
		gk_context_t *ctx,  ut_int32_t action,
		ut_uint8_t *__x, ut_uint32_t *__xlen,
		ut_uint8_t *__y, ut_uint32_t *__ylen,
		ut_uint8_t *__k, ut_uint32_t *__klen)
{
	ut_int32_t r = 0;

	psEccSet_t *ecc_set = NULL;
	psEccKey_t *ecc_key = NULL;

	switch( action ) {
	case UT_PF_CP_ACT_GK_SM2_SEP192R1:
		{ getEccParamByName("ECC-192", &ecc_set ); } break; /* secp192r1 */
	case UT_PF_CP_ACT_GK_SM2_SEP224R1:
		{ getEccParamByName("ECC-224", &ecc_set ); } break; /* secp224r1 */
	case UT_PF_CP_ACT_GK_SM2_SEP256R1:
		{ getEccParamByName("ECC-256", &ecc_set ); } break; /* secp256r1 */
	case UT_PF_CP_ACT_GK_SM2_SEP384R1:
		{ getEccParamByName("ECC-384", &ecc_set ); } break; /* secp384r1 */
	case UT_PF_CP_ACT_GK_SM2_SEP521R1:
		{ getEccParamByName("ECC-521", &ecc_set ); } break; /* secp521r1 */
	///////////////////////////////////////////////////////////////////////
	case UT_PF_CP_ACT_GK_SM2_SEP160K1:
	case UT_PF_CP_ACT_GK_SM2_SEP160R1:
	case UT_PF_CP_ACT_GK_SM2_SEP160R2:
	case UT_PF_CP_ACT_GK_SM2_SEP192K1:
	case UT_PF_CP_ACT_GK_SM2_SEP224K1:
	case UT_PF_CP_ACT_GK_SM2_SEP256K1:
	default:				return -1;
	}

	r = psEccMakeKeyEx(NULL, &ecc_key, ecc_set, NULL);
	if ( r < 0 ) { return  r; }

	if (__x != NULL && __xlen != NULL) {
		*__xlen = pstm_unsigned_bin_size(&ecc_key->pubkey.x);
		pstm_to_unsigned_bin(NULL, &ecc_key->pubkey.x, __x);
	}
	if (__y != NULL && __ylen != NULL) {
		*__ylen = pstm_unsigned_bin_size(&ecc_key->pubkey.y);
		pstm_to_unsigned_bin(NULL, &ecc_key->pubkey.y, __y);
	}
	if (__k != NULL && __klen != NULL) {
		*__klen = pstm_unsigned_bin_size(&ecc_key->k);
		pstm_to_unsigned_bin(NULL, &ecc_key->k, __k);
	}

	psEccFreeKey(&ecc_key);
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
		case UT_PF_CP_ACT_AC_ECDH_BP224R1_SHARE_KEY						  :
		case UT_PF_CP_ACT_AC_ECDH_BP256R1_SHARE_KEY						  :
		case UT_PF_CP_ACT_AC_ECDH_BP384R1_SHARE_KEY						  :
		case UT_PF_CP_ACT_AC_ECDH_BP512R1_SHARE_KEY						  :
												break;
		default: 	   							return -1;
		}										break;
	case UT_PF_CP_CLS_GK:
		switch( act ) {
		case UT_PF_CP_ACT_GK_RSA										  :
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

	(*ctx)->class 	= cls;
	(*ctx)->action 	= act;
	(*ctx)->state	= 0x0;
	(*ctx)->use_hwc	= 0x0;	// no use

	if ( use_hwc(act) ) {
		r = ut_pf_cp_hwc_open(&((*ctx)->cipher.hwc), cls, act);
		if ( r < 0 )	return r;
		(*ctx)->use_hwc	= 0x01;
	}

	return r;
}

ut_int32_t ut_pf_cp_md_starts(
		ut_pf_cp_context_t *ctx)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->class != UT_PF_CP_CLS_MD ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_md_starts(ctx->cipher.hwc);
		break;
	case 0x00:
		r = md_starts(&ctx->cipher.md, ctx->action);
		break;
	}

	if ( r < 0 ) { return -2; }

	ctx->state = 0x01;	/* start */
	return r;
}

ut_int32_t ut_pf_cp_md_update(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *src, ut_uint32_t srclen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->state != 0x01 ||
		 ctx->class != UT_PF_CP_CLS_MD ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_md_update(ctx->cipher.hwc, src, srclen);
		break;
	case 0x00:
		r = md_update(&ctx->cipher.md, ctx->action, src, srclen);
		break;
	}

	if ( r < 0 ) { return -2; }

	return r;
}

ut_int32_t ut_pf_cp_md_finish(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->state != 0x01 ||
		 ctx->class != UT_PF_CP_CLS_MD ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_md_finish(ctx->cipher.hwc,
				dst, dstlen);
		break;
	case 0x00:
		r = md_finish(&ctx->cipher.md, ctx->action,
				dst, dstlen);
		break;
	}

	if ( r < 0 ) { return -2; }

	ctx->state = 0x00;	/* finish */
	return r;
}

////////////////////////////////////////////////////////////////////////
ut_int32_t ut_pf_cp_sc_starts(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *key, ut_uint32_t keylen,
		ut_uint8_t *vec, ut_uint32_t veclen, ut_int32_t enc)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->class != UT_PF_CP_CLS_SC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_sc_starts(ctx->cipher.hwc,
				key, keylen, vec, veclen, enc);
		break;
	case 0x00:
		r = sc_starts(&ctx->cipher.sc, ctx->action,
				key, keylen, vec, veclen, enc);
		break;
	}

	if ( r < 0 ) { return r; }

	ctx->state = 0x01;	/* start */
	return r;
}

ut_int32_t ut_pf_cp_sc_update(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *src, ut_uint32_t srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->state != 0x01 ||
		 ctx->class != UT_PF_CP_CLS_SC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_sc_update(ctx->cipher.hwc,
				src, srclen, dst, dstlen);
		break;
	case 0x00:
		r = sc_update(&ctx->cipher.sc, ctx->action,
				src, srclen, dst, dstlen);
		break;
	}

	if ( r < 0 ) { return r; }

	return r;
}

ut_int32_t ut_pf_cp_sc_finish(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *src, ut_uint32_t srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->state != 0x01 ||
		 ctx->class != UT_PF_CP_CLS_SC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_sc_finish(ctx->cipher.hwc,
				src, srclen, dst, dstlen);
		break;
	case 0x00:
		r = sc_finish(&ctx->cipher.sc, ctx->action,
				src, srclen, dst, dstlen);
		break;
	}

	if ( r < 0 ) { return r; }

	ctx->state = 0x00;	/* finish */
	return r;
}

ut_int32_t ut_pf_cp_mc_starts(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *key, ut_uint32_t keylen,
		ut_uint8_t *vec, ut_uint32_t veclen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->class != UT_PF_CP_CLS_MC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_mc_starts(ctx->cipher.hwc,
				key, keylen, vec, veclen);
		break;
	case 0x00:
		r = mc_starts(&ctx->cipher.mc, ctx->action,
				key, keylen, vec, veclen);
		break;
	}

	if ( r < 0 ) { return -2; }

	ctx->state = 0x01;	/* start */
	return r;
}

ut_int32_t ut_pf_cp_mc_update(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *src, ut_uint32_t srclen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->state != 0x01 ||
		 ctx->class != UT_PF_CP_CLS_MC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_mc_update(ctx->cipher.hwc,
				src, srclen);
		break;
	case 0x00:
		r = mc_update(&ctx->cipher.mc, ctx->action,
				src, srclen);
		break;
	}

	if ( r < 0 ) { return -2; }

	return r;
}

ut_int32_t ut_pf_cp_mc_finish(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->state != 0x01 ||
		 ctx->class != UT_PF_CP_CLS_MC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_mc_finish(ctx->cipher.hwc,
				dst, dstlen);
		break;
	case 0x00:
		r = mc_finish(&ctx->cipher.mc, ctx->action,
				dst, dstlen);
		break;
	}

	if ( r < 0 ) { return -2; }

	ctx->state = 0x00;	/* finish */
	return r;
}

ut_int32_t ut_pf_cp_ae_starts(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *key, ut_uint32_t keylen,
		ut_uint8_t *vec, ut_uint32_t veclen, ut_int32_t enc,
		ut_uint32_t taglen, ut_uint32_t addlen, ut_uint32_t paylen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->class != UT_PF_CP_CLS_AE ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_ae_starts(ctx->cipher.hwc,
				key, keylen, vec, veclen, enc, taglen, addlen, paylen);
		break;
	case 0x00:
		ctx->cipher.ae.enc = enc;
		r = ae_starts(&ctx->cipher.ae, ctx->action,
				key, keylen, vec, veclen, taglen, addlen, paylen);
		break;
	}

	if ( r < 0 ) { return -2; }

	ctx->state = 0x01;	/* start */
	return r;
}

ut_int32_t ut_pf_cp_ae_updadd(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *add, ut_uint32_t addlen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->state != 0x01 ||
		 ctx->class != UT_PF_CP_CLS_AE ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_ae_updadd(ctx->cipher.hwc,
				add, addlen);
		break;
	case 0x00:
		r = ae_updadd(&ctx->cipher.ae, ctx->action,
				add, addlen);
		break;
	}

	if ( r < 0 ) { return -2; }

	return r;
}

ut_int32_t ut_pf_cp_ae_update(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *src, ut_uint32_t srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->state != 0x01 ||
		 ctx->class != UT_PF_CP_CLS_AE ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_ae_update(ctx->cipher.hwc,
				src, srclen, dst, dstlen);
		break;
	case 0x00:
		r = ae_update(&ctx->cipher.ae, ctx->action,
				src, srclen, dst, dstlen, ctx->cipher.ae.enc);
		break;
	}

	if ( r < 0 ) { return -2; }

	return r;
}

ut_int32_t ut_pf_cp_ae_finish(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *src, ut_uint32_t srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen,
		ut_uint8_t *tag, ut_uint32_t *taglen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->state != 0x01 ||
		 ctx->class != UT_PF_CP_CLS_AE ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_ae_finish(ctx->cipher.hwc,
				src, srclen, dst, dstlen, tag, taglen);
		break;
	case 0x00:
		r = ae_finish(&ctx->cipher.ae, ctx->action,
				src, srclen, dst, dstlen, tag, taglen, ctx->cipher.ae.enc);
		break;
	}

	if ( r < 0 ) { return -2; }

	ctx->state = 0x00;	/* finish */
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
		 ctx->class != UT_PF_CP_CLS_AC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_ac_rsaenc(ctx->cipher.hwc,
				__n, __nlen, __e, __elen,
				sal, sallen, src, srclen, dst, dstlen);
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
		 ctx->class != UT_PF_CP_CLS_AC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_ac_rsadec(ctx->cipher.hwc,
				__n, __nlen, __d, __dlen, __e, __elen,
				sal, sallen, src, srclen, dst, dstlen);
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

	if ( ctx == NULL ||
		 ctx->class != UT_PF_CP_CLS_AC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_ac_rsadec_crt(ctx->cipher.hwc,
				__n, __nlen, __p, __plen, __q, __qlen,
				_dp, _dplen, _dq, _dqlen, _qp, _qplen,
				sal, sallen, src, srclen, dst, dstlen);
		break;
	case 0x00:
		r = import_rsa_pri_key(&ctx->cipher.ac,
				__n, __nlen, 0, 0, __e, __elen,
				__p, __plen, __q, __qlen,
				_dp, _dplen, _dq, _dqlen, _qp, _qplen);
		if ( r < 0 ) break;

		r = rsa_decrypt(&ctx->cipher.ac, ctx->action,
				sal, sallen, src, srclen, dst, dstlen);
		rsa_rel_key(&ctx->cipher.ac);
		break;
	}

	if ( r < 0 ) { return r; }

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
		 ctx->class != UT_PF_CP_CLS_AC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_ac_rsasig(ctx->cipher.hwc,
				__n, __nlen, __d, __dlen, __e, __elen,
				sal, sallen, has, haslen, sig, siglen);
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

	if ( ctx == NULL ||
		 ctx->class != UT_PF_CP_CLS_AC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_ac_rsasig_crt(ctx->cipher.hwc,
				__n, __nlen, __p, __plen, __q, __qlen,
				_dp, _dplen, _dq, _dqlen, _qp, _qplen,
				sal, sallen, has, haslen, sig, siglen);
		break;
	case 0x00:
		r = import_rsa_pri_key(&ctx->cipher.ac,
				__n, __nlen, 0, 0, __e, __elen,
				__p, __plen, __q, __qlen,
				_dp, _dplen, _dq, _dqlen, _qp, _qplen);
		if ( r < 0 ) break;

		r = rsa_sign(&ctx->cipher.ac, ctx->action,
				sal, sallen, has, haslen, sig, siglen);
		rsa_rel_key(&ctx->cipher.ac);
		break;
	}

	if ( r < 0 ) { return r; }

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
		 ctx->class != UT_PF_CP_CLS_AC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_ac_rsavfy(ctx->cipher.hwc,
				__n, __nlen, __e, __elen,
				sal, sallen, has, haslen, sig, siglen);
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

ut_int32_t ut_pf_cp_ac_eccsig(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__k, ut_uint32_t  __klen,
		ut_uint8_t *has, ut_uint32_t  haslen,
		ut_uint8_t *sig, ut_uint32_t *siglen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->class != UT_PF_CP_CLS_AC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_ac_eccsig(ctx->cipher.hwc,
				__k, __klen, has, haslen, sig, siglen);
		break;
	case 0x00:
		r = ecc_ecdsa_sign(&ctx->cipher.ac, ctx->action,
				__k, __klen, has, haslen, sig, siglen);
		break;
	}

	if ( r < 0 ) { return -2; }

	return r;
}

ut_int32_t ut_pf_cp_ac_eccvfy(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__x, ut_uint32_t __xlen,
		ut_uint8_t *__y, ut_uint32_t __ylen,
		ut_uint8_t *has, ut_uint32_t haslen,
		ut_uint8_t *sig, ut_uint32_t siglen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->class != UT_PF_CP_CLS_AC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_ac_eccvfy(ctx->cipher.hwc,
				__x, __xlen, __y, __ylen,
				has, haslen, sig, siglen);
		break;
	case 0x00:
		r = ecc_ecdsa_verify(&ctx->cipher.ac, ctx->action,
				__x, __xlen, __y, __ylen,
				has, haslen, sig, siglen);
		break;
	}

	if ( r < 0 ) { return -2; }

	return r;
}

ut_int32_t ut_pf_cp_gk_ecckey(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__x, ut_uint32_t *__xlen,
		ut_uint8_t *__y, ut_uint32_t *__ylen,
		ut_uint8_t *__k, ut_uint32_t *__klen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->class != UT_PF_CP_CLS_GK ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_gk_ecckey(ctx->cipher.hwc,
				__x, __xlen, __y, __ylen, __k, __klen);
		break;
	case 0x00:
		r = ecc_gen_key(&ctx->cipher.gk, ctx->action,
				__x, __xlen, __y, __ylen, __k, __klen);
		break;
	}

	if ( r < 0 ) { return -2; }

	return r;
}


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
		ut_uint8_t *_qp, ut_uint32_t *_qplen)
{
	if ( ctx == NULL ||
		 ctx->class != UT_PF_CP_CLS_GK ) {
		return -1;
	}
	return rsa_gen_key(&ctx->cipher.gk, bit,exponent,
			__e, __elen, __n, __nlen, __d, __dlen,
			__p, __plen, __q, __qlen,
			_dp, _dplen, _dq, _dqlen, _qp, _qplen);
}

ut_int32_t ut_pf_cp_ac_sm2enc(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__k, ut_uint32_t __klen,
		ut_uint8_t *src, ut_uint32_t  srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->class != UT_PF_CP_CLS_AC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		break;
	case 0x00:
		/*
 		r = sm2_pri_key(&ctx->cipher.ac.sm2.key,
				__k, __klen);
		if ( r < 0 ) break;

		r = sm2_encrypt(&ctx->cipher.ac, ctx->action,
				src, srclen, dst, dstlen);
		sm2_rel_key(ctx->cipher.ac.sm2.key);
		*/
		break;
	}

	if ( r < 0 ) { return -2; }

	return r;
}

ut_int32_t ut_pf_cp_ac_sm2dec(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__x, ut_uint32_t __xlen,
		ut_uint8_t *__y, ut_uint32_t __ylen,
		ut_uint8_t *src, ut_uint32_t srclen,
		ut_uint8_t *dst, ut_uint32_t *dstlen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->class != UT_PF_CP_CLS_AC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		break;
	case 0x00:
		/*
		r = sm2_pub_key(&ctx->cipher.ac.sm2.key,
				__x, __xlen, __y, __ylen);
		if ( r < 0 ) break;

		r = sm2_decrypt(&ctx->cipher.ac, ctx->action,
				src, srclen, dst, dstlen);
		sm2_rel_key(ctx->cipher.ac.sm2.key);
		*/
		break;
	}

	if ( r < 0 ) { return -2; }

	return r;
}


ut_int32_t ut_pf_cp_ac_sm2sig(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__k, ut_uint32_t __klen,
		ut_uint8_t *id,  ut_uint32_t  idlen,
		ut_uint8_t *has, ut_uint32_t haslen,
		ut_uint8_t *sig, ut_uint32_t *siglen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->class != UT_PF_CP_CLS_AC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		break;
	case 0x00:
		/*
		r = sm2_sign(&ctx->cipher.ac, ctx->action,
				__k, __klen, id, idlen, has, haslen, sig, siglen);
		*/
		break;
	}

	if ( r < 0 ) { return -2; }

	return r;
}

ut_int32_t ut_pf_cp_ac_sm2vfy(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__x, ut_uint32_t __xlen,
		ut_uint8_t *__y, ut_uint32_t __ylen,
		ut_uint8_t *id,  ut_uint32_t  idlen,
		ut_uint8_t *has, ut_uint32_t haslen,
		ut_uint8_t *sig, ut_uint32_t siglen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->class != UT_PF_CP_CLS_AC ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		break;
	case 0x00:
		/*
		r = sm2_verify(&ctx->cipher.ac, ctx->action,
				__x, __xlen, __y, __ylen, id, idlen,
				has, haslen, sig, siglen);
		*/
		break;
	}

	if ( r < 0 ) { return -2; }

	return r;
}

ut_int32_t ut_pf_cp_gk_sm2key(
		ut_pf_cp_context_t *ctx,
		ut_uint8_t *__x, ut_uint32_t *__xlen,
		ut_uint8_t *__y, ut_uint32_t *__ylen,
		ut_uint8_t *__k, ut_uint32_t *__klen)
{
	ut_int32_t r = -1;

	if ( ctx == NULL ||
		 ctx->class != UT_PF_CP_CLS_GK ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		break;
	case 0x00:
		r = sm2_gen_key(&ctx->cipher.gk, ctx->action,
				__x, __xlen, __y, __ylen, __k, __klen);
		break;
	}

	if ( r < 0 ) { return -2; }

	return r;
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
		 ctx->class != UT_PF_CP_CLS_RD ) {
		return -1;
	}

	switch( ctx->use_hwc ) {
	case 0x01:
		r = ut_pf_cp_hwc_rd_random(ctx->cipher.hwc, rnd, rndlen);
		break;
	case 0x00:
		r = _rand(NULL, rnd, rndlen);
		break;
	}

	if ( r < 0 ) { return -2; }

	return r;
}

ut_int32_t ut_pf_cp_close(ut_pf_cp_context_t *ctx)
{
	ut_int32_t r = 0;

	if ( ctx != NULL )
	{
		switch( ctx->use_hwc ) {
		case 0x01: // hardware
			r = ut_pf_cp_hwc_close( ctx->cipher.hwc );
			break;
		case 0x00: // software
			switch( ctx->class ) {
			case UT_PF_CP_CLS_AE:
				switch( ctx->action ) {
				case UT_PF_CP_ACT_AE_AES_CCM:
					if ( ctx->cipher.ae.aes.mode.ccm.add ) {
						free(ctx->cipher.ae.aes.mode.ccm.add);
						ctx->cipher.ae.aes.mode.ccm.add = NULL;
					}
					break;
				}
				break;
			default:
				break;
			}
			break;
		}
		free( ctx );
	}

	return r;
}



static int load_big_int( pstm_int *a, ut_uint8_t * d,ut_uint32_t dlen)
{
	int r = 0;
	if(a==NULL || d==NULL || dlen==0 )
		return -UTPFCP_ERR_INVALID_PARAMS;
	
	MBEDRET(UTPFCP_ERR_LOADBIGINT, pstm_init_for_read_unsigned_bin(NULL, a , dlen) );
 
    MBEDRET(UTPFCP_ERR_LOADBIGINT,pstm_read_unsigned_bin(a,d, dlen) );

end:
	if(r<0)
		pstm_clear(a);
	return r;
}
static int load_big_int_as_one( pstm_int *a)
{
	int r = 0;
	if(a==NULL  )
		return -UTPFCP_ERR_INVALID_PARAMS;
	MBEDRET(UTPFCP_ERR_LOADBIGINT, pstm_init_size(NULL, a, 1));
    pstm_set(a, 1);
end:
	return r;
}

static  int ecc_key_load( psEccSet_t *ecc_set,
                ut_uint8_t *private_key,ut_uint32_t private_key_len,
                ut_uint8_t *public_key_x,ut_uint32_t public_key_x_len,
                ut_uint8_t *public_key_y,ut_uint32_t public_key_y_len,
		psEccKey_t ** out
)
{

	int r=0;
	psEccKey_t *privkey = NULL;
	if(ecc_set==NULL  || public_key_x==NULL ||  public_key_x_len==0 
		|| public_key_y==NULL || public_key_y_len==0 || out == NULL)
	{
		return -UTPFCP_ERR_INVALID_PARAMS;
	}
	
	privkey = (psEccKey_t *)psMalloc(0, sizeof(psEccKey_t));
	if(privkey==NULL)
	{
		return -UTPFCP_ERR_MALLOC_FAILED;
	}
	memset(privkey,0,sizeof(psEccKey_t));
	privkey->pool = NULL;
	privkey->type = PS_ECC;
	privkey->dp = ecc_set;
	privkey->pubkey.pool = 0;
	r = load_big_int( &privkey->pubkey.x , public_key_x ,public_key_x_len);
	if(r!=0) goto end;
	r = load_big_int( &privkey->pubkey.y , public_key_y ,public_key_y_len);
	if(r!=0) goto end;
	r = load_big_int_as_one(&privkey->pubkey.z);
	if(r!=0) goto end;
	if(private_key==NULL || private_key_len == 0)
	{
		*out = privkey;
		return 0;
	}
	r = load_big_int( &privkey->k , private_key ,private_key_len);
	if(r!=0) goto end;
	*out = privkey;
	return 0;
end:
	psEccFreeKey(&privkey);
	return r;
}
static void ecc_key_free(psEccKey_t *lkey)
{
	psEccFreeKey(&lkey);
}
		
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
                               ut_uint32_t * sklen ) 
{
	ut_int32_t r = 0;

	psEccSet_t *ecc_set = NULL; 
	if(ctx==NULL
		|| k1==NULL
		|| k1len == 0
		|| x1 == NULL
		|| x1len == 0
		|| y1 == NULL
		|| y1len == 0
		|| x2 == NULL
		|| x2len == 0
		|| y2 == NULL
		|| y2len == 0
		|| sk ==NULL
		|| sklen == 0)
		return -UTPFCP_ERR_INVALID_PARAMS;
	
	switch( ctx->action ){
	case UT_PF_CP_ACT_AC_ECDH_BP224R1_SHARE_KEY :
		MBEDRET2(UTPFCP_ERR_LOADECCPARAM, getEccParamByName("BP-224", &ecc_set )); 
		break;
	case UT_PF_CP_ACT_AC_ECDH_BP256R1_SHARE_KEY :
		MBEDRET2(UTPFCP_ERR_LOADECCPARAM, getEccParamByName("BP-256", &ecc_set ));
		break;
	case UT_PF_CP_ACT_AC_ECDH_BP384R1_SHARE_KEY :
		MBEDRET2(UTPFCP_ERR_LOADECCPARAM, getEccParamByName("BP-384", &ecc_set ));
		break;
	case UT_PF_CP_ACT_AC_ECDH_BP512R1_SHARE_KEY :
		MBEDRET2(UTPFCP_ERR_LOADECCPARAM,  getEccParamByName("BP-512", &ecc_set ));
		break;
	default:	return -UTPFCP_ERR_UNKNOWN_ACTION;
	}

	// prepare private key
	psPool_t   *pool = NULL;
	psEccKey_t *privkey = NULL;

	r =  ecc_key_load( ecc_set,
                k1, k1len,
                x1,x1len,
                y1,y1len,
				&privkey
		);
	if(r<0) return r;

	//prepare imported public key
	psEccKey_t	*pubkey_imported = NULL;
	r = ecc_key_load(ecc_set,
		NULL,0,
		x2,x2len,
                y2,y2len,
				&pubkey_imported
		);
	if(r <0)
		goto end;

	//generate shared key...
	r = psEccGenSharedSecret(pool, privkey, pubkey_imported,
		sk, (uint32*)sklen, NULL);
end:
	ecc_key_free(privkey);
	ecc_key_free(pubkey_imported);
end2:
	return r;
}

//port from psGetEntropy
// note: hardware only 
//       timetick should be add 
static int get_entropy(unsigned char *bytes, uint32 size)
{
	ut_int32_t r = -1;
	ut_pf_cp_context_h *ctx = NULL;
	ut_uint32_t seconds=0;
	ut_uint32_t million_seconds=0;
#ifdef HARDWARE_RND	
	r = ut_pf_cp_hwc_open(&ctx,
				UT_PF_CP_CLS_RD,
				UT_PF_CP_ACT_RD_GENVEC); 
	if ( r < 0 ) {
		return r;
	}

	r = ut_pf_cp_hwc_rd_random(ctx,
				(ut_uint8_t *)bytes, size); 
	if ( r < 0 ) {
		ut_pf_cp_hwc_close(ctx);
		return r;
	}
	
	r = ut_pf_cp_hwc_close(ctx); 
	if ( r < 0 ) 
		return r;
#endif	
	r = ut_pf_time_get_system_time(&seconds, &million_seconds); 
	if ( r < 0 )
		return r;
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

int mbedtls_hardware_poll(void *data,
	unsigned char *output, size_t len, size_t *olen)
{
	int r= get_entropy(output, len);
	((void)data);
	if(r>0)
		*olen = r;
	else
		*olen = 0;
	if(r<0)return r;
	return 0;
}

