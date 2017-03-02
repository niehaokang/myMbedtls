/**
 *	@file    gpd.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	GlobalPlatform Device Technology
 *	TEE Client API implementation.
 */
/*
 *	Copyright (c) 2013-2015 INSIDE Secure Corporation
 *	Copyright (c) PeerSec Networks, 2002-2011
 *	All Rights Reserved
 *
 *	The latest version of this code is available at http://www.matrixssl.org
 *
 *	This software is open source; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This General Public License does NOT permit incorporating this software
 *	into proprietary programs.  If you are unable to comply with the GPL, a
 *	commercial license for this software may be purchased from INSIDE at
 *	http://www.insidesecure.com/eng/Company/Locations
 *
 *	This program is distributed in WITHOUT ANY WARRANTY; without even the
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *	See the GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *	http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#include "../cryptoApi.h"
#include "../mbedtls/bignum.h"
#include "../mbedtls/entropy.h"
#include "../mbedtls/entropy_poll.h"
#include "../mbedtls/ctr_drbg.h"

#define matrixs_aes_encrypt_block  psAesEncryptBlock
#define matrixs_aes_decrypt_block  psAesDecryptBlock
#define matrixs_des_encrypt_block  psDesEncryptBlock
#define matrixs_des_decrypt_block  psDesDecryptBlock
#define matrixs_des3_encrypt_block psDes3EncryptBlock
#define matrixs_des3_decrypt_block psDes3DecryptBlock

static void hexify( unsigned char *obuf, const unsigned char *ibuf, int len ) {
    unsigned char l, h;

    while( len != 0 )
    {
        h = *ibuf / 16;
        l = *ibuf % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}

static void printlog(char *name, unsigned char *hex, int hexlen )
{
	int i = 0, n = 0, m = 0;
	unsigned char *p = hex;
	unsigned char out[128] = {0};

	n = hexlen / 32; m = hexlen % 32;
	for ( i = 0; i < n; i++) {
		memset( out, 0, sizeof(out));
		hexify( out, p, 32 );
		printf( "%s:%s\n", name, out);
		p += 32;
	}

	if ( m > 0 ) {
		memset( out, 0, sizeof(out));
		hexify( out, p, m );
		printf( "%s:%s\n", name, out);
	}
}

static void matrixs_aes_cbc_encrypt( unsigned char *in, unsigned char *out,
		size_t len,  void *key, unsigned char ivec[16], int enc)
{
	if (enc) {
		cbc128_encrypt(in, out, len, key, ivec,
				(block128_f)matrixs_aes_encrypt_block);
	} else {
		cbc128_decrypt(in, out, len, key, ivec,
				(block128_f)matrixs_aes_decrypt_block);
	}
}

/*
 * PKCS7 (and PKCS5) padding: fill with ll bytes, with ll = padding_len
 */
static void add_pkcs_padding( unsigned char *output, int32 output_len,
		int32 data_len )
{
	int32 i, padding_len;

	padding_len = output_len - data_len;
    for( i = 0; i < padding_len; i++ )
        output[data_len + i] = (unsigned char)padding_len;
}

/*  HMAC（K，M） = H（K⊕opad∣H（K⊕ipad∣M）） */
static  int matrixs_hmac_init(matrixs_mc_context_t *mac_ctx,
		unsigned char *key, size_t keylen)
{
	int i = 0, blocksize = 0;
	unsigned char mackey[128] = {0};

	switch ( mac_ctx->kind ) {
	case MATRIXS_HMAC_MD5:
		mac_ctx->hmac.md.len = 16; blocksize = 64;
		break;
	case MATRIXS_HMAC_SHA1:
		mac_ctx->hmac.md.len = 20; blocksize = 64;
		break;
	case MATRIXS_HMAC_SHA224:
		mac_ctx->hmac.md.len = 28; blocksize = 64;
		break;
	case MATRIXS_HMAC_SHA256:
		mac_ctx->hmac.md.len = 32; blocksize = 64;
		break;
	case MATRIXS_HMAC_SHA384:
		mac_ctx->hmac.md.len = 48; blocksize = 128;
		break;
	case MATRIXS_HMAC_SHA512:
		mac_ctx->hmac.md.len = 64; blocksize = 128;
		break;
	}

	/* keylen > blocksize */
	if ( keylen <= (size_t)blocksize ) {
		memcpy( mackey, key, keylen );
		memset(&mackey[keylen], 0x00, blocksize - keylen );
	} else {
		matrixs_md_starts( &mac_ctx->hmac.md );
		matrixs_md_update( &mac_ctx->hmac.md, key, keylen );
		matrixs_md_finish( &mac_ctx->hmac.md, mackey );

		if ( mac_ctx->hmac.md.len < (size_t)blocksize )
			memset(&mackey[mac_ctx->hmac.md.len], 0x00, blocksize - mac_ctx->hmac.md.len );
	}

	for ( i = 0; i < blocksize; i++ ) {
		mac_ctx->hmac.ipad[i] = mackey[i] ^ 0x36;
	}
	for ( i = 0; i < blocksize; i++ ) {
		mac_ctx->hmac.opad[i] = mackey[i] ^ 0x5C;
	}

	mac_ctx->hmac.blocksize = blocksize;
	matrixs_md_starts( &mac_ctx->hmac.md );
	matrixs_md_update( &mac_ctx->hmac.md, mac_ctx->hmac.ipad, blocksize );

	return( 0 );
}

static  int matrixs_hmac_update(matrixs_mc_context_t *mac_ctx,
		unsigned char *input, size_t inlen)
{
	matrixs_md_update( &mac_ctx->hmac.md, input, inlen );

	return( 0 );
}

static  int matrixs_hmac_final(matrixs_mc_context_t *mac_ctx,
		unsigned char *hash )
{
	matrixs_md_finish( &mac_ctx->hmac.md, hash );

	matrixs_md_starts( &mac_ctx->hmac.md );
	matrixs_md_update( &mac_ctx->hmac.md, mac_ctx->hmac.opad, mac_ctx->hmac.blocksize );
	matrixs_md_update( &mac_ctx->hmac.md, hash, mac_ctx->hmac.md.len );
	matrixs_md_finish( &mac_ctx->hmac.md, hash );

	return mac_ctx->hmac.md.len;
}

static int matrixs_cmac_init(matrixs_mc_context_t *mac_ctx,
		unsigned char *key, size_t keylen,
		unsigned char *ivec, uint32 iveclen)
{
	switch ( mac_ctx->kind ) {
	case MATRIXS_CMAC_AES:
		if ( ivec == NULL || iveclen == 0 )
			return psCmacAesInit( &mac_ctx->cmac.ctx,
					key, keylen );
		else
			return psCmacAesInit2( &mac_ctx->cmac.ctx,
					key, keylen, ivec, iveclen );
	}
	return -1;
}

static int matrixs_cmac_update(matrixs_mc_context_t *mac_ctx,
		unsigned char *input, size_t inlen)
{
	switch ( mac_ctx->kind ) {
	case MATRIXS_CMAC_AES: /* AES-CMAC */
		return psCmacAesUpdate(
				&mac_ctx->cmac.ctx, input, inlen );
	}
	return -1;
}

static  int matrixs_cmac_final(matrixs_mc_context_t *mac_ctx,
		unsigned char *hash )
{
	uint32 size = 0;

	switch ( mac_ctx->kind ) {
	case MATRIXS_CMAC_AES: /* AES-CMAC */
		psCmacAesFinal(
				&mac_ctx->cmac.ctx, hash, &size);
		return (int)size;
	}
	return -1;
}

static  int matrixs_cbcmac_init(matrixs_mc_context_t *mac_ctx,
		unsigned char *key, size_t keylen,
		unsigned char *ivec, uint32 iveclen, unsigned char padding)
{
	int ret = -1;
	size_t kind, IVlen = 0;
	unsigned char IV[16] = {0};

	switch ( mac_ctx->kind ) {
	case MATRIXS_CBCMAC_AES:	kind = MATRIXS_AES_CBC ; IVlen = 16; break;
	case MATRIXS_CBCMAC_DES:	kind = MATRIXS_DES_CBC ; IVlen =  8; break;
	case MATRIXS_CBCMAC_DES3:	kind = MATRIXS_DES3_CBC; IVlen =  8; break;
	}

	mac_ctx->cbcmac.last_len = 0;
	mac_ctx->cbcmac.padding = padding;
	ret = matrixs_cp_setkey( &mac_ctx->cbcmac.cp,
			kind, key, keylen, NULL, 0);

	if ( ret < 0 ) return ret;

	if ( ivec != NULL && iveclen != 0 )
		memcpy( IV, ivec, iveclen );

	ret = matrixs_cp_starts( &mac_ctx->cbcmac.cp,
			IV, IVlen);

	if ( ret < 0 ) return ret;

	return( 0 );
}

static  int matrixs_cbcmac_update(matrixs_mc_context_t *mac_ctx,
		unsigned char *input, size_t inlen)
{
	int ret ;
	size_t c1, blocksize, tempLen;
	unsigned char temp[32] = {0};

	switch ( mac_ctx->kind ) {
	case MATRIXS_CBCMAC_AES:	blocksize = 16; break;
	case MATRIXS_CBCMAC_DES:
	case MATRIXS_CBCMAC_DES3:	blocksize =  8; break;
	}

	if ( mac_ctx->cbcmac.last_len > 0 ) {

		c1 = blocksize - mac_ctx->cbcmac.last_len;
		if (inlen < c1) c1 = inlen;

		memcpy(&mac_ctx->cbcmac.last[mac_ctx->cbcmac.last_len], input, c1);

		inlen -= c1; input += c1; mac_ctx->cbcmac.last_len += c1;
		if (inlen == 0) return( 0 );

		tempLen = sizeof(temp);
		ret = matrixs_cp_update(  &mac_ctx->cbcmac.cp,
				MATRIXS_CP_ENCRYPT,
				mac_ctx->cbcmac.last, blocksize, temp, &tempLen );

		if ( ret < 0 ) return ret;
	}

	while ( inlen >= blocksize ) {
		tempLen = sizeof(temp);
		ret = matrixs_cp_update(  &mac_ctx->cbcmac.cp,
				MATRIXS_CP_ENCRYPT,
				input, blocksize, temp, &tempLen );

		if ( ret < 0 ) return ret;

		inlen -= blocksize; input += blocksize;
	}

	mac_ctx->cbcmac.last_len = inlen;
	memcpy(mac_ctx->cbcmac.last, input, inlen);
	return( 0 );
}

static  int matrixs_cbcmac_final(matrixs_mc_context_t *mac_ctx,
		unsigned char *hash )
{
	int ret = -1, blocksize = 0;
	size_t tempLen = 16;
	unsigned char temp[16];

	switch ( mac_ctx->kind ) {
	case MATRIXS_CBCMAC_AES:	blocksize = 16; break;
	case MATRIXS_CBCMAC_DES:
	case MATRIXS_CBCMAC_DES3:	blocksize =  8; break;
	}

	switch (mac_ctx->cbcmac.padding) {
	case 0: // NONE.#
		memcpy(temp,
			mac_ctx->cbcmac.cp.ivec, blocksize);
		break;

	case 1: // PKCS#5
		add_pkcs_padding( mac_ctx->cbcmac.last,
			blocksize, mac_ctx->cbcmac.last_len );

		ret = matrixs_cp_finish( &mac_ctx->cbcmac.cp,
				MATRIXS_CP_ENCRYPT, mac_ctx->cbcmac.last,
				blocksize, temp, &tempLen );
		if ( ret < 0 ) return ret;
		break;
	}

	memcpy( hash, temp, blocksize);
	return( blocksize );
}

////////////////////////////////////////////////////////////////////////////////
int matrix_check_prime( unsigned char *buf, size_t buflen )
{
    int ret;
	mbedtls_mpi X;

	mbedtls_mpi_init( &X );
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &X, buf, buflen ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_is_prime( &X, psGetPrngData, NULL ));

cleanup:
	mbedtls_mpi_free( &X );
	return( ret );
}

////////////////////////////////////////////////////////////////////////////////
void matrixs_random(void *p_rng,
		unsigned char *salt, size_t saltlen)
{
	int l, n;
	unsigned char *p = salt;

	n = saltlen / 2048; l = saltlen % 2048;
	while ( n-- ) {
		psGetPrngData(p_rng, p, 2048);
		p += 2048;
	}

	if ( l > 0 ) psGetPrngData(p_rng, p, l);
}

////////////////////////////////////////////////////////////////////////////////
int matrixs_md_valid(matrixs_md_context_t *md_ctx)
{
	switch ( md_ctx->len ) {
	case    MD5_HASH_SIZE:
	case   SHA1_HASH_SIZE:
	case SHA224_HASH_SIZE:
	case SHA256_HASH_SIZE:
	case SHA384_HASH_SIZE:
	case SHA512_HASH_SIZE:
		return( 1 );
	default:
		return( 0 );
	}
}

////////////////////////////////////////////////////////////////////////////////
void matrixs_md_starts(matrixs_md_context_t *md_ctx)
{
	switch ( md_ctx->len ) {
	case    MD5_HASH_SIZE:    psMd5Init( &md_ctx->ctx ); break;
	case   SHA1_HASH_SIZE:   psSha1Init( &md_ctx->ctx ); break;
	case SHA224_HASH_SIZE: psSha224Init( &md_ctx->ctx ); break;
	case SHA256_HASH_SIZE: psSha256Init( &md_ctx->ctx ); break;
	case SHA384_HASH_SIZE: psSha384Init( &md_ctx->ctx ); break;
	case SHA512_HASH_SIZE: psSha512Init( &md_ctx->ctx ); break;
	}
}

void matrixs_md_update(matrixs_md_context_t *md_ctx,
		unsigned char *input, size_t ilen)
{
	switch ( md_ctx->len ) {
	case    MD5_HASH_SIZE:    psMd5Update( &md_ctx->ctx, input, (uint32)ilen ); break;
	case   SHA1_HASH_SIZE:   psSha1Update( &md_ctx->ctx, input, (uint32)ilen ); break;
	case SHA224_HASH_SIZE: psSha224Update( &md_ctx->ctx, input, (uint32)ilen ); break;
	case SHA256_HASH_SIZE: psSha256Update( &md_ctx->ctx, input, (uint32)ilen ); break;
	case SHA384_HASH_SIZE: psSha384Update( &md_ctx->ctx, input, (uint32)ilen ); break;
	case SHA512_HASH_SIZE: psSha512Update( &md_ctx->ctx, input, (uint32)ilen ); break;
	}
}

void matrixs_md_finish(matrixs_md_context_t *md_ctx,
		unsigned char *output)
{
	switch ( md_ctx->len ) {
	case    MD5_HASH_SIZE:    psMd5Final( &md_ctx->ctx, output ); break;
	case   SHA1_HASH_SIZE:   psSha1Final( &md_ctx->ctx, output ); break;
	case SHA224_HASH_SIZE: psSha224Final( &md_ctx->ctx, output ); break;
	case SHA256_HASH_SIZE: psSha256Final( &md_ctx->ctx, output ); break;
	case SHA384_HASH_SIZE: psSha384Final( &md_ctx->ctx, output ); break;
	case SHA512_HASH_SIZE: psSha512Final( &md_ctx->ctx, output ); break;
	}
}

////////////////////////////////////////////////////////////////////////////////
int matrixs_mc_setkey(matrixs_mc_context_t *mc_ctx,
		unsigned int kind, unsigned char *key, unsigned int keylen)
{
	if ( mc_ctx != NULL && key != NULL )
	{
		memset(mc_ctx, 0x00, sizeof(matrixs_mc_context_t));

		mc_ctx->kind = kind;
		mc_ctx->keylen = keylen;
		memcpy(mc_ctx->keyval, key, keylen);

		return( 0 );
	}

	return( -1 );
}

int matrixs_mc_starts( matrixs_mc_context_t *mac_ctx,
		unsigned char *ivec, size_t iveclen, unsigned char padding)
{
	int ret = 0;

	switch ( mac_ctx->kind ) {
	case MATRIXS_HMAC_MD5:
	case MATRIXS_HMAC_SHA1:
	case MATRIXS_HMAC_SHA224:
	case MATRIXS_HMAC_SHA256:
	case MATRIXS_HMAC_SHA384:
	case MATRIXS_HMAC_SHA512:
		ret = matrixs_hmac_init( mac_ctx,
				mac_ctx->keyval, mac_ctx->keylen );
		return ret;

	case MATRIXS_CMAC_AES:
		ret = matrixs_cmac_init( mac_ctx,
				mac_ctx->keyval, mac_ctx->keylen, ivec, iveclen);
		return ret;

	case MATRIXS_CBCMAC_AES:
	case MATRIXS_CBCMAC_DES:
	case MATRIXS_CBCMAC_DES3:
		ret = matrixs_cbcmac_init( mac_ctx,
				mac_ctx->keyval, mac_ctx->keylen, ivec, iveclen, padding);
		return ret;
	}

	return( -1 );
}

int matrixs_mc_update( matrixs_mc_context_t *mac_ctx,
		unsigned char *input, size_t ilen)
{
	int ret = 0;

	switch ( mac_ctx->kind ) {
	case MATRIXS_HMAC_MD5:
	case MATRIXS_HMAC_SHA1:
	case MATRIXS_HMAC_SHA224:
	case MATRIXS_HMAC_SHA256:
	case MATRIXS_HMAC_SHA384:
	case MATRIXS_HMAC_SHA512:
		ret = matrixs_hmac_update( mac_ctx,
				input, ilen );
		return ret;

	case MATRIXS_CMAC_AES:
		ret = matrixs_cmac_update( mac_ctx,
				input, ilen );
		return ret;

	case MATRIXS_CBCMAC_AES:
	case MATRIXS_CBCMAC_DES:
	case MATRIXS_CBCMAC_DES3:
		ret = matrixs_cbcmac_update( mac_ctx,
				input, ilen );
		return ret;
	}

	return( -1 );
}

int matrixs_mc_finish( matrixs_mc_context_t *mac_ctx,
		unsigned char *mac, size_t *maclen)
{
	switch ( mac_ctx->kind )
	{
	case MATRIXS_HMAC_MD5:
	case MATRIXS_HMAC_SHA1:
	case MATRIXS_HMAC_SHA224:
	case MATRIXS_HMAC_SHA256:
	case MATRIXS_HMAC_SHA384:
	case MATRIXS_HMAC_SHA512:
		*maclen = matrixs_hmac_final( mac_ctx, mac );
		return( 0 );

	case MATRIXS_CMAC_AES:
		*maclen = matrixs_cmac_final( mac_ctx, mac );
		return( 0 );

	case MATRIXS_CBCMAC_AES:
	case MATRIXS_CBCMAC_DES:
	case MATRIXS_CBCMAC_DES3:
		*maclen = matrixs_cbcmac_final( mac_ctx, mac );
		return( 0 );
	}

	return( -1 );
}

////////////////////////////////////////////////////////////////////////////////
int matrixs_cp_setkey(matrixs_cp_context_t *cp_ctx,
		unsigned int kind,
		unsigned char *key, unsigned int keylen,
		unsigned char *key2, unsigned int keylen2)
{
	if ( cp_ctx != NULL && key != NULL)
	{
		memset(cp_ctx, 0x00, sizeof(matrixs_cp_context_t));

		cp_ctx->kind = kind;
		cp_ctx->keylen = keylen;
		memcpy(cp_ctx->keyval, key, keylen);

		if ( key2 != NULL )
		{
			cp_ctx->keylen2 = keylen2;
			memcpy(cp_ctx->keyval2, key2, keylen2);
		}

		return( 0 );
	}

	return( -1 );
}

int matrixs_cp_starts( matrixs_cp_context_t *cp_ctx,
		unsigned char *ivec, size_t iveclen)
{
	int ret = -1;
	unsigned int	kind;

	kind = cp_ctx->kind;

	switch ( cp_ctx->kind ) {
	case MATRIXS_AES_ECB:
	case MATRIXS_AES_CBC:
	case MATRIXS_AES_CTR:
	case MATRIXS_AES_CTS:

		memset(cp_ctx->ivec, 0x00, 16);
		if ( ivec != NULL && iveclen == 16 )
			memcpy(cp_ctx->ivec, ivec, iveclen);

		if ( cp_ctx->kind == MATRIXS_AES_CTR ) {
			cp_ctx->c.aes.mode.ctr.num = 0;
			memset(cp_ctx->c.aes.mode.ctr.ecount, 0x00, 16);
		}

		ret = psAesInitKey( cp_ctx->keyval, cp_ctx->keylen, &cp_ctx->c.aes.ctx);
		if ( ret != PS_SUCCESS) {
			return MATRIXS_ERR_CP_BAD_INPUT_DATA;
		}

		return ret;

	case MATRIXS_AES_XTS:

		memset(cp_ctx->ivec, 0x00, 16);
		if ( ivec != NULL && iveclen == 16 )
			memcpy(cp_ctx->ivec, ivec, iveclen);

		ret = psAesInitKey( cp_ctx->keyval,
				cp_ctx->keylen, &cp_ctx->c.aes.ctx);
		if ( ret != PS_SUCCESS)
			return MATRIXS_ERR_CP_BAD_INPUT_DATA;

		ret = psAesInitKey( cp_ctx->keyval2,
				cp_ctx->keylen2, &cp_ctx->c.aes.mode.xts.ctx);
		if ( ret != PS_SUCCESS)
			return MATRIXS_ERR_CP_BAD_INPUT_DATA;

		/* set key */
		xts128_init(&cp_ctx->c.aes.mode.xts.c, cp_ctx->ivec,
				&cp_ctx->c.aes.ctx, &cp_ctx->c.aes.mode.xts.ctx,
				(block128_f)matrixs_aes_encrypt_block);

		return ret;

	case MATRIXS_DES_ECB:
	case MATRIXS_DES_CBC:

		if ( ivec != NULL && iveclen != 8 )
			return MATRIXS_ERR_CP_BAD_INPUT_DATA;

		cp_ctx->blocklen = 0;
		memcpy(cp_ctx->ivec, ivec, iveclen);

		ret = psDesInitKey( cp_ctx->keyval, cp_ctx->keylen, &cp_ctx->c.des.ctx);
		if ( ret != PS_SUCCESS)
			return MATRIXS_ERR_CP_BAD_INPUT_DATA;

		return ret;

	case MATRIXS_DES3_ECB:
	case MATRIXS_DES3_CBC:

		if ( ivec != NULL && iveclen != 8 )
			return MATRIXS_ERR_CP_BAD_INPUT_DATA;

		cp_ctx->blocklen = 0;
		memcpy(cp_ctx->ivec, ivec, iveclen);

		ret = psDes3InitKey( cp_ctx->keyval, cp_ctx->keylen, &cp_ctx->c.des.ctx);
		if ( ret != PS_SUCCESS)
			return MATRIXS_ERR_CP_BAD_INPUT_DATA;

		return ret;
	}

	return( -1 );
}

int matrixs_cp_update( matrixs_cp_context_t *cp_ctx,
		int mode,
		unsigned char *input, size_t inlen,
		unsigned char *output, size_t *outlen)
{
	size_t blocksize = 0;

	if ( cp_ctx->kind & 0x0F )	blocksize  = 0x10; // 16B
	else						blocksize  = 0x08; //  8B

	if ( input  == NULL ||  output == NULL ||
		 outlen == NULL || *outlen < inlen || (inlen % blocksize) != 0 )
	{
		return MATRIXS_ERR_CP_BAD_INPUT_DATA;
	}

	switch ( cp_ctx->kind )
	{
	case MATRIXS_AES_ECB:
		switch ( mode ) {
		case MATRIXS_CP_ENCRYPT:
			ecb128_encrypt(input, output, inlen,
					&cp_ctx->c.aes.ctx,
					(block128_f)matrixs_aes_encrypt_block);
			break;
		case MATRIXS_CP_DECRYPT:
			ecb128_decrypt(input, output, inlen,
					&cp_ctx->c.aes.ctx,
					(block128_f)matrixs_aes_decrypt_block);
		}
		break;

	case MATRIXS_AES_CBC:
		switch ( mode ) {
		case MATRIXS_CP_ENCRYPT:
			cbc128_encrypt(input, output, inlen,
					&cp_ctx->c.aes.ctx, cp_ctx->ivec,
					(block128_f)matrixs_aes_encrypt_block);
			break;
		case MATRIXS_CP_DECRYPT:
			cbc128_decrypt(input, output, inlen,
					&cp_ctx->c.aes.ctx, cp_ctx->ivec,
					(block128_f)matrixs_aes_decrypt_block);
			break;
		}
		break;

	case MATRIXS_AES_CTR:
		switch ( mode ) {
		case MATRIXS_CP_ENCRYPT:
		case MATRIXS_CP_DECRYPT:
			ctr128_encrypt(input, output, inlen,
					&cp_ctx->c.aes.ctx, cp_ctx->ivec,
					cp_ctx->c.aes.mode.ctr.ecount, &cp_ctx->c.aes.mode.ctr.num,
					(block128_f)matrixs_aes_encrypt_block);
			break;
		}
		break;

	case MATRIXS_AES_CTS:
		switch ( mode ) {
		case MATRIXS_CP_ENCRYPT:
			nistcts128_encrypt(input, output, inlen,
					&cp_ctx->c.aes.ctx, cp_ctx->ivec,
					(cbc128_f)matrixs_aes_cbc_encrypt);
			break;
		case MATRIXS_CP_DECRYPT:
			nistcts128_decrypt(input, output, inlen,
					&cp_ctx->c.aes.ctx, cp_ctx->ivec,
					(cbc128_f)matrixs_aes_cbc_encrypt);
			break;
		}
		break;

	case MATRIXS_AES_XTS:
		switch ( mode ) {
		case MATRIXS_CP_ENCRYPT:
			cp_ctx->c.aes.mode.xts.c.block1 =
					(block128_f)matrixs_aes_encrypt_block;
			xts128_update(&cp_ctx->c.aes.mode.xts.c,
					input, output, inlen);
			break;
		case MATRIXS_CP_DECRYPT:
			cp_ctx->c.aes.mode.xts.c.block1 =
					(block128_f)matrixs_aes_decrypt_block;
			xts128_update(&cp_ctx->c.aes.mode.xts.c,
					input, output, inlen);
			break;
		}
		break;

	case MATRIXS_DES_ECB:
		switch ( mode ) {
		case MATRIXS_CP_ENCRYPT:
			ecb64_encrypt(input, output, inlen,
					&cp_ctx->c.des.ctx,
					(block64_f)matrixs_des_encrypt_block);
			break;
		case MATRIXS_CP_DECRYPT:
			ecb64_decrypt(input, output, inlen,
					&cp_ctx->c.des.ctx,
					(block64_f)matrixs_des_decrypt_block);
			break;
		}
		break;

	case MATRIXS_DES_CBC:
		switch ( mode ) {
		case MATRIXS_CP_ENCRYPT:
			cbc64_encrypt(input, output, inlen,
					&cp_ctx->c.des.ctx, cp_ctx->ivec,
					(block64_f)matrixs_des_encrypt_block);
			break;
		case MATRIXS_CP_DECRYPT:
			cbc64_decrypt(input, output, inlen,
					&cp_ctx->c.des.ctx, cp_ctx->ivec,
					(block64_f)matrixs_des_decrypt_block);
			break;
		}
		break;

	case MATRIXS_DES3_ECB:
		switch ( mode ) {
		case MATRIXS_CP_ENCRYPT:
			ecb64_encrypt(input, output, inlen,
					&cp_ctx->c.des.ctx,
					(block64_f)matrixs_des3_encrypt_block);
			break;
		case MATRIXS_CP_DECRYPT:
			ecb64_decrypt(input, output, inlen,
					&cp_ctx->c.des.ctx,
					(block64_f)matrixs_des3_decrypt_block);
			break;
		}
		break;

	case MATRIXS_DES3_CBC:
		switch ( mode ) {
		case MATRIXS_CP_ENCRYPT:
			cbc64_encrypt(input, output, inlen,
					&cp_ctx->c.des.ctx, cp_ctx->ivec,
					(block64_f)matrixs_des3_encrypt_block);
			break;
		case MATRIXS_CP_DECRYPT:
			cbc64_decrypt(input, output, inlen,
					&cp_ctx->c.des.ctx, cp_ctx->ivec,
					(block64_f)matrixs_des3_decrypt_block);
			break;
		}
	}

	*outlen = inlen;
	return( 0 );
}

int matrixs_cp_finish( matrixs_cp_context_t *cp_ctx,
		int mode,
		unsigned char *input, size_t inlen,
		unsigned char *output, size_t *outlen)
{
	switch ( cp_ctx->kind )
	{
	case MATRIXS_AES_ECB:
	case MATRIXS_AES_CBC:
	case MATRIXS_DES_ECB:
	case MATRIXS_DES_CBC:
	case MATRIXS_DES3_ECB:
	case MATRIXS_DES3_CBC:

		return matrixs_cp_update( cp_ctx, mode, input, inlen, output, outlen);

	case MATRIXS_AES_CTR:

		if ( output == NULL || outlen == NULL ||
			*outlen < inlen ) {
			return MATRIXS_ERR_CP_BAD_INPUT_DATA;
		}

		ctr128_encrypt(input, output, inlen,
				&cp_ctx->c.aes.ctx, cp_ctx->ivec,
				cp_ctx->c.aes.mode.ctr.ecount ,
				&cp_ctx->c.aes.mode.ctr.num,
				(block128_f)matrixs_aes_encrypt_block);

		*outlen = inlen;
		return( 0 );

	case MATRIXS_AES_CTS:

		if ( output == NULL || outlen == NULL ||
			*outlen < inlen ) {
			return MATRIXS_ERR_CP_BAD_INPUT_DATA;
		}

		switch ( mode )
		{
		case MATRIXS_CP_ENCRYPT:
			cts128_encrypt(input, output, inlen,
					&cp_ctx->c.aes.ctx, cp_ctx->ivec,
					(cbc128_f)matrixs_aes_cbc_encrypt);
			break;
		case MATRIXS_CP_DECRYPT:
			cts128_decrypt(input, output, inlen,
					&cp_ctx->c.aes.ctx, cp_ctx->ivec,
					(cbc128_f)matrixs_aes_cbc_encrypt);
			break;
		}

		*outlen = inlen;
		return( 0 );

	case MATRIXS_AES_XTS:

		if ( output == NULL || outlen == NULL ||
			*outlen < inlen ) {
			return MATRIXS_ERR_CP_BAD_INPUT_DATA;
		}

		switch ( mode )
		{
		case MATRIXS_CP_ENCRYPT:
			cp_ctx->c.aes.mode.xts.c.block1 =
					(block128_f)matrixs_aes_encrypt_block;
			xts128_finish(&cp_ctx->c.aes.mode.xts.c,
					input, output, inlen, 1);
			break;
		case MATRIXS_CP_DECRYPT:
			cp_ctx->c.aes.mode.xts.c.block1 =
					(block128_f)matrixs_aes_decrypt_block;
			xts128_finish(&cp_ctx->c.aes.mode.xts.c,
					input, output, inlen, 0);
			break;
		}

		*outlen = inlen;
		return( 0 );
	}

	return( -1 );
}

////////////////////////////////////////////////////////////////////////////////
int matrixs_ae_setkey(matrixs_cp_context_t *cp_ctx,
		unsigned int kind, unsigned char *key, unsigned int keylen)
{
	if ( cp_ctx != NULL && key != NULL )
	{
		memset(cp_ctx, 0x00, sizeof(matrixs_cp_context_t));

		cp_ctx->kind = kind;
		cp_ctx->keylen = keylen;
		memcpy(cp_ctx->keyval, key, keylen);

		return( 0 );
	}

	return( -1 );
}

int matrixs_ae_starts( matrixs_cp_context_t *cp_ctx,
		 unsigned char *ivec, size_t iveclen,
		size_t taglen, size_t addlen, size_t paylen)
{
	int ret = -1;
	unsigned int M,  L;

	switch ( cp_ctx->kind ) {
	case MATRIXS_AES_GCM:

		/* Initialize AES */
		ret = psAesInitKey( cp_ctx->keyval, cp_ctx->keylen, &cp_ctx->c.aes.ctx);
		if ( ret != PS_SUCCESS) {
			return MATRIXS_ERR_CP_BAD_INPUT_DATA;
		}

		/* Initialize GCM */
		cp_ctx->paylen = paylen;
		cp_ctx->c.aes.mode.gcm.taglen = taglen; // bytes
		gcm128_init( &cp_ctx->c.aes.mode.gcm.c, &cp_ctx->c.aes.ctx,
				(block128_f)matrixs_aes_encrypt_block );
		gcm128_setiv( &cp_ctx->c.aes.mode.gcm.c, ivec, iveclen);

		return( 0 );

	case MATRIXS_AES_CCM:

		/* Initialize AES */
		ret = psAesInitKey( cp_ctx->keyval, cp_ctx->keylen, &cp_ctx->c.aes.ctx);
		if ( ret != PS_SUCCESS) {
			return MATRIXS_ERR_CP_BAD_INPUT_DATA;
		}

		/* Initialize CCM */
		cp_ctx->paylen = paylen;
		cp_ctx->c.aes.mode.ccm.addlen = addlen;	//
		cp_ctx->c.aes.mode.ccm.taglen = taglen; // bytes

		M = taglen; L = (15 - iveclen);
		ccm128_init( &cp_ctx->c.aes.mode.ccm.c, M, L,
				&cp_ctx->c.aes.ctx, (block128_f)matrixs_aes_encrypt_block );
		ccm128_setiv( &cp_ctx->c.aes.mode.ccm.c, ivec, iveclen, paylen);

		return( 0 );
	}

	return( -1 );
}

int matrixs_ae_update_add( matrixs_cp_context_t *cp_ctx,
		 unsigned char *add, size_t addlen)
{
	switch ( cp_ctx->kind ) {
	case MATRIXS_AES_GCM:
		if ( add != NULL && addlen > 0 ) {
			cp_ctx->flags |= 0x01;	// flag(add)
			gcm128_aad( &cp_ctx->c.aes.mode.gcm.c, add, addlen );
		}
		return 0;

	case MATRIXS_AES_CCM:
		// the add length has already been reached ?
		if ( cp_ctx->flags & 0x01 )
			return -2;

		if ( add != NULL && addlen > 0 ) {
			cp_ctx->flags |= 0x01;	// flag(add)
			ccm128_aad( &cp_ctx->c.aes.mode.ccm.c, add, addlen );
		}
		return 0;
	}

	return( -1 );
}

int matrixs_ae_update( matrixs_cp_context_t *cp_ctx,
		int mode,
		unsigned char *input, size_t inlen,
		unsigned char *output, size_t *outlen)
{
	int ret = -1;

	switch ( cp_ctx->kind ) {
	case MATRIXS_AES_GCM:

		switch ( mode ) {
		case MATRIXS_CP_ENCRYPT:
			ret =  gcm128_encrypt( &cp_ctx->c.aes.mode.gcm.c,
					input, output, inlen );
			break;
		case MATRIXS_CP_DECRYPT:
			ret =  gcm128_decrypt( &cp_ctx->c.aes.mode.gcm.c,
					input, output, inlen );
			break;
		}

		if ( ret == 0 ) {*outlen = inlen; cp_ctx->paylen -= inlen;}
		break;

	case MATRIXS_AES_CCM:

		// the payload length has already been reached ?
		if ( cp_ctx->paylen < inlen )
			return( -1 );

		// the required add length has not been provided yet ?
		if ( !( cp_ctx->flags & 0x01 ) )
			return -2;

		switch ( mode ) {
		case MATRIXS_CP_ENCRYPT:
			ret = nistccm128_encrypt_block( &cp_ctx->c.aes.mode.ccm.c,
					input, output, inlen );
			break;
		case MATRIXS_CP_DECRYPT:
			ret = nistccm128_decrypt_block( &cp_ctx->c.aes.mode.ccm.c,
					input, output, inlen );
			break;
		}

		if ( ret == 0 ) {*outlen = inlen; cp_ctx->paylen -= inlen;}
	}

	return( ret );
}

int matrixs_ae_encrypt_finish( matrixs_cp_context_t *cp_ctx,
		unsigned char *input, size_t inlen,
		unsigned char *output, size_t *outlen,
		unsigned char *tag, size_t *taglen )
{
	int ret = -1;

	switch ( cp_ctx->kind ) {
	case MATRIXS_AES_GCM:
		if ( input != NULL && output != NULL ) {
			if ( outlen != NULL && *outlen >= inlen ) {
				ret = gcm128_encrypt( &cp_ctx->c.aes.mode.gcm.c,
						input, output, inlen );
				if ( ret != 0 ) {break;}

				cp_ctx->paylen -= inlen;
				if ( outlen != NULL ) *outlen = inlen;
			}
		}

		/* Get Tag Data */
		if ( tag != NULL && taglen != NULL ) {
			if ( *taglen >= cp_ctx->c.aes.mode.gcm.taglen ) {
				gcm128_tag( &cp_ctx->c.aes.mode.gcm.c, tag,
						  cp_ctx->c.aes.mode.gcm.taglen );
				*taglen = cp_ctx->c.aes.mode.gcm.taglen;

				return( 0 );
			}
		}

		break;

	case MATRIXS_AES_CCM:
		// the payload length has already been reached ?
		if ( cp_ctx->paylen < inlen )
			return( -1 );

		// the required add length has not been provided yet ?
		if ( !( cp_ctx->flags & 0x01 ) )
			return -2;

		ret = nistccm128_encrypt_finish( &cp_ctx->c.aes.mode.ccm.c,
				input, output, inlen );
		if ( ret != 0 ) {break;}

		cp_ctx->paylen -= inlen;
		if ( outlen != NULL ) *outlen = inlen;

		/* Get Tag Data */
		if ( tag != NULL && taglen != NULL ) {
			if ( *taglen >= cp_ctx->c.aes.mode.ccm.taglen ) {
				ccm128_tag(&cp_ctx->c.aes.mode.ccm.c, tag,
						  cp_ctx->c.aes.mode.ccm.taglen );
				*taglen = cp_ctx->c.aes.mode.ccm.taglen;

				return( 0 );
			}
		}

		break;
	}

	return( ret );
}

int matrixs_ae_decrypt_finish( matrixs_cp_context_t *cp_ctx,
		unsigned char *input, size_t inlen,
		unsigned char *output, size_t *outlen,
		unsigned char *tag, size_t taglen )
{
	int ret = -1;

	switch ( cp_ctx->kind ) {
	case MATRIXS_AES_GCM:
		if ( input != NULL && output != NULL ) {
			if ( outlen != NULL && *outlen >= inlen ) {
				ret = gcm128_decrypt( &cp_ctx->c.aes.mode.gcm.c,
						input, output, inlen );
				if ( ret != 0 ) {break;}

				*outlen = inlen;
			}
		}

		if ( tag != NULL && taglen > 0 ) {
			gcm128_tag(&cp_ctx->c.aes.mode.gcm.c, tag, taglen);
		}

		return( 0 );

	case MATRIXS_AES_CCM:
		// the payload length has already been reached ?
		if ( cp_ctx->paylen < inlen )
			return( -1 );

		// the required add length has not been provided yet ?
		if ( !( cp_ctx->flags & 0x01 ) )
			return -2;

		ret = nistccm128_decrypt_finish( &cp_ctx->c.aes.mode.ccm.c,
				input, output, inlen );
		if ( ret != 0 ) {break;}

		cp_ctx->paylen -= inlen;
		if ( outlen != NULL ) *outlen = inlen;

		if ( tag != NULL && taglen > 0 ) {
			ccm128_tag(&cp_ctx->c.aes.mode.ccm.c, tag, taglen);
		}

		return( 0 );
	}

	return( ret );
}

////////////////////////////////////////////////////////////////////////////////
int matrixs_rsa_public(matrixs_rsa_context_t *rsa,
		 unsigned char *input, size_t inlen,
		unsigned char *output, size_t *outlen)
{
	return psRsaCrypt( 0, input, inlen, output, (uint32 *)outlen, &rsa->ctx, PUBKEY_TYPE, 0);
}

int matrixs_rsa_private(matrixs_rsa_context_t *rsa,
		 unsigned char *input, size_t inlen,
		unsigned char *output, size_t *outlen)
{
	return psRsaCrypt( 0, input, inlen, output, (uint32 *)outlen, &rsa->ctx, PRIVKEY_TYPE, 0);
}

int matrixs_oid_get_oid_by_md(matrixs_md_context_t *md_ctx,
		unsigned char **oid, size_t *olen)
{
	switch ( md_ctx->len ) {
	case    MD5_HASH_SIZE:
		*olen = 0x08; *oid = (unsigned char *)"\x2a\x86\x48\x86\xf7\x0d\x02\x05";
		return 0;
	case   SHA1_HASH_SIZE:
		*olen = 0x05; *oid = (unsigned char *)"\x2b\x0e\x03\x02\x1a";
		return 0;
	case SHA224_HASH_SIZE:
		*olen = 0x09; *oid = (unsigned char *)"\x60\x86\x48\x01\x65\x03\x04\x02\x04";
		return 0;
	case SHA256_HASH_SIZE:
		*olen = 0x09; *oid = (unsigned char *)"\x60\x86\x48\x01\x65\x03\x04\x02\x01";
		return 0;
	case SHA384_HASH_SIZE:
		*olen = 0x09; *oid = (unsigned char *)"\x60\x86\x48\x01\x65\x03\x04\x02\x02";
		return 0;
	case SHA512_HASH_SIZE:
		*olen = 0x09; *oid = (unsigned char *)"\x60\x86\x48\x01\x65\x03\x04\x02\x03";
		return 0;
	}

	return( 1 );
}

int matrixs_oid_check_oid_by_md(matrixs_md_context_t *md_ctx,
		unsigned char *oid, size_t oidlen)
{
	switch ( md_ctx->len ) {
	case    MD5_HASH_SIZE:
		return !memcmp(oid, "\x2a\x86\x48\x86\xf7\x0d\x02\x05", oidlen);
	case   SHA1_HASH_SIZE:
		return !memcmp(oid, "\x2b\x0e\x03\x02\x1a", oidlen);
	case SHA224_HASH_SIZE:
		return !memcmp(oid, "\x60\x86\x48\x01\x65\x03\x04\x02\x04", oidlen);
	case SHA256_HASH_SIZE:
		return !memcmp(oid, "\x60\x86\x48\x01\x65\x03\x04\x02\x01", oidlen);
	case SHA384_HASH_SIZE:
		return !memcmp(oid, "\x60\x86\x48\x01\x65\x03\x04\x02\x02", oidlen);
	case SHA512_HASH_SIZE:
		return !memcmp(oid, "\x60\x86\x48\x01\x65\x03\x04\x02\x03", oidlen);
	}

	return 0;
}

void matrixs_mgf_mask( unsigned char *dst, size_t dlen,
		unsigned char *src, size_t slen,
		matrixs_md_context_t *md_ctx )
{
    unsigned char mask[MATRIXS_MD_MAX_SIZE];
    unsigned char counter[4];
    unsigned char *p;
    unsigned int hlen;
    size_t i, use_len;

    memset( mask, 0, MATRIXS_MD_MAX_SIZE );
    memset( counter, 0, 4 );

    hlen = md_ctx->len;

    // Generate and apply dbMask
    //
    p = dst;

    while( dlen > 0 )
    {
        use_len = hlen;
        if( dlen < hlen )
            use_len = dlen;

        matrixs_md_starts( md_ctx );
        matrixs_md_update( md_ctx, src, slen );
        matrixs_md_update( md_ctx, counter, 4 );
        matrixs_md_finish( md_ctx, mask );

        for( i = 0; i < use_len; ++i )
            *p++ ^= mask[i];

        counter[3]++;

        dlen -= use_len;
    }
}

/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-ENCRYPT function
 */
int matrixs_rsa_rsaes_oaep_encrypt(matrixs_rsa_context_t *rsa,
		int mode,  unsigned char *input, size_t inlen,
		unsigned char *label, size_t label_len,
		unsigned char *output, void *p_rng)
{
	size_t olen, hlen;
	unsigned char *p = output;

	olen = rsa->ctx.size;
	hlen = rsa->hash.len;

	if( olen < inlen + 2 * hlen + 2 )
		return( MATRIXS_ERR_RSA_BAD_INPUT_DATA );

	memset( output, 0, olen );

	// EM = 0x00 || maskedSeed || maskedDB
	//
	*p++ = 0;

	// Generate a random octet string seed
	//
	matrixs_random(p_rng, p, hlen);

	p += hlen;

	// Construct DB (DB = lHash || PS || 0x01 || M )
	//
	matrixs_md_starts( &rsa->hash );
	matrixs_md_update( &rsa->hash, label, label_len );
	matrixs_md_finish( &rsa->hash, p );
	p += hlen;
	p += olen - 2 * hlen - 2 - inlen;
	*p++ = 1;
	memcpy( p, input, inlen );

    // maskedDB: Apply dbMask to DB
    //
	matrixs_mgf_mask( output + hlen + 1, olen - hlen - 1, output + 1, hlen,
			&rsa->hash );

    // maskedSeed: Apply seedMask to seed
    //
	matrixs_mgf_mask( output + 1, hlen, output + hlen + 1, olen - hlen - 1,
				&rsa->hash );

	// RSA operation
	//
	return( ( mode == MATRIXS_RSA_PUBLIC )
			? matrixs_rsa_public(  rsa, output, olen, output, &olen )
			: matrixs_rsa_private( rsa, output, olen, output, &olen ) );
}

/*
 * Implementation of the PKCS#1 v2.1 RSAES-OAEP-DECRYPT function
 */
int matrixs_rsa_rsaes_oaep_decrypt( matrixs_rsa_context_t *rsa,
		int mode,  unsigned char *input, size_t inlen,
		unsigned char *label, size_t label_len,
		unsigned char *output, size_t *outlen, void *p_rng )
{
	(void)p_rng;
	int ret;
	size_t ilen, olen, i, pad_count, hlen;
	unsigned char *p, bad, pad_done;
	unsigned char buf[MATRIXS_MPI_MAX_SIZE];
	unsigned char lhash[MATRIXS_MD_MAX_SIZE];

	olen = MATRIXS_MPI_MAX_SIZE;
	ilen = rsa->ctx.size;

	if ( inlen != ilen )
		return( MATRIXS_ERR_RSA_BAD_INPUT_DATA );

	// RSA operation
	//
	ret = ( mode == MATRIXS_RSA_PUBLIC )
		  ? matrixs_rsa_public(  rsa, input, inlen, buf, &olen )
		  : matrixs_rsa_private( rsa, input, inlen, buf, &olen );

	if( ret != 0 )
		return( ret );

	// Unmask data and generate lHash
	//
	hlen = rsa->hash.len;

	matrixs_md_starts( &rsa->hash );
	matrixs_md_update( &rsa->hash, label, label_len );
	matrixs_md_finish( &rsa->hash, lhash );

	// seed: Apply seedMask to maskedSeed
	//
	matrixs_mgf_mask( buf + 1, hlen, buf + hlen + 1, ilen - hlen - 1,
				&rsa->hash );

	// DB: Apply dbMask to maskedDB
	//
	matrixs_mgf_mask( buf + hlen + 1, ilen - hlen - 1, buf + 1, hlen,
				&rsa->hash );

	// Check contents, in "constant-time"
	//
	p = buf;
	bad = 0;

	bad |= *p++; /* First byte must be 0 */
	p += hlen; /* Skip seed */

	// Check lHash
	//
	 for( i = 0; i < hlen; i++ )
		 bad |= lhash[i] ^ *p++;

	// Get zero-padding len, but always read till end of buffer
	// (minus one, for the 01 byte)
	//
	pad_count = 0;
	pad_done = 0;
	for( i = 0; i < ilen - 2 * hlen - 2; i++ )
	{
		pad_done |= p[i];
		pad_count += ((pad_done | (unsigned char)-pad_done) >> 7) ^ 1;
	}

	p += pad_count;
	bad |= *p++ ^ 0x01;

    /*
     * The only information "leaked" is whether the padding was correct or not
     * (eg, no data is copied if it was not correct). This meets the
     * recommendations in PKCS#1 v2.2: an opponent cannot distinguish between
     * the different error conditions.
     */
	if( bad != 0 )
		return( MATRIXS_ERR_RSA_INVALID_PADDING );

	if( ilen - ( p - buf ) > *outlen )
		return( MATRIXS_ERR_RSA_OUTPUT_TOO_LARGE );

	*outlen = ilen - (p - buf);
	memcpy( output, p, *outlen );

	return( 0 );
}

/*
 * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-ENCRYPT function
 */
int matrixs_rsa_rsaes_pkcs1_v15_encrypt( matrixs_rsa_context_t *rsa,
		int mode,  unsigned char *input, size_t inlen,
		unsigned char *output, void *p_rng)
{
	(void)p_rng;
	size_t nb_pad, olen;
	unsigned char *p = output;

	olen = rsa->ctx.size;

	if( olen < inlen + 11 )
		return( MATRIXS_ERR_RSA_BAD_INPUT_DATA );

	nb_pad = olen - 3 - inlen;

	*p++ = 0;
	if( mode == MATRIXS_RSA_PUBLIC )
	{
		*p++ = MATRIXS_RSA_CRYPT;

		// Generate a random octet string seed
		//
		matrixs_random(p_rng, p, nb_pad);

		// SECURITY:  Read through the random data and change all 0x0 to 0x01.
		// This is per spec that no random bytes should be 0
		//
		while ( nb_pad-- > 0 ) {
			if ( *p == 0x00 ) *p = 0x01;
			p++;
		}
	}
	else
	{
		*p++ = MATRIXS_RSA_SIGN;

		while( nb_pad-- > 0 )
			*p++ = 0xFF;
	}

	*p++ = 0;
	memcpy( p, input, inlen );

	// RSA operation
	//
	return( ( mode == MATRIXS_RSA_PUBLIC )
			? matrixs_rsa_public(  rsa, output, olen, output, &olen )
			: matrixs_rsa_private( rsa, output, olen, output, &olen ) );
}

/*
 * Implementation of the PKCS#1 v2.1 RSAES-PKCS1-V1_5-DECRYPT function
 */
int matrixs_rsa_rsaes_pkcs1_v15_decrypt(matrixs_rsa_context_t *rsa,
		int mode,  unsigned char *input, size_t inlen,
		unsigned char *output, size_t *outlen, void *p_rng)
{
	(void)p_rng;
	int ret;
	size_t ilen, olen, i, pad_count = 0;
	unsigned char *p, bad, pad_done = 0;
	unsigned char buf[MATRIXS_MPI_MAX_SIZE];
	//unsigned char lhash[MATRIXS_MD_MAX_SIZE];

	olen = MATRIXS_MPI_MAX_SIZE;
	ilen = rsa->ctx.size;

	if ( inlen != ilen )
		return( MATRIXS_ERR_RSA_BAD_INPUT_DATA );

	// RSA operation
	//
	ret = ( mode == MATRIXS_RSA_PUBLIC )
		  ? matrixs_rsa_public(  rsa, input, inlen, buf, &olen )
		  : matrixs_rsa_private( rsa, input, inlen, buf, &olen );

	if( ret != 0 )
		return( ret );

	p = buf;
	bad = 0;

	// Check and get padding len in "constant-time"
	//
	bad |= *p++; /* First byte must be 0 */

	// This test does not depend on secret data
	//
	if( mode == MATRIXS_RSA_PRIVATE )
	{
		bad |= *p++ ^ MATRIXS_RSA_CRYPT;

		/* Get padding len, but always read till end of buffer
		 * (minus one, for the 00 byte) */
		for( i = 0; i < ilen - 3; i++ )
		{
			pad_done  |= ((p[i] | (unsigned char)-p[i]) >> 7) ^ 1;
			pad_count += ((pad_done | (unsigned char)-pad_done) >> 7) ^ 1;
		}

		p += pad_count;
		bad |= *p++; /* Must be zero */
	}
	else
	{
		bad |= *p++ ^ MATRIXS_RSA_SIGN;

		/* Get padding len, but always read till end of buffer
		 * (minus one, for the 00 byte) */
		for( i = 0; i < ilen - 3; i++ )
		{
			pad_done |= ( p[i] != 0xFF );
			pad_count += ( pad_done == 0 );
		}

		p += pad_count;
		bad |= *p++; /* Must be zero */
	}

	if( bad )
		return( MATRIXS_ERR_RSA_INVALID_PADDING );

	if( ilen - ( p - buf ) > *outlen )
		return( MATRIXS_ERR_RSA_OUTPUT_TOO_LARGE );

	*outlen = ilen - (p - buf);
	memcpy( output, p, *outlen );

	return( 0 );
}

/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PSS-SIGN function
 */
int matrixs_rsa_rsassa_pss_sign(matrixs_rsa_context_t *rsa,
		int mode, unsigned char *hash, size_t hashlen,
		unsigned char *salt, size_t saltlen,
		unsigned char *sig, void *p_rng)
{
	(void)p_rng;
	size_t olen, msb;
	unsigned char *p = sig;
	unsigned char saltdat[MATRIXS_MD_MAX_SIZE];
	unsigned int slen, hlen, offset = 0;

	olen = rsa->ctx.size;
	hlen = rsa->hash.len;
	slen = (saltlen)?(saltlen):(hlen);

	if( olen < hlen + slen + 2 )
		return( MATRIXS_ERR_RSA_BAD_INPUT_DATA );

	memset( sig, 0, olen );

    // Generate salt of length slen
    //
	if ( salt ) {
		memcpy( saltdat, salt, slen );
	} else {
		matrixs_random(p_rng, saltdat, slen );
	}

    // Note: EMSA-PSS encoding is over the length of N - 1 bits
    //
	msb = pstm_count_bits( &rsa->ctx.N ) - 1;
	p += olen - hlen - slen - 2;
	*p++ = 0x01;
	memcpy( p, saltdat, slen );
	p += slen;

    // Generate H = Hash( M' )
    //
	matrixs_md_starts( &rsa->hash );
	matrixs_md_update( &rsa->hash, p, 8 );
	matrixs_md_update( &rsa->hash, hash, hashlen );
	matrixs_md_update( &rsa->hash, saltdat, slen );
	matrixs_md_finish( &rsa->hash, p );

    // Compensate for boundary condition when applying mask
    //
	if( msb % 8 == 0 )
		offset = 1;

    // maskedDB: Apply dbMask to DB
    //
	matrixs_mgf_mask( sig + offset, olen - hlen - 1 - offset, p, hlen,
			&rsa->hash );

	msb = pstm_count_bits( &rsa->ctx.N ) - 1;
	sig[0] &= 0xFF >> ( olen * 8 - msb );

	p += hlen;
	*p++ = 0xBC;

	// RSA operation
	//
	return( ( mode == MATRIXS_RSA_PUBLIC )
			? matrixs_rsa_public(  rsa, sig, olen, sig, &olen )
			: matrixs_rsa_private( rsa, sig, olen, sig, &olen ) );
}

int matrixs_rsa_rsassa_pss_verify(matrixs_rsa_context_t *rsa,
		int mode,  unsigned char *hash, size_t hashlen,
		unsigned char *salt, size_t saltlen,
		unsigned char *sig, void *p_rng)
{
	(void)p_rng;
	int ret;
	size_t siglen, olen, slen, hlen, msb;
	unsigned char *p;
	unsigned char buf[MATRIXS_MPI_MAX_SIZE];
	unsigned char result[MATRIXS_MD_MAX_SIZE];
	unsigned char saltdat[MATRIXS_MD_MAX_SIZE];
	unsigned char zeros[8];

	olen = MATRIXS_MPI_MAX_SIZE;
	siglen = rsa->ctx.size;

	// Generate salt of length slen
	//
	if ( salt )
	{
		memcpy(saltdat, salt, saltlen );
	}

	// RSA operation
	//
	ret = ( mode == MATRIXS_RSA_PUBLIC )
			? matrixs_rsa_public(  rsa, sig, siglen, buf, &olen )
			: matrixs_rsa_private( rsa, sig, siglen, buf, &olen );

	if( ret != 0 )
		return( ret );

	p = buf;

	if( buf[siglen - 1] != 0xBC )
		return( MATRIXS_ERR_RSA_INVALID_PADDING );

	hlen = rsa->hash.len;
	slen = siglen - hlen - 1; /* Currently length of salt + padding */

	memset( zeros, 0, 8 );

	// Note: EMSA-PSS verification is over the length of N - 1 bits
	//
	msb = pstm_count_bits( &rsa->ctx.N ) - 1;

	// Compensate for boundary condition when applying mask
	//
	if( msb % 8 == 0 )
	{
		p++;
		siglen -= 1;
	}
	if( buf[0] >> ( 8 - siglen * 8 + msb ) )
		return( MATRIXS_ERR_RSA_BAD_INPUT_DATA );

	matrixs_mgf_mask( p, siglen - hlen - 1, p + siglen - hlen - 1, hlen,
				&rsa->hash );

	buf[0] &= 0xFF >> ( siglen * 8 - msb );

	while( p < buf + siglen && *p == 0 )
		p++;

	if( p == buf + siglen || *p++ != 0x01 )
		return( MATRIXS_ERR_RSA_INVALID_PADDING );

	/* Actual salt len */
	slen -= p - buf;

	if ( salt )
	{
		if (slen != hlen || memcmp(p, saltdat, slen) != 0)
			return( MATRIXS_ERR_RSA_VERIFY_FAILED );
	}

    // Generate H = Hash( M' )
    //
	matrixs_md_starts( &rsa->hash );
	matrixs_md_update( &rsa->hash, zeros, 8 );
	matrixs_md_update( &rsa->hash, hash, hashlen );
	matrixs_md_update( &rsa->hash, p, slen );
	matrixs_md_finish( &rsa->hash, result );


	if( memcmp( p + slen, result, hlen ) != 0 )
		return( MATRIXS_ERR_RSA_VERIFY_FAILED );

	return( 0 );
}

/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-V1_5-SIGN function
 */
int matrixs_rsa_rsassa_pkcs1_v15_sign(matrixs_rsa_context_t *rsa,
		int mode,  unsigned char *hash, size_t hashlen,
		unsigned char *sig, void *p_rng)
{
	(void)p_rng;
	size_t nb_pad, olen, oid_size = 0;
	unsigned char *p = sig;
	unsigned char *oid = NULL;

	olen = rsa->ctx.size;
	nb_pad = olen - 3;

	if ( matrixs_md_valid( &rsa->hash ) ) {

		if ( matrixs_oid_get_oid_by_md( &rsa->hash, &oid, &oid_size) != 0 )
			return( MATRIXS_ERR_RSA_BAD_INPUT_DATA );

		nb_pad -= 10 + oid_size;
		hashlen = rsa->hash.len;
	}

	nb_pad -= hashlen;
	if( ( nb_pad < 8 ) || ( nb_pad > olen ) )
		return( MATRIXS_ERR_RSA_BAD_INPUT_DATA );

	*p++ = 0;
	*p++ = MATRIXS_RSA_SIGN;
	memset( p, 0xFF, nb_pad );
	p += nb_pad;
	*p++ = 0;

	if ( !matrixs_md_valid( &rsa->hash ) )
	{
		memcpy( p, hash, hashlen );
	}
	else
	{
	   /*
		 * DigestInfo ::= SEQUENCE {
		 *   digestAlgorithm DigestAlgorithmIdentifier,
		 *   digest Digest }
		 *
		 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
		 *
		 * Digest ::= OCTET STRING
		 */
		*p++ = MATRIXS_ASN1_SEQUENCE | MATRIXS_ASN1_CONSTRUCTED;
		*p++ = (unsigned char) ( 0x08 + oid_size + hashlen );
		*p++ = MATRIXS_ASN1_SEQUENCE | MATRIXS_ASN1_CONSTRUCTED;
		*p++ = (unsigned char) ( 0x04 + oid_size );
		*p++ = MATRIXS_ASN1_OID;
		*p++ = oid_size & 0xFF;
		memcpy( p, oid, oid_size );
		p += oid_size;
		*p++ = MATRIXS_ASN1_NULL;
		*p++ = 0x00;
		*p++ = MATRIXS_ASN1_OCTET_STRING;
		*p++ = hashlen;
		memcpy( p, hash, hashlen );
	}

	// RSA operation
	//
	return( ( mode == MATRIXS_RSA_PUBLIC )
			? matrixs_rsa_public(  rsa, sig, olen, sig, &olen )
			: matrixs_rsa_private( rsa, sig, olen, sig, &olen ) );
}

/*
 * Implementation of the PKCS#1 v2.1 RSASSA-PKCS1-v1_5-VERIFY function
 */
int matrixs_rsa_rsassa_pkcs1_v15_verify(matrixs_rsa_context_t *rsa,
		int mode,  unsigned char *hash, size_t hashlen,
		unsigned char *sig, void *p_rng)
{
	(void)p_rng;
	int ret;
	size_t len, siglen, olen, asn1_oid_len;
	unsigned char *p, *end;
	unsigned char buf[MATRIXS_MPI_MAX_SIZE];

	olen = MATRIXS_MPI_MAX_SIZE;
	siglen = rsa->ctx.size;

	// RSA operation
	//
	ret = ( mode == MATRIXS_RSA_PUBLIC )
			? matrixs_rsa_public(  rsa, sig, siglen, buf, &olen )
			: matrixs_rsa_private( rsa, sig, siglen, buf, &olen );

	if( ret != 0 )
		return( ret );

	p = buf;

	if( *p++ != 0 || *p++ != MATRIXS_RSA_SIGN )
		return( MATRIXS_ERR_RSA_INVALID_PADDING );

	while( *p != 0 )
	{
		if( p >= buf + siglen - 1 || *p != 0xFF )
			return( MATRIXS_ERR_RSA_INVALID_PADDING );
		p++;
	}
	p++;

	len = siglen - ( p - buf );
	if( len == hashlen && !matrixs_md_valid( &rsa->hash ) )
	{
		if( memcmp( p, hash, hashlen ) == 0 )
			return( 0 );
		else
			return( MATRIXS_ERR_RSA_VERIFY_FAILED );
	}

	hashlen = rsa->hash.len;

	end = p + len;

	// Parse the ASN.1 structure inside the PKCS#1 v1.5 structure
	//
	if ( p > end ||
		*p++ != (MATRIXS_ASN1_SEQUENCE | MATRIXS_ASN1_CONSTRUCTED) )
		return( MATRIXS_ERR_RSA_VERIFY_FAILED );

	if ( p > end ||
		*p++ != len - 2 )
		return( MATRIXS_ERR_RSA_VERIFY_FAILED );

	if ( p > end ||
		*p++ != (MATRIXS_ASN1_SEQUENCE | MATRIXS_ASN1_CONSTRUCTED) )
		return( MATRIXS_ERR_RSA_VERIFY_FAILED );

	if ( p > end ||
		*p++ != len - 6 - hashlen )
		return( MATRIXS_ERR_RSA_VERIFY_FAILED );

	if ( p > end ||
		*p++ != (MATRIXS_ASN1_OID) )
		return( MATRIXS_ERR_RSA_VERIFY_FAILED );

	if ( p > end )
		return( MATRIXS_ERR_RSA_VERIFY_FAILED );

	asn1_oid_len = *p++;

	if ( p > end - asn1_oid_len ||
		!matrixs_oid_check_oid_by_md(&rsa->hash, p, asn1_oid_len) )
		return( MATRIXS_ERR_RSA_VERIFY_FAILED );

	p += asn1_oid_len;
    /*
     * assume the algorithm parameters must be NULL
     */
	if ( p > end ||
		*p++ != (MATRIXS_ASN1_NULL) )
		return( MATRIXS_ERR_RSA_VERIFY_FAILED );

	if ( p > end ||
		*p++ != 0x00 )
		return( MATRIXS_ERR_RSA_VERIFY_FAILED );

	if ( p > end ||
		*p++ != (MATRIXS_ASN1_OCTET_STRING) )
		return( MATRIXS_ERR_RSA_VERIFY_FAILED );

	if ( p > end ||
		*p++ != hashlen )
		return( MATRIXS_ERR_RSA_VERIFY_FAILED );

	if ( p > end - hashlen ||
		memcmp( p, hash, hashlen ) != 0 )
		return( MATRIXS_ERR_RSA_VERIFY_FAILED );

	p += hashlen;

	if( p != end )
		return( MATRIXS_ERR_RSA_VERIFY_FAILED );

	return( 0 );
}


int matrixs_dsa_sign(matrixs_dsa_context_t *dsa,
		unsigned char *hash, size_t hashlen,
		unsigned char *sig, size_t *siglen, void *p_rng)
{
	int ret;
	size_t rlen, slen;
	unsigned char *p = sig;
	unsigned char r[64], s[64];

	if ( hash == NULL || hashlen <= 0 ||
		 sig  == NULL || siglen  == NULL || *siglen < 40 ) {
		return( MATRIXS_ERR_DSA_SIGN_FAILED );
	}

	ret = psDsaSignHash(0, &dsa->ctx, &dsa->params,
			hash, hashlen, &dsa->sign, p_rng);
	if ( ret < PS_SUCCESS ) {
		return( MATRIXS_ERR_DSA_SIGN_FAILED );
	}

	rlen = pstm_unsigned_bin_size( &dsa->sign.r );
	pstm_to_unsigned_bin( 0, &dsa->sign.r, r);
	slen = pstm_unsigned_bin_size( &dsa->sign.s );
	pstm_to_unsigned_bin( 0, &dsa->sign.s, s);

#if 0
	*p++ = MATRIXS_ASN1_SEQUENCE | MATRIXS_ASN1_CONSTRUCTED;
	*p++ = (unsigned char) ( 0x04 + rlen + slen );
	*p++ = MATRIXS_ASN1_INTEGER;
	*p++ = (unsigned char) ( rlen & 0xFF );
	 memcpy(p, r, rlen);
	*p++ = MATRIXS_ASN1_INTEGER;
	*p++ = (unsigned char) ( slen & 0xFF );
	 memcpy(p, s, slen);

	 *siglen = ( 0x06 + rlen + slen );
#else

	memcpy( p +    0, r, rlen );
	memcpy( p + rlen, s, slen );

	*siglen = (rlen + slen );
#endif

	return( 0 );
}

int matrixs_dsa_verify(matrixs_dsa_context_t *dsa,
		unsigned char *hash, size_t hashlen,
		unsigned char *sig, size_t siglen, void *p_rng)
{
	psDsaSign_t sign;

#if 0

	size_t rlen, slen;
	unsigned char *p = sig, *end = sig + siglen;

	// Parse the ASN.1 structure
	//
	if ( p > end ||
		*p++ != (MATRIXS_ASN1_SEQUENCE | MATRIXS_ASN1_CONSTRUCTED) )
		return( MATRIXS_ERR_DSA_VERIFY_FAILED );

	if ( p > end ||
		*p++ != siglen - 2 )
		return( MATRIXS_ERR_DSA_VERIFY_FAILED );

	if ( p > end ||
		*p++ != (MATRIXS_ASN1_INTEGER) )
		return( MATRIXS_ERR_DSA_VERIFY_FAILED );

	rlen = *p++;
	if ( p > end - rlen )
		return( MATRIXS_ERR_DSA_VERIFY_FAILED );

	pstm_init_for_read_unsigned_bin(0, &sign.r, rlen);
	pstm_read_unsigned_bin(&sign.r, p, rlen);
	p += rlen;

	slen = *p++;
	if ( p > end - slen )
		return( MATRIXS_ERR_DSA_VERIFY_FAILED );

	pstm_init_for_read_unsigned_bin(0, &sign.s, slen);
	pstm_read_unsigned_bin(&sign.s, p, slen);
	p += slen;
#else

	if ( hash == NULL || hashlen <= 0 ||
		 sig  == NULL || siglen  != 40 ) {
		return( MATRIXS_ERR_DSA_VERIFY_FAILED );
	}

	pstm_init_for_read_unsigned_bin(0, &sign.r, 20);
	pstm_read_unsigned_bin(&sign.r, &sig[0], 20);
	pstm_init_for_read_unsigned_bin(0, &sign.s, 20);
	pstm_read_unsigned_bin(&sign.s, &sig[20], 20);

#endif

	return psDsaVerifyHash( 0, &dsa->ctx,
			&dsa->params, hash, hashlen, &sign);
}
