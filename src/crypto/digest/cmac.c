/**
 *	@file    hmac.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	HMAC implementation.
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

/******************************************************************************/
#ifdef USE_CMAC

/******************************************************************************/

#if !defined(USE_AES)
	#error "Must enable USE_AES for USE_CMAC"
#endif

/* For CMAC Calculation */
unsigned char const_Rb[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
};

unsigned char const_Zero[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Basic Functions */
static void xor_128(unsigned char *a, unsigned char *b, unsigned char *out)
{
	int i;
	for (i = 0; i < 16; i++) {
		out[i] = a[i] ^ b[i];
	}
}

static void leftshift_onebit(unsigned char *in, unsigned char *out)
 {
	int32				i;
	unsigned char 		of = 0;

	for ( i = 15; i >= 0; i-- ) {
		out[i]  = in[i] << 1;
		out[i] |= of;
		of = (in[i] & 0x80) ? (1) : (0);
	}

	return;
 }

static void padding(unsigned char *lastb, unsigned char *pad, int length)
{
	int32				i;

	for ( i = 0; i < 16; i++ ) {
		if ( i < length ) {
			pad[i] = lastb[i];
		} else if ( i == length ) {
			pad[i] = 0x80;
		} else {
			pad[i] = 0x00;
		}
	}
}

static int32 psGenerateSubKey(psCmacContext_t *ctx, unsigned char *K1, unsigned char *K2)
{
	unsigned char 		L[16] = {0};
	unsigned char 		Z[16] = {0};
	unsigned char 		tmp[16] = {0};

	psAesEncryptBlock(Z, L, &ctx->u.aes.aes.key);

	if ( (L[0] & 0x80) == 0 ) { /* If MSB(L) = 0, then K1 = L << 1 */
		leftshift_onebit(L, K1);
	} else { /* Else K1 = ( L << 1 ) (+) Rb */
		leftshift_onebit(L, tmp);
		xor_128(tmp, const_Rb, K1);
	}
	if ( (K1[0] & 0x80) == 0 ) {
		leftshift_onebit(K1, K2);
	} else {
		leftshift_onebit(K1, tmp);
		xor_128(tmp, const_Rb, K2);
	}

	return PS_SUCCESS;
}

/* AES-128-CMAC */
int32 psCmacAesInit(psCmacContext_t *ctx, unsigned char *key,
				uint32  klen)
{
	int32				err = PS_FAILURE;

	if ((ctx == NULL) || (key == NULL)) {
		psTraceCrypto("FAILED:  incorrect parameters\n");
		return err;
	}

	/* AES initialize */
	memset(ctx, 0x00, sizeof(psCmacContext_t));
	err = psAesInitKey(key, klen, &ctx->u.aes.aes.key);
	if (err < PS_SUCCESS) {
		psTraceIntCrypto("FAILED:  psAesInitKey returned %d\n", err);
		return err;
	}

	ctx->u.aes.aes.blocklen = 16;
	memcpy(ctx->u.aes.aes.IV, const_Zero, 16);

	/* Generate sub-key */
	err = psGenerateSubKey(ctx, ctx->k1, ctx->k2);
	if (err < PS_SUCCESS) {
		psTraceIntCrypto("FAILED:  psGenerateSubKey returned %d\n", err);
		return err;
	}

	return PS_SUCCESS;
}

int32 psCmacAesInit2(psCmacContext_t *ctx, unsigned char *key,
				uint32  klen, unsigned char *ivec, uint32 iveclen)
{
	int32				err = PS_FAILURE;

	if ((ctx == NULL) || (key == NULL) ||
		(ivec == NULL) || iveclen != 16) {
		psTraceCrypto("FAILED:  incorrect parameters\n");
		return err;
	}

	/* AES initialize */
	memset(ctx, 0x00, sizeof(psCmacContext_t));
	err = psAesInitKey(key, klen, &ctx->u.aes.aes.key);
	if (err < PS_SUCCESS) {
		psTraceIntCrypto("FAILED:  psAesInitKey returned %d\n", err);
		return err;
	}

	ctx->u.aes.aes.blocklen = 16;
	memcpy(ctx->u.aes.aes.IV, ivec, iveclen);

	/* Generate sub-key */
	err = psGenerateSubKey(ctx, ctx->k1, ctx->k2);
	if (err < PS_SUCCESS) {
		psTraceIntCrypto("FAILED:  psGenerateSubKey returned %d\n", err);
		return err;
	}

	return PS_SUCCESS;
}

int32 psCmacAesUpdate(psCmacContext_t *ctx, unsigned char *data,
				uint32  dlen)
{
	int32				c1 = 0;
	unsigned char		Y[16] = {0};

	if (ctx->last_len > 0) {
		c1 = 16 - ctx->last_len;
		if (dlen < c1) c1 = dlen;

		memcpy(&ctx->last[ctx->last_len], data, c1);

		dlen -= c1; ctx->last_len += c1;
		if (dlen == 0) return PS_SUCCESS;

		data += c1;

		xor_128(ctx->u.aes.aes.IV, ctx->last, Y); /* Y := Mi (+) X */
		psAesEncryptBlock(Y, ctx->u.aes.aes.IV, &ctx->u.aes.aes.key); /* X := AES-128(KEY, Y); */
	}

	/* Encrypt all but one of the complete blocks left */
	while(dlen > 16) {
		xor_128(ctx->u.aes.aes.IV, data, Y); /* Y := Mi (+) X */
		psAesEncryptBlock(Y, ctx->u.aes.aes.IV, &ctx->u.aes.aes.key); /* X := AES-128(KEY, Y); */
		dlen -= 16; data += 16;
	}

	/* Copy any data left to last block buffer */
	memcpy(ctx->last, data, dlen);
	ctx->last_len = dlen;

	return PS_SUCCESS;
}

int32 psCmacAesFinal(psCmacContext_t *ctx, unsigned char *out,
				uint32 *olen)
{
	int32				i = 0;
	unsigned char		Y[16] = {0};
	unsigned char		M_last[16] = {0};
	unsigned char		padded[16] = {0};

	if (ctx->last_len == 16) {
		xor_128(ctx->last, ctx->k1, M_last);
	} else {
		padding(ctx->last, padded, ctx->last_len);
		xor_128(padded, ctx->k2, M_last);
	}

	xor_128(ctx->u.aes.aes.IV, M_last, Y); /* Y := Mi (+) X */
	psAesEncryptBlock(Y, ctx->u.aes.aes.IV, &ctx->u.aes.aes.key); /* X := AES-128(KEY, Y); */

	for (i = 0; i < 16; i++) {
		out[i] = ctx->u.aes.aes.IV[i];
	}
	*olen = 16;

	return PS_SUCCESS;
}

#endif
