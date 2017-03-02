/**
 *	@file    ccm.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	AES CCM block cipher implementation.
 *	( Counter with CBC-MAC)
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
#include "../../cryptoApi.h"

/* First you setup M and L parameters and pass the key schedule.
 * This is called once per session setup... */
void ccm128_init(struct ccm128_context *ctx,
	unsigned int M, unsigned int L, void *key,block128_f block)
{
	memset(ctx->nonce.c,0,sizeof(ctx->nonce.c));
	ctx->nonce.c[0] = ((u8)(L-1)&7) | (u8)(((M-2)/2)&7)<<3;
	ctx->blocks = 0;
	ctx->block = block;
	ctx->key = key;
	ctx->flags0 = ctx->flags1 = 0;
}

/* !!! Following interfaces are to be called *once* per packet !!! */

/* Then you setup per-message nonce and pass the length of the message */
int ccm128_setiv(struct ccm128_context *ctx,
	const unsigned char *nonce, size_t nlen, size_t mlen)
{
	unsigned int L = ctx->nonce.c[0]&7;	/* the L parameter */

	if (nlen<(14-L)) return -1;		/* nonce is too short */

	ctx->paylen = mlen;

	if (sizeof(mlen)==8 && L>=3) {
		ctx->nonce.c[8]  = (u8)(mlen>>(56%(sizeof(mlen)*8)));
		ctx->nonce.c[9]  = (u8)(mlen>>(48%(sizeof(mlen)*8)));
		ctx->nonce.c[10] = (u8)(mlen>>(40%(sizeof(mlen)*8)));
		ctx->nonce.c[11] = (u8)(mlen>>(32%(sizeof(mlen)*8)));
	}
	else
		*(u32*)(&ctx->nonce.c[8]) = 0;

	ctx->nonce.c[12] = (u8)(mlen>>24);
	ctx->nonce.c[13] = (u8)(mlen>>16);
	ctx->nonce.c[14] = (u8)(mlen>>8);
	ctx->nonce.c[15] = (u8)mlen;

	ctx->nonce.c[0] &= ~0x40;	/* clear Adata flag */
	memcpy(&ctx->nonce.c[1],nonce,14-L);

	return 0;
}

/* Then you pass additional authentication data, this is optional */
void ccm128_aad(struct ccm128_context *ctx,
	const unsigned char *aad, size_t alen)
{
	unsigned int i;
	block128_f block = ctx->block;

	if (alen==0) return;

	ctx->nonce.c[0] |= 0x40;	/* set Adata flag */
	(*block)(ctx->nonce.c,ctx->cmac.c,ctx->key),
	ctx->blocks++;

	if (alen<(0x10000-0x100)) {
		ctx->cmac.c[0] ^= (u8)(alen>>8);
		ctx->cmac.c[1] ^= (u8)alen;
		i=2;
	}
	else if (sizeof(alen)==8 && alen>=(size_t)1<<(32%(sizeof(alen)*8)))
	{
		ctx->cmac.c[0] ^= 0xFF;
		ctx->cmac.c[1] ^= 0xFF;
		ctx->cmac.c[2] ^= (u8)(alen>>(56%(sizeof(alen)*8)));
		ctx->cmac.c[3] ^= (u8)(alen>>(48%(sizeof(alen)*8)));
		ctx->cmac.c[4] ^= (u8)(alen>>(40%(sizeof(alen)*8)));
		ctx->cmac.c[5] ^= (u8)(alen>>(32%(sizeof(alen)*8)));
		ctx->cmac.c[6] ^= (u8)(alen>>24);
		ctx->cmac.c[7] ^= (u8)(alen>>16);
		ctx->cmac.c[8] ^= (u8)(alen>>8);
		ctx->cmac.c[9] ^= (u8)alen;
		i=10;
	}
	else
	{
		ctx->cmac.c[0] ^= 0xFF;
		ctx->cmac.c[1] ^= 0xFE;
		ctx->cmac.c[2] ^= (u8)(alen>>24);
		ctx->cmac.c[3] ^= (u8)(alen>>16);
		ctx->cmac.c[4] ^= (u8)(alen>>8);
		ctx->cmac.c[5] ^= (u8)alen;
		i=6;
	}

	do {
		for(;i<16 && alen;++i,++aad,--alen)
			ctx->cmac.c[i] ^= *aad;

		(*block)(ctx->cmac.c,ctx->cmac.c,ctx->key),
		ctx->blocks++;
		i=0;
	} while (alen);
}

/* Finally you encrypt or decrypt the message */

/* counter part of nonce may not be larger than L*8 bits,
 * L is not larger than 8, therefore 64-bit counter... */
static void ctr64_inc(unsigned char *counter) {

	unsigned int n=8;
	u8  c;

	counter += 8;
	do {
		--n;
		c = counter[n];
		++c;
		counter[n] = c;
		if (c) return;
	} while (n);
}

int ccm128_encrypt(struct ccm128_context *ctx,
	const unsigned char *inp, unsigned char *out, size_t len)
{
	size_t		n;
	unsigned int	i,L;
	unsigned char	flags0	= ctx->nonce.c[0];
	block128_f	block	= ctx->block;
	void *		key	= ctx->key;
	union { u64 u[2]; u8 c[16]; } scratch;

	if (!(flags0&0x40))
		(*block)(ctx->nonce.c,ctx->cmac.c,key),
		ctx->blocks++;

	ctx->nonce.c[0] = L = flags0&7;
	for (n=0,i=15-L;i<15;++i) {
		n |= ctx->nonce.c[i];
		ctx->nonce.c[i]=0;
		n <<= 8;
	}
	n |= ctx->nonce.c[15];	/* reconstructed length */
	ctx->nonce.c[15]=1;

	if (n!=len) return -1;	/* length mismatch */

	ctx->blocks += ((len+15)>>3)|1;
	if (ctx->blocks > (U64(1)<<61))	return -2; /* too much data */

	while (len>=16) {
		ctx->cmac.u[0] ^= ((u64*)inp)[0];
		ctx->cmac.u[1] ^= ((u64*)inp)[1];

		(*block)(ctx->cmac.c,ctx->cmac.c,key);
		(*block)(ctx->nonce.c,scratch.c,key);
		ctr64_inc(ctx->nonce.c);

		((u64*)out)[0] = scratch.u[0]^((u64*)inp)[0];
		((u64*)out)[1] = scratch.u[1]^((u64*)inp)[1];

		inp += 16;
		out += 16;
		len -= 16;
	}

	if (len) {
		for (i=0; i<len; ++i) ctx->cmac.c[i] ^= inp[i];
		(*block)(ctx->cmac.c,ctx->cmac.c,key);
		(*block)(ctx->nonce.c,scratch.c,key);
		for (i=0; i<len; ++i) out[i] = scratch.c[i]^inp[i];
	}

	for (i=15-L;i<16;++i)
		ctx->nonce.c[i]=0;

	(*block)(ctx->nonce.c,scratch.c,key);
	ctx->cmac.u[0] ^= scratch.u[0];
	ctx->cmac.u[1] ^= scratch.u[1];

	ctx->nonce.c[0] = flags0;

	return 0;
}

int ccm128_decrypt(struct ccm128_context *ctx,
	const unsigned char *inp, unsigned char *out, size_t len)
{
	size_t		n;
	unsigned int	i,L;
	unsigned char	flags0	= ctx->nonce.c[0];
	block128_f	block	= ctx->block;
	void *		key	= ctx->key;
	union { u64 u[2]; u8 c[16]; } scratch;

	if (!(flags0&0x40))
		(*block)(ctx->nonce.c,ctx->cmac.c,key);

	ctx->nonce.c[0] = L = flags0&7;
	for (n=0,i=15-L;i<15;++i) {
		n |= ctx->nonce.c[i];
		ctx->nonce.c[i]=0;
		n <<= 8;
	}
	n |= ctx->nonce.c[15];	/* reconstructed length */
	ctx->nonce.c[15]=1;

	if (n!=len) return -1;

	while (len>=16) {

		(*block)(ctx->nonce.c,scratch.c,key);
		ctr64_inc(ctx->nonce.c);

		ctx->cmac.u[0] ^= (((u64*)out)[0] = scratch.u[0]^((u64*)inp)[0]);
		ctx->cmac.u[1] ^= (((u64*)out)[1] = scratch.u[1]^((u64*)inp)[1]);

		(*block)(ctx->cmac.c,ctx->cmac.c,key);

		inp += 16;
		out += 16;
		len -= 16;
	}

	if (len) {
		(*block)(ctx->nonce.c,scratch.c,key);
		for (i=0; i<len; ++i)
			ctx->cmac.c[i] ^= (out[i] = scratch.c[i]^inp[i]);
		(*block)(ctx->cmac.c,ctx->cmac.c,key);
	}

	for (i=15-L;i<16;++i)
		ctx->nonce.c[i]=0;

	(*block)(ctx->nonce.c,scratch.c,key);
	ctx->cmac.u[0] ^= scratch.u[0];
	ctx->cmac.u[1] ^= scratch.u[1];

	ctx->nonce.c[0] = flags0;

	return 0;
}

static void ctr64_add (unsigned char *counter,size_t inc) {

	size_t n=8, val=0;

	counter += 8;
	do {
		--n;
		val += counter[n] + (inc&0xff);
		counter[n] = (unsigned char)val;
		val >>= 8;	/* carry bit */
		inc >>= 8;
	} while(n && (inc || val));
}

int ccm128_encrypt_ccm64(struct ccm128_context *ctx,
	const unsigned char *inp, unsigned char *out, size_t len,
	ccm128_f stream)
{
	size_t		n;
	unsigned int	i,L;
	unsigned char	flags0	= ctx->nonce.c[0];
	block128_f	block	= ctx->block;
	void *		key	= ctx->key;
	union { u64 u[2]; u8 c[16]; } scratch;

	if (!(flags0&0x40))
		(*block)(ctx->nonce.c,ctx->cmac.c,key),
		ctx->blocks++;

	ctx->nonce.c[0] = L = flags0&7;
	for (n=0,i=15-L;i<15;++i) {
		n |= ctx->nonce.c[i];
		ctx->nonce.c[i]=0;
		n <<= 8;
	}
	n |= ctx->nonce.c[15];	/* reconstructed length */
	ctx->nonce.c[15]=1;

	if (n!=len) return -1;	/* length mismatch */

	ctx->blocks += ((len+15)>>3)|1;
	if (ctx->blocks > (U64(1)<<61))	return -2; /* too much data */

	if ((n=len/16)) {
		(*stream)(inp,out,n,key,ctx->nonce.c,ctx->cmac.c);
		n   *= 16;
		inp += n;
		out += n;
		len -= n;
		if (len) ctr64_add(ctx->nonce.c,n/16);
	}

	if (len) {
		for (i=0; i<len; ++i) ctx->cmac.c[i] ^= inp[i];
		(*block)(ctx->cmac.c,ctx->cmac.c,key);
		(*block)(ctx->nonce.c,scratch.c,key);
		for (i=0; i<len; ++i) out[i] = scratch.c[i]^inp[i];
	}

	for (i=15-L;i<16;++i)
		ctx->nonce.c[i]=0;

	(*block)(ctx->nonce.c,scratch.c,key);
	ctx->cmac.u[0] ^= scratch.u[0];
	ctx->cmac.u[1] ^= scratch.u[1];

	ctx->nonce.c[0] = flags0;

	return 0;
}

int ccm128_decrypt_ccm64(struct ccm128_context *ctx,
	const unsigned char *inp, unsigned char *out, size_t len,
	ccm128_f stream)
{
	size_t		n;
	unsigned int	i,L;
	unsigned char	flags0	= ctx->nonce.c[0];
	block128_f	block	= ctx->block;
	void *		key	= ctx->key;
	union { u64 u[2]; u8 c[16]; } scratch;

	if (!(flags0&0x40))
		(*block)(ctx->nonce.c,ctx->cmac.c,key);

	ctx->nonce.c[0] = L = flags0&7;
	for (n=0,i=15-L;i<15;++i) {
		n |= ctx->nonce.c[i];
		ctx->nonce.c[i]=0;
		n <<= 8;
	}
	n |= ctx->nonce.c[15];	/* reconstructed length */
	ctx->nonce.c[15]=1;

	if (n!=len) return -1;

	if ((n=len/16)) {
		(*stream)(inp,out,n,key,ctx->nonce.c,ctx->cmac.c);
		n   *= 16;
		inp += n;
		out += n;
		len -= n;
		if (len) ctr64_add(ctx->nonce.c,n/16);
	}

	if (len) {
		(*block)(ctx->nonce.c,scratch.c,key);
		for (i=0; i<len; ++i)
			ctx->cmac.c[i] ^= (out[i] = scratch.c[i]^inp[i]);
		(*block)(ctx->cmac.c,ctx->cmac.c,key);
	}

	for (i=15-L;i<16;++i)
		ctx->nonce.c[i]=0;

	(*block)(ctx->nonce.c,scratch.c,key);
	ctx->cmac.u[0] ^= scratch.u[0];
	ctx->cmac.u[1] ^= scratch.u[1];

	ctx->nonce.c[0] = flags0;

	return 0;
}

size_t ccm128_tag(struct ccm128_context *ctx, unsigned char *tag,
		size_t len)
{
	unsigned int M = (ctx->nonce.c[0]>>3)&7;	/* the M parameter */

	M *= 2; M += 2;
	if (len<M)	return 0;
	memcpy(tag,ctx->cmac.c,M);

	return M;
}

static int nistccm128_encrypt_starts(struct ccm128_context *ctx, size_t len)
{
	size_t n;
	unsigned int i, L;
	unsigned char flags0;
	block128_f block = ctx->block;
	void *key = ctx->key;

	flags0 = ctx->flags0 = ctx->nonce.c[0];
	if (!(flags0 & 0x40))
		(*block)(ctx->nonce.c,ctx->cmac.c,key), ctx->blocks++;

	ctx->nonce.c[0] = L = flags0 & 7;
	for(n = 0, i = 15 - L; i < 15; ++i) {
		n |= ctx->nonce.c[i];
		ctx->nonce.c[i]=0;
		n <<= 8;
	}

	n |= ctx->nonce.c[15];	/* reconstructed length */
	ctx->nonce.c[15]=1;

	ctx->blocks += ((len+15)>>3)|1;
	if (ctx->blocks > (U64(1)<<61))	return -2; /* too much data */

	ctx->flags1 = 1;
	return 0;
}

int nistccm128_encrypt_block(struct ccm128_context *ctx,
		const unsigned char *inp, unsigned char *out, size_t len)
{
	block128_f block = ctx->block;
	void *key = ctx->key;
	union { u64 u[2]; u8 c[16]; } scratch;

	if ( !ctx->flags1 )
		nistccm128_encrypt_starts(ctx, ctx->paylen);

	while (len >= 16) {
		ctx->cmac.u[0] ^= ((u64*)inp)[0];
		ctx->cmac.u[1] ^= ((u64*)inp)[1];

		(*block)(ctx->cmac.c,ctx->cmac.c,key);
		(*block)(ctx->nonce.c,scratch.c,key);
		ctr64_inc(ctx->nonce.c);

		((u64*)out)[0] = scratch.u[0]^((u64*)inp)[0];
		((u64*)out)[1] = scratch.u[1]^((u64*)inp)[1];

		inp += 16; out += 16; len -= 16;
	}

	return 0;
}

int nistccm128_encrypt_finish(struct ccm128_context *ctx,
		const unsigned char *inp, unsigned char *out, size_t len)
{
	size_t m, n, l;
	unsigned int i, L;
	unsigned char flags0;

	block128_f block = ctx->block;
	void* key = ctx->key;
	union { u64 u[2]; u8 c[16]; } scratch;

	flags0 = ctx->flags0; L = flags0 & 7;

	if ( !ctx->flags1 )
		nistccm128_encrypt_starts(ctx, ctx->paylen);

	if ( inp && out && len )
	{
		m = len / 16; n = len % 16; l = len - n;
		if ( m > 0 ) {
			if (nistccm128_encrypt_block(ctx, inp, out, l) < 0)
				return -1;
			inp += l; out += l; len = n;
		}

		if (len) {
			for (i = 0; i < len; ++i) ctx->cmac.c[i] ^= inp[i];
			(*block)(ctx->cmac.c,ctx->cmac.c,key);
			(*block)(ctx->nonce.c,scratch.c,key);
			for (i = 0; i < len; ++i) out[i] = scratch.c[i]^inp[i];
		}
	}

	for (i = 15 - L; i < 16; ++i)
		ctx->nonce.c[i]=0;

	(*block)(ctx->nonce.c, scratch.c, key);
	ctx->cmac.u[0] ^= scratch.u[0];
	ctx->cmac.u[1] ^= scratch.u[1];
	ctx->nonce.c[0] = flags0;
	ctx->flags1 = 0;

	return 0;
}

static int nistccm128_decrypt_starts(struct ccm128_context *ctx, size_t len)
{
	size_t n;
	unsigned int i, L;
	unsigned char flags0 = ctx->nonce.c[0];
	block128_f block = ctx->block;
	void *key = ctx->key;

	flags0 = ctx->flags0 = ctx->nonce.c[0];
	if (!(flags0 & 0x40))
		(*block)(ctx->nonce.c,ctx->cmac.c,key);

	ctx->nonce.c[0] = L = flags0 & 7;
	for (n = 0, i = 15 - L; i < 15; ++i) {
		n |= ctx->nonce.c[i];
		ctx->nonce.c[i]=0;
		n <<= 8;
	}
	n |= ctx->nonce.c[15];	/* reconstructed length */
	ctx->nonce.c[15]=1;

	ctx->flags1 = 1;
	return 0;
}

int nistccm128_decrypt_block(struct ccm128_context *ctx,
		const unsigned char *inp, unsigned char *out, size_t len)
{
	block128_f block = ctx->block;
	void *key = ctx->key;
	union { u64 u[2]; u8 c[16]; } scratch;

	if ( !ctx->flags1 )
		nistccm128_decrypt_starts(ctx, ctx->paylen);

	while (len>=16) {
		//unsigned char o[16];
		u64 dat1, dat2;

		(*block)(ctx->nonce.c,scratch.c,key);
		ctr64_inc(ctx->nonce.c);

		//ctx->cmac.u[0] ^= (((u64*)out)[0] = scratch.u[0]^((u64*)inp)[0]);
		//ctx->cmac.u[1] ^= (((u64*)out)[1] = scratch.u[1]^((u64*)inp)[1]);
		dat1 = scratch.u[0]^((u64*)inp)[0]; ctx->cmac.u[0] ^= dat1;
		dat2 = scratch.u[1]^((u64*)inp)[1];	ctx->cmac.u[1] ^= dat2;

		memcpy(&out[0], &dat1, sizeof(u64));
		memcpy(&out[8], &dat2, sizeof(u64));
		(*block)(ctx->cmac.c,ctx->cmac.c,key);

		//memcpy(o    , &dat1, sizeof(u64));
		//memcpy(o + 8, &dat2, sizeof(u64));
		//memcpy(out, o, sizeof(o));
		inp += 16; out += 16; len -= 16;
	}

	return 0;
}

int nistccm128_decrypt_finish(struct ccm128_context *ctx,
		const unsigned char *inp, unsigned char *out, size_t len)
{
	size_t m, n, l;
	unsigned int i, L;
	unsigned char flags0;

	block128_f block = ctx->block;
	void* key = ctx->key;
	union { u64 u[2]; u8 c[16]; } scratch;

	flags0 = ctx->flags0; L = flags0 & 7;

	if ( !ctx->flags1 )
		nistccm128_decrypt_starts(ctx, ctx->paylen);

	if ( inp && out && len )
	{
		m = len /16; n = len % 16; l = len - n;
		if ( m > 0 ) {
			if (nistccm128_decrypt_block(ctx, inp, out, l) < 0)
				return -1;
			inp += l; out += l; len = n;
		}

		if (len) {
			(*block)(ctx->nonce.c,scratch.c,key);
			for (i=0; i<len; ++i)
				ctx->cmac.c[i] ^= (out[i] = scratch.c[i]^inp[i]);
			(*block)(ctx->cmac.c,ctx->cmac.c,key);
		}
	}

	for (i = 15 - L; i < 16; ++i)
		ctx->nonce.c[i]=0;

	(*block)(ctx->nonce.c,scratch.c,key);

	ctx->cmac.u[0] ^= scratch.u[0];
	ctx->cmac.u[1] ^= scratch.u[1];
	ctx->nonce.c[0] = flags0;
	ctx->flags1 = 0;

	return 0;
}
