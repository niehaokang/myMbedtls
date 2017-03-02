/**
 *	@file    gcm.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	AES GCM block cipher implementation.
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

/*
 * Precompute small multiples of H, that is set
 *      HH[i] || HL[i] = H times i,
 * where i is seen as a field element as in [MGV], ie high-order bits
 * correspond to low powers of P. The result is stored in the same way, that
 * is the high-order bit of HH corresponds to P^0 and the low-order bit of HL
 * corresponds to P^127.
 */
static void gcm_init_4bit(u128 Htable[16], u64 H[2])
{
	u128 V;
	int  i;

	Htable[0].hi = 0;
	Htable[0].lo = 0;
	V.hi = H[0];
	V.lo = H[1];

	for (Htable[8]=V, i=4; i>0; i>>=1) {
		REDUCE1BIT(V);
		Htable[i] = V;
	}

	for (i=2; i<16; i<<=1) {
		u128 *Hi = Htable+i;
		int   j;
		for (V=*Hi, j=1; j<i; ++j) {
			Hi[j].hi = V.hi^Htable[j].hi;
			Hi[j].lo = V.lo^Htable[j].lo;
		}
	}
}

/*
 * Shoup's method for multiplication use this table with
 *      last4[x] = x times P^128
 * where x and last4[x] are seen as elements of GF(2^128) as in [MGV]
 */
static const size_t rem_4bit[16] = {
	PACK(0x0000), PACK(0x1C20), PACK(0x3840), PACK(0x2460),
	PACK(0x7080), PACK(0x6CA0), PACK(0x48C0), PACK(0x54E0),
	PACK(0xE100), PACK(0xFD20), PACK(0xD940), PACK(0xC560),
	PACK(0x9180), PACK(0x8DA0), PACK(0xA9C0), PACK(0xB5E0) };

static void gcm_gmult_4bit(u64 Xi[2], const u128 Htable[16])
{
	u128 Z;
	int cnt = 15;
	size_t rem, nlo, nhi;
	const union { long one; char little; } is_endian = {1};

	nlo  = ((const u8 *)Xi)[15];
	nhi  = nlo>>4;
	nlo &= 0xf;

	Z.hi = Htable[nlo].hi;
	Z.lo = Htable[nlo].lo;

	while (1) {
		rem  = (size_t)Z.lo&0xf;
		Z.lo = (Z.hi<<60)|(Z.lo>>4);
		Z.hi = (Z.hi>>4);
		if (sizeof(size_t) == 8)
			Z.hi ^= rem_4bit[rem];
		else
			Z.hi ^= (u64)rem_4bit[rem]<<32;

		Z.hi ^= Htable[nhi].hi;
		Z.lo ^= Htable[nhi].lo;

		if (--cnt<0)		break;

		nlo  = ((const u8 *)Xi)[cnt];
		nhi  = nlo>>4;
		nlo &= 0xf;

		rem  = (size_t)Z.lo&0xf;
		Z.lo = (Z.hi<<60)|(Z.lo>>4);
		Z.hi = (Z.hi>>4);
		if (sizeof(size_t)==8)
			Z.hi ^= rem_4bit[rem];
		else
			Z.hi ^= (u64)rem_4bit[rem]<<32;

		Z.hi ^= Htable[nlo].hi;
		Z.lo ^= Htable[nlo].lo;
	}

	if (is_endian.little) {

		u8 *p = (u8 *)Xi;
		u32 v;
		v = (u32)(Z.hi>>32);	PUTU32(p,v);
		v = (u32)(Z.hi);	PUTU32(p+4,v);
		v = (u32)(Z.lo>>32);	PUTU32(p+8,v);
		v = (u32)(Z.lo);	PUTU32(p+12,v);
	}
	else {
		Xi[0] = Z.hi;
		Xi[1] = Z.lo;
	}
}

#define GCM_MUL(ctx,Xi)   gcm_gmult_4bit(ctx->Xi.u, ctx->Htable)

/*
 * Initialize a context
 */
void gcm128_init(struct gcm128_context *ctx,void *key,block128_f block)
{
	const union { long one; char little; } is_endian = {1};

	memset(ctx,0,sizeof(*ctx));
	ctx->block = block;
	ctx->key   = key;

	(*block)(ctx->H.c,ctx->H.c,key);

	if (is_endian.little) {
		/* H is stored in host byte order */

		u8 *p = ctx->H.c;
		u64 hi,lo;
		hi = (u64)GETU32(p)  <<32|GETU32(p+4);
		lo = (u64)GETU32(p+8)<<32|GETU32(p+12);
		ctx->H.u[0] = hi;
		ctx->H.u[1] = lo;
	}

	gcm_init_4bit(ctx->Htable,ctx->H.u);
}

void gcm128_setiv(struct gcm128_context *ctx, const unsigned char *iv,
			size_t len)
{
	const union { long one; char little; } is_endian = {1};
	unsigned int ctr;

	ctx->Yi.u[0]  = 0;
	ctx->Yi.u[1]  = 0;
	ctx->Xi.u[0]  = 0;
	ctx->Xi.u[1]  = 0;
	ctx->len.u[0] = 0;	/* AAD length */
	ctx->len.u[1] = 0;	/* message length */
	ctx->ares = 0;
	ctx->mres = 0;

	if (len==12) {
		memcpy(ctx->Yi.c,iv,12);
		ctx->Yi.c[15]=1;
		ctr=1;
	}
	else {
		size_t i;
		u64 len0 = len;

		while (len>=16) {
			for (i=0; i<16; ++i) ctx->Yi.c[i] ^= iv[i];
			GCM_MUL(ctx,Yi);
			iv += 16;
			len -= 16;
		}
		if (len) {
			for (i=0; i<len; ++i) ctx->Yi.c[i] ^= iv[i];
			GCM_MUL(ctx,Yi);
		}
		len0 <<= 3;
		if (is_endian.little) {

			ctx->Yi.c[8]  ^= (u8)(len0>>56);
			ctx->Yi.c[9]  ^= (u8)(len0>>48);
			ctx->Yi.c[10] ^= (u8)(len0>>40);
			ctx->Yi.c[11] ^= (u8)(len0>>32);
			ctx->Yi.c[12] ^= (u8)(len0>>24);
			ctx->Yi.c[13] ^= (u8)(len0>>16);
			ctx->Yi.c[14] ^= (u8)(len0>>8);
			ctx->Yi.c[15] ^= (u8)(len0);
		}
		else
			ctx->Yi.u[1]  ^= len0;

		GCM_MUL(ctx,Yi);

		if (is_endian.little)
			ctr = GETU32(ctx->Yi.c+12);
		else
			ctr = ctx->Yi.d[3];
	}

	(*ctx->block)(ctx->Yi.c,ctx->EK0.c,ctx->key);
	++ctr;
	if (is_endian.little)
		PUTU32(ctx->Yi.c+12,ctr);
	else
		ctx->Yi.d[3] = ctr;
}

int gcm128_aad(struct gcm128_context *ctx, const unsigned char *aad,
			size_t len)
{
	size_t i;
	unsigned int n;
	u64 alen = ctx->len.u[0];

	if (ctx->len.u[1]) return -2;

	alen += len;
	if (alen>(U64(1)<<61) || (sizeof(len)==8 && alen<len))
		return -1;
	ctx->len.u[0] = alen;

	n = ctx->ares;
	if (n) {
		while (n && len) {
			ctx->Xi.c[n] ^= *(aad++);
			--len;
			n = (n+1)%16;
		}
		if (n==0) GCM_MUL(ctx,Xi);
		else {
			ctx->ares = n;
			return 0;
		}
	}

	while (len>=16) {
		for (i=0; i<16; ++i) ctx->Xi.c[i] ^= aad[i];
		GCM_MUL(ctx,Xi);
		aad += 16;
		len -= 16;
	}

	if (len) {
		n = (unsigned int)len;
		for (i=0; i<len; ++i) ctx->Xi.c[i] ^= aad[i];
	}

	ctx->ares = n;
	return 0;
}

int gcm128_encrypt(struct gcm128_context *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len)
{
	const union { long one; char little; } is_endian = {1};
	unsigned int n, ctr;
	size_t i;
	u64        mlen  = ctx->len.u[1];
	block128_f block = ctx->block;
	void      *key   = ctx->key;

	mlen += len;
	if (mlen>((U64(1)<<36)-32) || (sizeof(len)==8 && mlen<len))
		return -1;
	ctx->len.u[1] = mlen;

	if (ctx->ares) {
		/* First call to encrypt finalizes GHASH(AAD) */
		GCM_MUL(ctx,Xi);
		ctx->ares = 0;
	}

	if (is_endian.little)
		ctr = GETU32(ctx->Yi.c+12);
	else
		ctr = ctx->Yi.d[3];

	n = ctx->mres;

	for (i=0;i<len;++i) {
		if (n==0) {
			(*block)(ctx->Yi.c,ctx->EKi.c,key);
			++ctr;
			if (is_endian.little)
				PUTU32(ctx->Yi.c+12,ctr);
			else
				ctx->Yi.d[3] = ctr;
		}
		ctx->Xi.c[n] ^= out[i] = in[i]^ctx->EKi.c[n];
		n = (n+1)%16;
		if (n==0)
			GCM_MUL(ctx,Xi);
	}

	ctx->mres = n;
	return 0;
}

int gcm128_decrypt(struct gcm128_context *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len)
{
	const union { long one; char little; } is_endian = {1};
	unsigned int n, ctr;
	size_t i;
	u64        mlen  = ctx->len.u[1];
	block128_f block = ctx->block;
	void      *key   = ctx->key;

	mlen += len;
	if (mlen>((U64(1)<<36)-32) || (sizeof(len)==8 && mlen<len))
		return -1;
	ctx->len.u[1] = mlen;

	if (ctx->ares) {
		/* First call to decrypt finalizes GHASH(AAD) */
		GCM_MUL(ctx,Xi);
		ctx->ares = 0;
	}

	if (is_endian.little)
		ctr = GETU32(ctx->Yi.c+12);
	else
		ctr = ctx->Yi.d[3];

	n = ctx->mres;

	for (i=0;i<len;++i) {
		u8 c;
		if (n==0) {
			(*block)(ctx->Yi.c,ctx->EKi.c,key);
			++ctr;
			if (is_endian.little)
				PUTU32(ctx->Yi.c+12,ctr);
			else
				ctx->Yi.d[3] = ctr;
		}
		c = in[i];
		out[i] = c^ctx->EKi.c[n];
		ctx->Xi.c[n] ^= c;
		n = (n+1)%16;
		if (n==0)
			GCM_MUL(ctx,Xi);
	}

	ctx->mres = n;
	return 0;
}

int gcm128_encrypt_ctr32(struct gcm128_context *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len, ctr128_f stream)
{
	const union { long one; char little; } is_endian = {1};
	unsigned int n, ctr;
	size_t i;
	u64   mlen = ctx->len.u[1];
	void *key  = ctx->key;

	mlen += len;
	if (mlen>((U64(1)<<36)-32) || (sizeof(len)==8 && mlen<len))
		return -1;
	ctx->len.u[1] = mlen;

	if (ctx->ares) {
		/* First call to encrypt finalizes GHASH(AAD) */
		GCM_MUL(ctx,Xi);
		ctx->ares = 0;
	}

	if (is_endian.little)
		ctr = GETU32(ctx->Yi.c+12);
	else
		ctr = ctx->Yi.d[3];

	n = ctx->mres;
	if (n) {
		while (n && len) {
			ctx->Xi.c[n] ^= *(out++) = *(in++)^ctx->EKi.c[n];
			--len;
			n = (n+1)%16;
		}
		if (n==0) GCM_MUL(ctx,Xi);
		else {
			ctx->mres = n;
			return 0;
		}
	}

	if ((i = (len&(size_t)-16))) {
		size_t j=i/16;

		(*stream)(in,out,j,key,ctx->Yi.c);
		ctr += (unsigned int)j;
		if (is_endian.little)
			PUTU32(ctx->Yi.c+12,ctr);
		else
			ctx->Yi.d[3] = ctr;
		in  += i;
		len -= i;

		while (j--) {
			for (i=0;i<16;++i) ctx->Xi.c[i] ^= out[i];
			GCM_MUL(ctx,Xi);
			out += 16;
		}
	}
	if (len) {
		(*ctx->block)(ctx->Yi.c,ctx->EKi.c,key);
		++ctr;
		if (is_endian.little)
			PUTU32(ctx->Yi.c+12,ctr);
		else
			ctx->Yi.d[3] = ctr;
		while (len--) {
			ctx->Xi.c[n] ^= out[n] = in[n]^ctx->EKi.c[n];
			++n;
		}
	}

	ctx->mres = n;
	return 0;
}

int gcm128_decrypt_ctr32(struct gcm128_context *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len, ctr128_f stream)
{
	const union { long one; char little; } is_endian = {1};
	unsigned int n, ctr;
	size_t i;
	u64   mlen = ctx->len.u[1];
	void *key  = ctx->key;

	mlen += len;
	if (mlen>((U64(1)<<36)-32) || (sizeof(len)==8 && mlen<len))
		return -1;
	ctx->len.u[1] = mlen;

	if (ctx->ares) {
		/* First call to decrypt finalizes GHASH(AAD) */
		GCM_MUL(ctx,Xi);
		ctx->ares = 0;
	}

	if (is_endian.little)
		ctr = GETU32(ctx->Yi.c+12);
	else
		ctr = ctx->Yi.d[3];

	n = ctx->mres;
	if (n) {
		while (n && len) {
			u8 c = *(in++);
			*(out++) = c^ctx->EKi.c[n];
			ctx->Xi.c[n] ^= c;
			--len;
			n = (n+1)%16;
		}
		if (n==0) GCM_MUL (ctx,Xi);
		else {
			ctx->mres = n;
			return 0;
		}
	}

	if ((i = (len&(size_t)-16))) {
		size_t j=i/16;

		while (j--) {
			size_t k;
			for (k=0;k<16;++k) ctx->Xi.c[k] ^= in[k];
			GCM_MUL(ctx,Xi);
			in += 16;
		}
		j   = i/16;
		in -= i;

		(*stream)(in,out,j,key,ctx->Yi.c);
		ctr += (unsigned int)j;
		if (is_endian.little)
			PUTU32(ctx->Yi.c+12,ctr);
		else
			ctx->Yi.d[3] = ctr;
		out += i;
		in  += i;
		len -= i;
	}
	if (len) {
		(*ctx->block)(ctx->Yi.c,ctx->EKi.c,key);
		++ctr;
		if (is_endian.little)
			PUTU32(ctx->Yi.c+12,ctr);
		else
			ctx->Yi.d[3] = ctr;
		while (len--) {
			u8 c = in[n];
			ctx->Xi.c[n] ^= c;
			out[n] = c^ctx->EKi.c[n];
			++n;
		}
	}

	ctx->mres = n;
	return 0;
}

int gcm128_finish(struct gcm128_context *ctx,const unsigned char *tag,
			size_t len)
{
	const union { long one; char little; } is_endian = {1};
	u64 alen = ctx->len.u[0]<<3;
	u64 clen = ctx->len.u[1]<<3;

	if (ctx->mres)
		GCM_MUL(ctx,Xi);

	if (is_endian.little) {

		u8 *p = ctx->len.c;

		ctx->len.u[0] = alen;
		ctx->len.u[1] = clen;

		alen = (u64)GETU32(p)  <<32|GETU32(p+4);
		clen = (u64)GETU32(p+8)<<32|GETU32(p+12);
	}

	ctx->Xi.u[0] ^= alen;
	ctx->Xi.u[1] ^= clen;
	GCM_MUL(ctx,Xi);

	ctx->Xi.u[0] ^= ctx->EK0.u[0];
	ctx->Xi.u[1] ^= ctx->EK0.u[1];

	if (tag && len<=sizeof(ctx->Xi))
		return memcmp(ctx->Xi.c,tag,len);
	else
		return -1;
}

void gcm128_tag(struct gcm128_context *ctx, unsigned char *tag,
			size_t len)
{
	gcm128_finish(ctx, NULL, 0);
	memcpy(tag, ctx->Xi.c, len<=sizeof(ctx->Xi.c)?len:sizeof(ctx->Xi.c));
}

