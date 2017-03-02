/**
 *	@file    xts.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	AES XTS block cipher implementation.
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

int xts128_encrypt(const struct xts128_context *ctx, const unsigned char iv[16],
	const unsigned char *inp, unsigned char *out, size_t len, int enc)
{
	const union { long one; char little; } is_endian = {1};
	union { u64 u[2]; u32 d[4]; u8 c[16]; } tweak, scratch;
	unsigned int i;

	if (len<16) return -1;

	memcpy(tweak.c, iv, 16);

	(*ctx->block2)(tweak.c,tweak.c,ctx->key2);

	if (!enc && (len%16)) len-=16;

	while (len>=16) {

		scratch.u[0] = ((u64*)inp)[0]^tweak.u[0];
		scratch.u[1] = ((u64*)inp)[1]^tweak.u[1];

		(*ctx->block1)(scratch.c,scratch.c,ctx->key1);

		((u64*)out)[0] = scratch.u[0]^=tweak.u[0];
		((u64*)out)[1] = scratch.u[1]^=tweak.u[1];

		inp += 16;
		out += 16;
		len -= 16;

		if (len==0)	return 0;

		if (is_endian.little) {
			unsigned int carry,res;

			res = 0x87&(((int)tweak.d[3])>>31);
			carry = (unsigned int)(tweak.u[0]>>63);
			tweak.u[0] = (tweak.u[0]<<1)^res;
			tweak.u[1] = (tweak.u[1]<<1)|carry;
		}
		else {
			size_t c;

			for (c=0,i=0;i<16;++i) {
				/*+ substitutes for |, because c is 1 bit */
				c += ((size_t)tweak.c[i])<<1;
				tweak.c[i] = (u8)c;
				c = c>>8;
			}
			tweak.c[0] ^= (u8)(0x87&(0-c));
		}
	}

	if (enc) {
		for (i=0;i<len;++i) {
			u8 c = inp[i];
			out[i] = scratch.c[i];
			scratch.c[i] = c;
		}
		scratch.u[0] ^= tweak.u[0];
		scratch.u[1] ^= tweak.u[1];
		(*ctx->block1)(scratch.c,scratch.c,ctx->key1);
		scratch.u[0] ^= tweak.u[0];
		scratch.u[1] ^= tweak.u[1];
		memcpy(out-16,scratch.c,16);
	}
	else {
		union { u64 u[2]; u8 c[16]; } tweak1;

		if (is_endian.little) {
			unsigned int carry,res;

			res = 0x87&(((int)tweak.d[3])>>31);
			carry = (unsigned int)(tweak.u[0]>>63);
			tweak1.u[0] = (tweak.u[0]<<1)^res;
			tweak1.u[1] = (tweak.u[1]<<1)|carry;
		}
		else {
			size_t c;

			for (c=0,i=0;i<16;++i) {
				/*+ substitutes for |, because c is 1 bit */
				c += ((size_t)tweak.c[i])<<1;
				tweak1.c[i] = (u8)c;
				c = c>>8;
			}
			tweak1.c[0] ^= (u8)(0x87&(0-c));
		}

		scratch.u[0] = ((u64*)inp)[0]^tweak1.u[0];
		scratch.u[1] = ((u64*)inp)[1]^tweak1.u[1];

		(*ctx->block1)(scratch.c,scratch.c,ctx->key1);
		scratch.u[0] ^= tweak1.u[0];
		scratch.u[1] ^= tweak1.u[1];

		for (i=0;i<len;++i) {
			u8 c = inp[16+i];
			out[16+i] = scratch.c[i];
			scratch.c[i] = c;
		}
		scratch.u[0] ^= tweak.u[0];
		scratch.u[1] ^= tweak.u[1];
		(*ctx->block1)(scratch.c,scratch.c,ctx->key1);

		((u64*)out)[0] = scratch.u[0]^tweak.u[0];
		((u64*)out)[1] = scratch.u[1]^tweak.u[1];
	}

	return 0;
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

int xts128_update(struct xts128_context *ctx,
		const unsigned char *inp, unsigned char *out, size_t len)
{
	unsigned int carry, res;

	if (len%16) return -1;

	while (len>=16)
	{
		ctx->scratch.u[0] = ((u64*)inp)[0]^ctx->tweak.u[0];
		ctx->scratch.u[1] = ((u64*)inp)[1]^ctx->tweak.u[1];

		(*ctx->block1)(ctx->scratch.c,ctx->scratch.c,ctx->key1);

		((u64*)out)[0] = ctx->scratch.u[0]^=ctx->tweak.u[0];
		((u64*)out)[1] = ctx->scratch.u[1]^=ctx->tweak.u[1];

		inp += 16; out += 16; len -= 16;

		res = 0x87&(((int)ctx->tweak.d[3])>>31);
		carry = (unsigned int)(ctx->tweak.u[0]>>63);
		ctx->tweak.u[0] = (ctx->tweak.u[0]<<1)^res;
		ctx->tweak.u[1] = (ctx->tweak.u[1]<<1)|carry;
	}

	return 0;
}

int xts128_finish(struct xts128_context *ctx,
		const unsigned char *inp, unsigned char *out, size_t len, int enc)
{
	unsigned int i;
	unsigned int carry,res;

	if (len<16) return -1;

	if (!enc && (len%16)) len-=16;

	while (len >= 16) {

		ctx->scratch.u[0] = ((u64*)inp)[0]^ctx->tweak.u[0];
		ctx->scratch.u[1] = ((u64*)inp)[1]^ctx->tweak.u[1];

		(*ctx->block1)(ctx->scratch.c,ctx->scratch.c,ctx->key1);

		((u64*)out)[0] = ctx->scratch.u[0]^=ctx->tweak.u[0];
		((u64*)out)[1] = ctx->scratch.u[1]^=ctx->tweak.u[1];

		inp += 16; out += 16; len -= 16;

		if (len == 0)	return 0;

		res = 0x87&(((int)ctx->tweak.d[3])>>31);
		carry = (unsigned int)(ctx->tweak.u[0]>>63);
		ctx->tweak.u[0] = (ctx->tweak.u[0]<<1)^res;
		ctx->tweak.u[1] = (ctx->tweak.u[1]<<1)|carry;
	}

	if (enc) {

		for (i = 0; i < len; ++i) {
			u8 c = inp[i]; out[i] = ctx->scratch.c[i]; ctx->scratch.c[i] = c;
		}

		ctx->scratch.u[0] ^= ctx->tweak.u[0];
		ctx->scratch.u[1] ^= ctx->tweak.u[1];

		(*ctx->block1)(ctx->scratch.c,ctx->scratch.c,ctx->key1);

		ctx->scratch.u[0] ^= ctx->tweak.u[0];
		ctx->scratch.u[1] ^= ctx->tweak.u[1];
		memcpy(out - 16, ctx->scratch.c, 16);
	} else {

		union { u64 u[2]; u8 c[16]; } tweak1;

		res = 0x87&(((int)ctx->tweak.d[3])>>31);
		carry = (unsigned int)(ctx->tweak.u[0]>>63);
		tweak1.u[0] = (ctx->tweak.u[0]<<1)^res;
		tweak1.u[1] = (ctx->tweak.u[1]<<1)|carry;

		ctx->scratch.u[0] = ((u64*)inp)[0]^tweak1.u[0];
		ctx->scratch.u[1] = ((u64*)inp)[1]^tweak1.u[1];

		(*ctx->block1)(ctx->scratch.c,ctx->scratch.c,ctx->key1);

		ctx->scratch.u[0] ^= tweak1.u[0];
		ctx->scratch.u[1] ^= tweak1.u[1];


		for (i = 0; i < len; ++i) {
			u8 c = inp[16 + i]; out[16+i] = ctx->scratch.c[i]; ctx->scratch.c[i] = c;
		}
		ctx->scratch.u[0] ^= ctx->tweak.u[0];
		ctx->scratch.u[1] ^= ctx->tweak.u[1];
		(*ctx->block1)(ctx->scratch.c,ctx->scratch.c,ctx->key1);

		((u64*)out)[0] = ctx->scratch.u[0]^ctx->tweak.u[0];
		((u64*)out)[1] = ctx->scratch.u[1]^ctx->tweak.u[1];
	}

	return 0;
}



