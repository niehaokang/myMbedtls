/**
 *	@file    ctr.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	AES CTR block cipher implementation.
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

/* NOTE: the IV/counter CTR mode is big-endian.  The code itself
 * is endian-neutral. */

/* increment counter (128-bit int) by 1 */
static void ctr128_inc(unsigned char *counter) {

	u32 n=16;
	u8  c;

	do {
		--n;
		c = counter[n];
		++c;
		counter[n] = c;
		if (c) return;
	} while (n);
}

/* The input encrypted as though 128bit counter mode is being
 * used.  The extra state information to record how much of the
 * 128bit block we have used is contained in *num, and the
 * encrypted counter is kept in ecount_buf.  Both *num and
 * ecount_buf must be initialised with zeros before the first
 * call to ctr128_encrypt().
 *
 * This algorithm assumes that the counter is in the x lower bits
 * of the IV (ivec), and that the application has full control over
 * overflow and the rest of the IV.  This implementation takes NO
 * responsability for checking that the counter doesn't overflow
 * into the rest of the IV when incremented.
 */
void ctr128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], unsigned char ecount_buf[16],
			unsigned int *num, block128_f block)
{
	unsigned int n;
	size_t l=0;

	assert(in && out && key && ecount_buf && num);
	assert(*num < 16);

	n = *num;

	while (l<len) {
		if (n==0) {
			(*block)(ivec, ecount_buf, key);
 			ctr128_inc(ivec);
		}
		out[l] = in[l] ^ ecount_buf[n];
		++l;
		n = (n+1) % 16;
	}

	*num=n;
}

/* increment upper 96 bits of 128-bit counter by 1 */
static void ctr96_inc(unsigned char *counter) {
	u32 n=12;
	u8  c;

	do {
		--n;
		c = counter[n];
		++c;
		counter[n] = c;
		if (c) return;
	} while (n);
}

void ctr128_encrypt_ctr32(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], unsigned char ecount_buf[16],
			unsigned int *num, ctr128_f func)
{
	unsigned int n,ctr32;

	assert(in && out && key && ecount_buf && num);
	assert(*num < 16);

	n = *num;

	while (n && len) {
		*(out++) = *(in++) ^ ecount_buf[n];
		--len;
		n = (n+1) % 16;
	}

	ctr32 = GETU32(ivec+12);
	while (len>=16) {
		size_t blocks = len/16;
		/*
		 * 1<<28 is just a not-so-small yet not-so-large number...
		 * Below condition is practically never met, but it has to
		 * be checked for code correctness.
		 */
		if (sizeof(size_t)>sizeof(unsigned int) && blocks>(1U<<28))
			blocks = (1U<<28);
		/*
		 * As (*func) operates on 32-bit counter, caller
		 * has to handle overflow. 'if' below detects the
		 * overflow, which is then handled by limiting the
		 * amount of blocks to the exact overflow point...
		 */
		ctr32 += (u32)blocks;
		if (ctr32 < blocks) {
			blocks -= ctr32;
			ctr32   = 0;
		}
		(*func)(in,out,blocks,key,ivec);
		/* (*ctr) does not update ivec, caller does: */
		PUTU32(ivec+12,ctr32);
		/* ... overflow was detected, propogate carry. */
		if (ctr32 == 0)	ctr96_inc(ivec);
		blocks *= 16;
		len -= blocks;
		out += blocks;
		in  += blocks;
	}
	if (len) {
		memset(ecount_buf,0,16);
		(*func)(ecount_buf,ecount_buf,1,key,ivec);
		++ctr32;
		PUTU32(ivec+12,ctr32);
		if (ctr32 == 0)	ctr96_inc(ivec);
		while (len--) {
			out[n] = in[n] ^ ecount_buf[n];
			++n;
		}
	}

	*num=n;
}
