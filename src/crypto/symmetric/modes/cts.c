/**
 *	@file    cts.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	AES CTS block cipher implementation.
 *	(CTS = CBC-CS3)
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
 * Trouble with Ciphertext Stealing, CTS, mode is that there is no
 * common official specification, but couple of cipher/application
 * specific ones: RFC2040 and RFC3962. Then there is 'Proposal to
 * Extend CBC Mode By "Ciphertext Stealing"' at NIST site, which
 * deviates from mentioned RFCs. Most notably it allows input to be
 * of block length and it doesn't flip the order of the last two
 * blocks. CTS is being discussed even in ECB context, but it's not
 * adopted for any known application. This implementation provides
 * two interfaces: one compliant with above mentioned RFCs and one
 * compliant with the NIST proposal, both extending CBC mode.
 */
size_t cts128_encrypt_block(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block128_f block)
{	size_t residue, n;

	assert (in && out && key && ivec);

	if (len <= 16) return 0;

	if ((residue=len%16) == 0) residue = 16;

	len -= residue;

	cbc128_encrypt(in,out,len,key,ivec,block);

	in  += len;
	out += len;

	for (n=0; n<residue; ++n)
		ivec[n] ^= in[n];
	(*block)(ivec,ivec,key);
	memcpy(out,out-16,residue);
	memcpy(out-16,ivec,16);

	return len+residue;
}

size_t cts128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], cbc128_f cbc)
{	size_t residue;
	union { size_t align; unsigned char c[16]; } tmp;

	assert (in && out && key && ivec);

	if (len <= 16) return 0;

	if ((residue=len%16) == 0) residue = 16;

	len -= residue;

	(*cbc)(in,out,len,key,ivec,1);

	in  += len;
	out += len;


	{
	size_t n;
	for (n=0; n<16; n+=sizeof(size_t))
		*(size_t *)(tmp.c+n) = 0;
	memcpy(tmp.c,in,residue);
	}
	memcpy(out,out-16,residue);
	(*cbc)(tmp.c,out-16,16,key,ivec,1);

	return len+residue;
}

size_t cts128_decrypt_block(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block128_f block)
{	size_t residue, n;
	union { size_t align; unsigned char c[32]; } tmp;

	assert (in && out && key && ivec);

	if (len<=16) return 0;

	if ((residue=len%16) == 0) residue = 16;

	len -= 16+residue;

	if (len) {
		cbc128_decrypt(in,out,len,key,ivec,block);
		in  += len;
		out += len;
	}

	(*block)(in,tmp.c+16,key);

	for (n=0; n<16; n+=sizeof(size_t))
		*(size_t *)(tmp.c+n) = *(size_t *)(tmp.c+16+n);
	memcpy(tmp.c,in+16,residue);
	(*block)(tmp.c,tmp.c,key);

	for(n=0; n<16; ++n) {
		unsigned char c = in[n];
		out[n] = tmp.c[n] ^ ivec[n];
		ivec[n] = c;
	}
	for(residue+=16; n<residue; ++n)
		out[n] = tmp.c[n] ^ in[n];

	return 16+len+residue;
}

size_t cts128_decrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], cbc128_f cbc)
{	size_t residue, n;
	union { size_t align; unsigned char c[32]; } tmp;

	assert (in && out && key && ivec);

	if (len<=16) return 0;

	if ((residue=len%16) == 0) residue = 16;

	len -= 16+residue;

	if (len) {
		(*cbc)(in,out,len,key,ivec,0);
		in  += len;
		out += len;
	}

	for (n=16; n<32; n+=sizeof(size_t))
		*(size_t *)(tmp.c+n) = 0;
	/* this places in[16] at &tmp.c[16] and decrypted block at &tmp.c[0] */
	(*cbc)(in,tmp.c,16,key,tmp.c+16,0);

	memcpy(tmp.c,in+16,residue);
	(*cbc)(tmp.c,tmp.c,32,key,ivec,0);
	memcpy(out,tmp.c,16+residue);

	return 16+len+residue;
}

size_t nistcts128_encrypt_block(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block128_f block)
{	size_t residue, n;

	assert (in && out && key && ivec);

	if (len < 16) return 0;

	residue=len%16;

	len -= residue;

	cbc128_encrypt(in,out,len,key,ivec,block);

	if (residue==0)	return len;

	in  += len;
	out += len;

	for (n=0; n<residue; ++n)
		ivec[n] ^= in[n];
	(*block)(ivec,ivec,key);
	memcpy(out-16+residue,ivec,16);

	return len+residue;
}

size_t nistcts128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], cbc128_f cbc)
{	size_t residue;
	union { size_t align; unsigned char c[16]; } tmp;

	assert (in && out && key && ivec);

	if (len < 16) return 0;

	residue=len%16;

	len -= residue;

	(*cbc)(in,out,len,key,ivec,1);

	if (residue==0) return len;

	in  += len;
	out += len;


	{
	size_t n;
	for (n=0; n<16; n+=sizeof(size_t))
		*(size_t *)(tmp.c+n) = 0;
	memcpy(tmp.c,in,residue);
	}
	(*cbc)(tmp.c,out-16+residue,16,key,ivec,1);

	return len+residue;
}

size_t nistcts128_decrypt_block(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block128_f block)
{
	size_t residue, n;
	union { size_t align; unsigned char c[32]; } tmp;

	assert (in && out && key && ivec);

	if (len<16) return 0;

	residue=len%16;

	if (residue==0) {
		cbc128_decrypt(in,out,len,key,ivec,block);
		return len;
	}

	len -= 16+residue;

	if (len) {
		cbc128_decrypt(in,out,len,key,ivec,block);
		in  += len;
		out += len;
	}

	(*block)(in+residue,tmp.c+16,key);

	for (n=0; n<16; n+=sizeof(size_t))
		*(size_t *)(tmp.c+n) = *(size_t *)(tmp.c+16+n);
	memcpy(tmp.c,in,residue);
	(*block)(tmp.c,tmp.c,key);

	for(n=0; n<16; ++n) {
		unsigned char c = in[n];
		out[n] = tmp.c[n] ^ ivec[n];
		ivec[n] = in[n+residue];
		tmp.c[n] = c;
	}
	for(residue+=16; n<residue; ++n)
		out[n] = tmp.c[n] ^ tmp.c[n-16];

	return 16+len+residue;
}

size_t nistcts128_decrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], cbc128_f cbc)
{
	size_t residue, n;
	union { size_t align; unsigned char c[32]; } tmp;

	assert (in && out && key && ivec);

	if (len<16) return 0;

	residue=len%16;

	if (residue==0) {
		(*cbc)(in,out,len,key,ivec,0);
		return len;
	}

	len -= 16+residue;

	if (len) {
		(*cbc)(in,out,len,key,ivec,0);
		in  += len;
		out += len;
	}

	for (n=16; n<32; n+=sizeof(size_t))
		*(size_t *)(tmp.c+n) = 0;
	/* this places in[16] at &tmp.c[16] and decrypted block at &tmp.c[0] */
	(*cbc)(in+residue,tmp.c,16,key,tmp.c+16,0);

	memcpy(tmp.c,in,residue);

	(*cbc)(tmp.c,tmp.c,32,key,ivec,0);
	memcpy(out,tmp.c,16+residue);

	return 16+len+residue;
}
