/*	@file    ecb.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	AES ECB block cipher implementation.
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

void ecb64_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key, block64_f block)
{
	psAssert(in && out && key);

	while (len) {
		(*block)(in, out, key);
		if (len<=8) break;
		len -= 8;
		in  += 8;
		out += 8;
	}
}

void ecb64_decrypt(const unsigned char *in, unsigned char *out,
		size_t len, const void *key, block64_f block)
{
	psAssert(in && out && key);

	while (len) {
		(*block)(in, out, key);
		if (len<=8) break;
		len -= 8;
		in  += 8;
		out += 8;
	}
}

void ecb128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key, block128_f block)
{
	psAssert(in && out && key);

	while (len) {
		(*block)(in, out, key);
		if (len<=16) break;
		len -= 16;
		in  += 16;
		out += 16;
	}
}

void ecb128_decrypt(const unsigned char *in, unsigned char *out,
		size_t len, const void *key, block128_f block)
{
	psAssert(in && out && key);

	while (len) {
		(*block)(in, out, key);
		if (len<=16) break;
		len -= 16;
		in  += 16;
		out += 16;
	}
}
