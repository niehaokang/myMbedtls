/**
 *	@file    asn1.h
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	ASN.1 header.
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

#ifndef _h_PS_ASN1
#define _h_PS_ASN1
#include "crypto/cryptoConfig.h"

/******************************************************************************/
/******************************************************************************/
/*
	8 bit bit masks for ASN.1 tag field
*/
#define ASN_PRIMITIVE			0x0
#define ASN_CONSTRUCTED			0x20

#define ASN_UNIVERSAL			0x0
#define ASN_APPLICATION			0x40
#define ASN_CONTEXT_SPECIFIC	0x80
#define ASN_PRIVATE				0xC0

#define __ASN_CHECK__(g, f) do { if( ( ret = f ) < 0 ) return( ret ); else   \
						g += ret; } while( 0 )
/*
	ASN.1 primitive data types
*/
enum {
	ASN_BOOLEAN = 1,
	ASN_INTEGER,
	ASN_BIT_STRING,
	ASN_OCTET_STRING,
	ASN_NULL,
	ASN_OID,
	ASN_UTF8STRING = 12,
	ASN_SEQUENCE = 16,
	ASN_SET,
	ASN_PRINTABLESTRING = 19,
	ASN_T61STRING,
	ASN_IA5STRING = 22,
	ASN_UTCTIME,
	ASN_GENERALIZEDTIME,
	ASN_GENERAL_STRING = 27,
	ASN_BMPSTRING = 30
};

#define ASN_UNKNOWN_LEN	16777215

extern int32 getAsnLength(unsigned char **p, uint32 size, uint32 *valLen);
extern int32 getAsnBig(psPool_t *pool, unsigned char **pp, uint32 len,
				pstm_int *big);
extern int32 getAsnSequence(unsigned char **pp, uint32 len, uint32 *seqlen);
extern int32 getAsnSequenceNoLenCheck(unsigned char **pp, uint32 len,
				uint32 *seqlen);
extern int32 getAsnSet(unsigned char **pp, uint32 len, uint32 *setlen);
extern int32 getAsnInteger(unsigned char **pp, uint32 len, int32 *val);

extern int32 getAsnAlgorithmIdentifier(unsigned char **pp, uint32 len,
				int32 *oi, int32 *paramLen);
extern int32 getStreamingAsnAlgorithmIdentifier(unsigned char **pp, uint32 len,
				int32 *oi, int32 *paramLen);
extern int32 getAsnOID(unsigned char **pp, uint32 len, int32 *oi,
				int32 checkForParams, int32 *paramLen);
extern int32 getAsnConstructedOctetString(psPool_t *pool, unsigned char **pp,
				uint32 len, unsigned char **outString, int32 *outStringLen);
#ifdef USE_RSA
extern int32 getAsnRsaPubKey(psPool_t *pool, unsigned char **pp, uint32 len,
				psRsaKey_t *pubKey);
#endif /* USE_RSA */
/******************************************************************************/

extern int32 setAsnRawData(unsigned char **p, unsigned char *start,
				unsigned char *raw, uint32 size);
extern int32 setAsnLength(unsigned char **p, unsigned char *start,
				uint32 len);
extern int32 setAsnTag(unsigned char **p, unsigned char *start,
				unsigned char tag);
extern int32 setAsnBig(psPool_t *pool, unsigned char **p, unsigned char *start,
				pstm_int *big);
extern int32 setAsnSequence(unsigned char **p, unsigned char *start,
				uint32 seqlen);
extern int32 setAsnNull(unsigned char **p, unsigned char *start);
extern int32 setAsnOID(unsigned char **p, unsigned char *start,
				unsigned char *oid, uint32 oid_len);
extern int32 setAsnAlgorithmIdentifier(unsigned char **p, unsigned char *start,
				unsigned char *oid, uint32 oid_len, uint32 par_len);
extern int32 setAsnBool(unsigned char **p, unsigned char *start, int boolean);
extern int32 setAsnInteger(unsigned char **p, unsigned char *start,
				int val);
extern int32 setAsnBitString(unsigned char **p, unsigned char *start,
				unsigned char *string, int32 bits);
extern int32 setAsnConstructedOctetString(unsigned char **p, unsigned char *start,
				unsigned char *string, int32 octets);
				
#endif /* _h_PS_ASN1 */

