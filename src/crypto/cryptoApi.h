/**
 *	@file    cryptoApi.h
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	Prototypes for the Matrix crypto public APIs.
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

#ifndef _h_PS_CRYPTOAPI
#define _h_PS_CRYPTOAPI

#include "core/coreApi.h" /* Must be first included */
#include "cryptoConfig.h" /* Must be second included */
#include "cryptolib.h"

/******************************************************************************/
/*	Public return codes */
/******************************************************************************/
/*	Failure codses MUST be < 0  */
/*	NOTE: The range for crypto error codes must be between -30 and -49  */
#define	PS_PARSE_FAIL			-31

/*
	PS NOTE:  Any future additions to certificate authentication failures
	must be carried through to MatrixSSL code
*/
#define PS_CERT_AUTH_PASS			PS_TRUE
#define	PS_CERT_AUTH_FAIL_BC		-32 /* BasicConstraint failure */
#define	PS_CERT_AUTH_FAIL_DN		-33 /* DistinguishedName failure */
#define	PS_CERT_AUTH_FAIL_SIG		-34 /* Signature validation failure */
#define PS_CERT_AUTH_FAIL_REVOKED	-35 /* Revoked via CRL */
#define	PS_CERT_AUTH_FAIL			-36 /* Generic cert auth fail */
#define PS_CERT_AUTH_FAIL_EXTENSION -37 /* extension permission problem */
#define PS_CERT_AUTH_FAIL_PATH_LEN	-38 /* pathLen exceeded */
#define PS_CERT_AUTH_FAIL_AUTHKEY	-39 /* subjectKeyid != issuer authKeyid */

#define PS_SIGNATURE_MISMATCH	-40 /* Alorithms all work but sig not a match */

/* Set as authStatusFlags to certificate callback when authStatus
	is PS_CERT_AUTH_FAIL_EXTENSION */
#define PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG	0x01
#define PS_CERT_AUTH_FAIL_EKU_FLAG			0x02
#define PS_CERT_AUTH_FAIL_SUBJECT_FLAG		0x04
#define PS_CERT_AUTH_FAIL_DATE_FLAG			0x08

/******************************************************************************/

#if defined PSTM_X86 || defined PSTM_X86_64 || defined PSTM_ARM || \
	defined PSTM_MIPS
 #define PSTM_ASM_CONFIG_STR "Y"
#else
 #define PSTM_ASM_CONFIG_STR "N"
#endif
#ifdef PSTM_64BIT
 #define PSTM_64_CONFIG_STR "Y"
#else
 #define PSTM_64_CONFIG_STR "N"
#endif
#ifdef USE_AESNI_CRYPTO
 #define AESNI_CONFIG_STR "Y"
#else
 #define AESNI_CONFIG_STR "N"
#endif
 #define HW_PKA_CONFIG_STR "N"
#ifdef USE_PKCS11
 #define PKCS11_CONFIG_STR "Y"
#else
 #define PKCS11_CONFIG_STR "N"
#endif
 #define FIPS_CONFIG_STR "N"

#define PSCRYPTO_CONFIG \
	"Y" \
	PSTM_ASM_CONFIG_STR \
	PSTM_64_CONFIG_STR \
	AESNI_CONFIG_STR \
	HW_PKA_CONFIG_STR \
	PKCS11_CONFIG_STR \
	FIPS_CONFIG_STR

/******************************************************************************/
/* Public APIs */
/******************************************************************************/

PSPUBLIC int32 psCryptoOpen(char *config);
PSPUBLIC void psCryptoClose(void);


#ifdef USE_AES
/******************************************************************************/
/*
	Block Mode AES
*/
PSPUBLIC int32 psAesInitKey(const unsigned char *key, uint32 keylen,
						psAesKey_t *skey);
PSPUBLIC void psAesEncryptBlock(const unsigned char *pt, unsigned char *ct,
						psAesKey_t *skey);
PSPUBLIC void psAesDecryptBlock(const unsigned char *ct, unsigned char *pt,
						psAesKey_t *skey);

/*
	CBC Mode AES (old interface)
*/
PSPUBLIC int32 psCbcAesInit(psCipherContext_t *ctx, unsigned char *IV,
						unsigned char *key, uint32 keylen);
PSPUBLIC int32 psCbcAesDecrypt(psCipherContext_t *ctx, unsigned char *ct,
						unsigned char *pt, uint32 len);
PSPUBLIC int32 psCbcAesEncrypt(psCipherContext_t *ctx, unsigned char *pt,
						unsigned char *ct, uint32 len);

/*
	CTR Mode AES (old interface)
*/
PSPUBLIC int32 psAesInitCTR(psCipherContext_t *ctx, unsigned char *key,
		int32 keylen, unsigned char IV[]);
PSPUBLIC int32 psAesSetParamsCTR(psCipherContext_t *ctx,
		unsigned int used_bytes_num, unsigned char IV[16]);
PSPUBLIC int32 psAesEncryptCTR(psCipherContext_t *ctx, unsigned char *ct,
		unsigned char *pt, uint32 len);

#ifdef USE_CMAC
PSPUBLIC int32 psCmacAesInit(psCmacContext_t *ctx, unsigned char *key,
						uint32  klen);
PSPUBLIC int32 psCmacAesInit2(psCmacContext_t *ctx, unsigned char *key,
						uint32  klen,
						unsigned char *ivec, uint32 iveclen);
PSPUBLIC int32 psCmacAesUpdate(psCmacContext_t *ctx, unsigned char *data,
						uint32  dlen);
PSPUBLIC int32 psCmacAesFinal(psCmacContext_t *ctx, unsigned char *out,
						uint32 *olen);
#endif /* USE_CMAC */

#ifdef USE_CBCMAC
PSPUBLIC int32 psCbcmacAesInit(psCbcmacContext_t *ctx, unsigned char *key,
						uint32  klen);
PSPUBLIC int32 psCbcmacAesInit2(psCbcmacContext_t *ctx, unsigned char *key,
						uint32  klen,
						unsigned char *ivec, uint32 iveclen);
PSPUBLIC int32 psCbcmacAesUpdate(psCbcmacContext_t *ctx, unsigned char *data,
						uint32  dlen);
PSPUBLIC int32 psCbcmacAesFinal(psCbcmacContext_t *ctx, unsigned char *out,
						uint32 *olen);
#endif /* USE_CBCMAC */
#endif /* USE_AES */
/******************************************************************************/

#ifdef USE_SM4
/******************************************************************************/
PSPUBLIC int32 psSm4InitKey(const unsigned char *key, uint32 keylen,
						psSm4Key_t *skey);
PSPUBLIC void psSm4EncryptBlock(const unsigned char *pt, unsigned char *ct,
						psSm4Key_t *skey);
PSPUBLIC void psSm4DecryptBlock(const unsigned char *ct, unsigned char *pt,
						psSm4Key_t *skey);
#endif /* USE_SM4 */

#ifdef USE_SEED
/******************************************************************************/
PSPUBLIC int32 psSeedInit(psCipherContext_t *ctx, unsigned char *IV,
						unsigned char *key, uint32 keylen);
PSPUBLIC int32 psSeedDecrypt(psCipherContext_t *ctx, unsigned char *ct,
						unsigned char *pt, uint32 len);
PSPUBLIC int32 psSeedEncrypt(psCipherContext_t *ctx, unsigned char *pt,
						unsigned char *ct, uint32 len);

PSPUBLIC int32 psSeedInitKey(const unsigned char *key, uint32 keylen,
						psSeedKey_t *skey);
PSPUBLIC void psSeedEncryptBlock(const unsigned char *pt, unsigned char *ct,
						psSeedKey_t *skey);
PSPUBLIC void psSeedDecryptBlock(const unsigned char *ct, unsigned char *pt,
						psSeedKey_t *skey);
#endif /* USE_SEED */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_3DES
/******************************************************************************/
/*
	CBC Mode DES3
*/
PSPUBLIC int32 psDes3Init(psCipherContext_t *ctx, unsigned char *IV,
						unsigned char *key, uint32 keylen);
PSPUBLIC int32 psDes3Decrypt(psCipherContext_t *ctx, unsigned char *ct,
						unsigned char *pt, uint32 len);
PSPUBLIC int32 psDes3Encrypt(psCipherContext_t *ctx, unsigned char *pt,
						unsigned char *ct, uint32 len);
/*
	Block Mode DES3
*/
PSPUBLIC int32 psDes3InitKey(const unsigned char *key, uint32 keylen,
						psDes3Key_t *skey);
PSPUBLIC void psDes3EncryptBlock(const unsigned char *pt, unsigned char *ct,
						psDes3Key_t *skey);
PSPUBLIC void psDes3DecryptBlock(const unsigned char *ct, unsigned char *pt,
						psDes3Key_t *skey);

#ifdef USE_CBCMAC
PSPUBLIC int32 psCbcmacDes3Init(psCbcmacContext_t *ctx, unsigned char *key,
						uint32  klen);
PSPUBLIC int32 psCbcmacDes3Init2(psCbcmacContext_t *ctx, unsigned char *key,
						uint32  klen,
						unsigned char *ivec, uint32 iveclen);
PSPUBLIC int32 psCbcmacDes3Update(psCbcmacContext_t *ctx, unsigned char *data,
						uint32  dlen);
PSPUBLIC int32 psCbcmacDes3Final(psCbcmacContext_t *ctx, unsigned char *out,
						uint32 *olen);
#endif /* USE_CBCMAC*/
#endif /* USE_3DES */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_DES
PSPUBLIC int32 psDesInitKey(const unsigned char *key, int32 keylen,
						psDes3Key_t *skey);
PSPUBLIC void psDesEncryptBlock(const unsigned char *pt, unsigned char *ct,
						psDes3Key_t *skey);
PSPUBLIC void psDesDecryptBlock(const unsigned char *ct, unsigned char *pt,
						psDes3Key_t *skey);

#ifdef USE_CBCMAC
PSPUBLIC int32 psCbcmacDesInit(psCbcmacContext_t *ctx, unsigned char *key,
						uint32  klen);
PSPUBLIC int32 psCbcmacDesInit2(psCbcmacContext_t *ctx, unsigned char *key,
						uint32  klen,
						unsigned char *ivec, uint32 iveclen);
PSPUBLIC int32 psCbcmacDesUpdate(psCbcmacContext_t *ctx, unsigned char *data,
						uint32  dlen);
PSPUBLIC int32 psCbcmacDesFinal(psCbcmacContext_t *ctx, unsigned char *out,
				uint32 *olen);
#endif /* USE_CBCMAC*/
#endif /* USE_DES */
/******************************************************************************/

#ifdef USE_IDEA
/******************************************************************************/
/*
	CBC Mode IDEA
*/
PSPUBLIC int32 psIdeaInit(psCipherContext_t *ctx, unsigned char *IV,
						unsigned char *key, uint32 keylen);
PSPUBLIC int32 psIdeaDecrypt(psCipherContext_t *ctx, unsigned char *ct,
						unsigned char *pt, uint32 len);
PSPUBLIC int32 psIdeaEncrypt(psCipherContext_t *ctx, unsigned char *pt,
						unsigned char *ct, uint32 len);
#endif

/******************************************************************************/
#ifdef USE_ARC4
PSPUBLIC void psArc4Init(psCipherContext_t *ctx, unsigned char *key,
						uint32 keylen);
PSPUBLIC int32 psArc4(psCipherContext_t *ctx, unsigned char *in,
						unsigned char *out, uint32 len);
#endif /* USE_ARC4 */
/******************************************************************************/

#ifdef USE_RC2
/******************************************************************************/
PSPUBLIC int32 psRc2Init(psCipherContext_t *ctx, unsigned char *IV,
						unsigned char *key, uint32 keylen);
PSPUBLIC int32 psRc2Decrypt(psCipherContext_t *ctx, unsigned char *ct,
						unsigned char *pt, uint32 len);
PSPUBLIC int32 psRc2Encrypt(psCipherContext_t *ctx, unsigned char *pt,
						unsigned char *ct, uint32 len);
PSPUBLIC int32 psRc2InitKey(unsigned char *key, uint32 keylen, uint32 rds,
						psRc2Key_t *skey);
PSPUBLIC int32 psRc2EncryptBlock(unsigned char *pt, unsigned char *ct,
						psRc2Key_t *skey);
PSPUBLIC int32 psRc2DecryptBlock(unsigned char *ct, unsigned char *pt,
						psRc2Key_t *skey);
#endif /* USE_RC2 */
/******************************************************************************/
/******************************************************************************/
#ifdef USE_SHA1
/******************************************************************************/
PSPUBLIC void psSha1Init(psDigestContext_t * md);
PSPUBLIC void psSha1Update(psDigestContext_t * md, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psSha1Final(psDigestContext_t * md, unsigned char *hash);

#ifdef USE_HMAC
PSPUBLIC int32 psHmacSha1(unsigned char *key, uint32 keyLen,
				const unsigned char *buf, uint32 len,
				unsigned char *hash, unsigned char *hmacKey,
				uint32 *hmacKeyLen);
PSPUBLIC void psHmacSha1Init(psHmacContext_t *ctx, unsigned char *key,
				uint32 keyLen);
PSPUBLIC void psHmacSha1Update(psHmacContext_t *ctx, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psHmacSha1Final(psHmacContext_t *ctx, unsigned char *hash);
#endif /* USE_HMAC */
#endif /* USE_SHA1 */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_SHA256
#ifdef USE_HMAC
PSPUBLIC int32 psHmacSha2(unsigned char *key, uint32 keyLen,
				const unsigned char *buf, uint32 len,
				unsigned char *hash, unsigned char *hmacKey,
				uint32 *hmacKeyLen, uint32 hashSize);
PSPUBLIC void psHmacSha2Init(psHmacContext_t *ctx, unsigned char *key,
				uint32 keyLen, uint32 hashSize);
PSPUBLIC void psHmacSha2Update(psHmacContext_t *ctx, const unsigned char *buf,
				uint32 len, uint32 hashSize);
PSPUBLIC int32 psHmacSha2Final(psHmacContext_t *ctx, unsigned char *hash,
				uint32 hashSize);
#endif /* USE_HMAC */
#endif /* USE_SHA256 */
/******************************************************************************/
#ifdef USE_SHA256
PSPUBLIC void psSha256Init(psDigestContext_t * md);
PSPUBLIC void psSha256Update(psDigestContext_t * md, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psSha256Final(psDigestContext_t * md, unsigned char *hash);
#endif /* USE_SHA256 */

#ifdef USE_SHA224
PSPUBLIC void psSha224Init(psDigestContext_t * md);
PSPUBLIC void psSha224Update(psDigestContext_t * md, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psSha224Final(psDigestContext_t * md, unsigned char *hash);
#endif /* USE_SHA224 */

#ifdef USE_SHA384
PSPUBLIC void psSha384Init(psDigestContext_t * md);
PSPUBLIC void psSha384Update(psDigestContext_t * md, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psSha384Final(psDigestContext_t * md, unsigned char *hash);
#endif /* USE_SHA384 */

#ifdef USE_SHA512
PSPUBLIC void psSha512Init(psDigestContext_t * md);
PSPUBLIC void psSha512Update(psDigestContext_t * md, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psSha512Final(psDigestContext_t * md, unsigned char *hash);
#endif /* USE_SHA512 */

/******************************************************************************/

#ifdef USE_ECC
PSPUBLIC int32 psEcdsaParsePrivKey(psPool_t *pool, unsigned char *keyBuf,
				int32 keyBufLen, psPubKey_t **keyPtr, psEccSet_t *curve);
PSPUBLIC int32 psEcdsaParsePrivFile(psPool_t *pool, char *fileName,
				char *password,	psPubKey_t **outkey);
PSPUBLIC int32 psEccX963ImportKey(psPool_t *pool, const unsigned char *inbuf,
				uint32 inlen, psEccKey_t *key, psEccSet_t *dp);
PSPUBLIC int32 psEccX963ExportKey(psPool_t *pool, psEccKey_t *key,
				unsigned char *outbuf, uint32 *outlen);
PSPUBLIC int32 psEccMakeKeyEx(psPool_t *pool, psEccKey_t **keyPtr,
				psEccSet_t *dp, void *eccData);
PSPUBLIC void psEccFreeKey(psEccKey_t **key);
PSPUBLIC int32 psEccGenSharedSecret(psPool_t *pool, psEccKey_t *private_key,
				psEccKey_t *public_key, unsigned char *outbuf,
				uint32 *outlen, void *eccData);
PSPUBLIC int32 psEcDsaValidateSignature(psPool_t *pool, psEccKey_t *myPubKey,
				unsigned char *signature, int32 sigLen,	unsigned char *hash,
				int32 hashLen, int32 *stat, void *eccData);
PSPUBLIC int32 psEccSignHash(psPool_t *pool, unsigned char *inbuf,
				int32 inlen, unsigned char *c, int32 outlen,
				psEccKey_t *privKey, int32 *bytesWritten, int32 includeSize,
				void *eccData);
PSPUBLIC int32 psEccSignHashForkeymaster(psPool_t *pool, unsigned char *inbuf,
				int32 inlen, unsigned char *c, int32 outlen,
				psEccKey_t *privKey, int32 *bytesWritten, int32 includeSize,
				void *eccData);


#endif /* USE_ECC */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_SM3
/******************************************************************************/
PSPUBLIC int psSm3Init(psDigestContext_t *md);
PSPUBLIC int psSm3Update(psDigestContext_t *md, unsigned char *buf, int len);
PSPUBLIC int psSm3Final(psDigestContext_t *md, unsigned char *hash);
#endif /* USE_SM3 */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_MD5
/******************************************************************************/
PSPUBLIC void psMd5Init(psDigestContext_t * md);
PSPUBLIC void psMd5Update(psDigestContext_t * md, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psMd5Final(psDigestContext_t * md, unsigned char *hash);

#ifdef USE_HMAC
PSPUBLIC int32 psHmacMd5(unsigned char *key, uint32 keyLen,
				const unsigned char *buf, uint32 len,
				unsigned char *hash, unsigned char *hmacKey,
				uint32 *hmacKeyLen);
PSPUBLIC void psHmacMd5Init(psHmacContext_t *ctx, unsigned char *key,
				uint32 keyLen);
PSPUBLIC void psHmacMd5Update(psHmacContext_t *ctx, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psHmacMd5Final(psHmacContext_t *ctx, unsigned char *hash);
#endif /* USE_HMAC */
#endif /* USE_MD5 */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_MD4
/******************************************************************************/
PSPUBLIC void psMd4Init(psDigestContext_t * md);
PSPUBLIC void psMd4Update(psDigestContext_t * md, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psMd4Final(psDigestContext_t * md, unsigned char *hash);
#endif /* USE_MD4 */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_MD2
/******************************************************************************/
PSPUBLIC void psMd2Init(psDigestContext_t * md);
PSPUBLIC int32 psMd2Update(psDigestContext_t * md, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psMd2Final(psDigestContext_t * md, unsigned char *hash);
#endif /* USE_MD2 */
/******************************************************************************/

/******************************************************************************/
/*
	Private Key Parsing
	PKCS#1 - RSA specific
	PKCS#8 - General private key storage format
*/
#ifdef USE_PRIVATE_KEY_PARSING
#ifdef USE_RSA
PSPUBLIC int32 pkcs1ParsePrivBin(psPool_t *pool, unsigned char *p,
				uint32 size, psPubKey_t **key);
#ifdef MATRIX_USE_FILE_SYSTEM
PSPUBLIC int32 pkcs1ParsePrivFile(psPool_t *pool, char *fileName,
				char *password, psPubKey_t **outkey);
#endif /* MATRIX_USE_FILE_SYSTEM */
#endif /* USE_RSA */

#ifdef MATRIX_USE_FILE_SYSTEM
PSPUBLIC int32 pkcs1DecodePrivFile(psPool_t *pool, char *fileName,
				char *password,	unsigned char **DERout, uint32 *DERlen);
#endif /* MATRIX_USE_FILE_SYSTEM */

#ifdef USE_PKCS8
PSPUBLIC int32 pkcs8ParsePrivBin(psPool_t *pool, unsigned char *p,
				int32 size, char *pass, psPubKey_t **key);
#ifdef MATRIX_USE_FILE_SYSTEM
#ifdef USE_PKCS12
PSPUBLIC int32 psPkcs12Parse(psPool_t *pool, psX509Cert_t **cert,
				psPubKey_t **privKey, const unsigned char *file, int32 flags,
				unsigned char *importPass, int32 ipasslen,
				unsigned char *privkeyPass, int32 kpasslen);
#endif /* USE_PKCS12 */
#endif /* MATRIX_USE_FILE_SYSTEM */
#endif /* USE_PKCS8 */
#endif /* USE_PRIVATE_KEY_PARSING */

/******************************************************************************/

/******************************************************************************/
#ifdef USE_PKCS5
/******************************************************************************/
/*
	PKCS#5 PBKDF v1 and v2 key generation
*/
PSPUBLIC void pkcs5pbkdf1(unsigned char *pass, uint32 passlen,
				unsigned char *salt, int32 iter, unsigned char *key);
PSPUBLIC void pkcs5pbkdf2(unsigned char *password, uint32 pLen,
				 unsigned char *salt, uint32 sLen, int32 rounds,
				 unsigned char *key, uint32 kLen);
#endif /* USE_PKCS5 */

/******************************************************************************/
/*
	Public Key Cryptography
*/
PSPUBLIC psPubKey_t *psNewPubKey(psPool_t *pool);
PSPUBLIC void psFreePubKey(psPubKey_t *key);

/******************************************************************************/
#ifdef USE_RSA
/******************************************************************************/
/*
	RSA crypto
*/
PSPUBLIC int32 psRsaGenerateKeyPair(psPool_t *pool, psRsaKey_t *key,
				unsigned short int bits, uint32 e_value, void *userPtr);

PSPUBLIC int32 psRsaDecryptPriv(psPool_t *pool, psRsaKey_t *key,
					unsigned char *in, uint32 inlen,
					unsigned char *out, uint32 outlen, void *data);
PSPUBLIC int32 psRsaDecryptPub(psPool_t *pool, psRsaKey_t *key,
					unsigned char *in, uint32 inlen,
					unsigned char *out, uint32 outlen, void *data);
PSPUBLIC int32 psRsaEncryptPub(psPool_t *pool, psRsaKey_t *key,
				unsigned char *in, uint32 inlen,
				unsigned char *out, uint32 outlen, void *data);
PSPUBLIC int32 pubRsaDecryptSignedElement(psPool_t *pool, psPubKey_t *key,
				unsigned char *in, uint32 inlen, unsigned char *out,
				uint32 outlen, void *data);
PSPUBLIC int32 psRsaEncryptPriv(psPool_t *pool, psRsaKey_t *key,
					unsigned char *in, uint32 inlen,
					unsigned char *out, uint32 outlen, void *data);
PSPUBLIC int32 privRsaEncryptSignedElement(psPool_t *pool, psPubKey_t *key,
				unsigned char *in, uint32 inlen, unsigned char *out,
				uint32 outlen, void *data);

PSPUBLIC int32 psRsaCrypt(psPool_t *pool, const unsigned char *in, uint32 inlen,
				unsigned char *out, uint32 *outlen,	psRsaKey_t *key,
				int32 type, void *data);
#endif /* USE_RSA */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_DH
/******************************************************************************/
/******************************************************************************/
/*
	PKCS#3 - Diffie-Hellman parameters
*/
PSPUBLIC int32 pkcs3ParseDhParamBin(psPool_t *pool, unsigned char *dhBin,
					int32 dhBinLen, psDhParams_t **key);
#ifdef MATRIX_USE_FILE_SYSTEM
PSPUBLIC int32 pkcs3ParseDhParamFile(psPool_t *pool, char *fileName,
					 psDhParams_t **key);
#endif /* MATRIX_USE_FILE_SYSTEM */
PSPUBLIC void pkcs3FreeDhParams(psDhParams_t *params);


PSPUBLIC int32 psDhKeyGen(psPool_t *pool, uint32 keysize, unsigned char *pBin,
					uint32 pLen, unsigned char *gBin, uint32 gLen,
					psDhKey_t *key, void *data);
PSPUBLIC int32 psDhKeyGenEx(psPool_t *pool, uint32 keysize, unsigned char *pBin,
					uint32 pLen, unsigned char *gBin, uint32 gLen,
					unsigned char *qBin, uint32 qLen,
					uint32 xbits, psDhKey_t *key, void *data);
PSPUBLIC int32 psDhKeyGenInts(psPool_t *pool, uint32 keysize, pstm_int *p,
					pstm_int *g, psDhKey_t *key, void *data);

PSPUBLIC int32 psDhGenSecret(psPool_t *pool, psDhKey_t *private_key,
					psDhKey_t *public_key, unsigned char *pBin, uint32 pLen,
					unsigned char *outbuf, uint32 *outlen, void* data);
PSPUBLIC int32 psDhImportPubKey(psPool_t *pool, unsigned char *inbuf,
					uint32 inlen, psDhKey_t *key);
PSPUBLIC int32 psDhExportPubKey(psPool_t *pool, psDhKey_t *key,
					unsigned char **out);

PSPUBLIC int32 psDhExportParameters(psPool_t *pool, psDhParams_t *key,
					uint32 *pLen, unsigned char **p, uint32 *gLen,
					unsigned char **g);
PSPUBLIC void psDhFreeKey(psDhKey_t *key);
#endif /* USE_DH */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_DSA
/******************************************************************************/
PSPUBLIC int32 psDsaParamsGen(psPool_t *pool, psDsaParams_t *params,
		unsigned int p_bits, unsigned int q_bits, void *p_rng);

PSPUBLIC int32 psDsaKeyGen(psPool_t *pool, psDsaKey_t *key,
		psDsaParams_t *params, void *p_rng);

PSPUBLIC int32 psDsaSignHash(psPool_t *pool, psDsaKey_t *key,
		psDsaParams_t *params, unsigned char *in, uint32 inLen,
		psDsaSign_t *sig, void *p_rng);

PSPUBLIC int32 psDsaVerifyHash(psPool_t *pool, psDsaKey_t *key,
		psDsaParams_t *params, unsigned char *in, uint32 inLen,
		psDsaSign_t *sig);

#endif /* USE_DSA */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_X509
/******************************************************************************/
/*
	X.509 Certificate support
*/
PSPUBLIC int32 psX509ParseCertFile(psPool_t *pool, char *fileName,
					psX509Cert_t **outcert, int32 flags);
PSPUBLIC int32 psX509ParseCert(psPool_t *pool, unsigned char *pp, uint32 size,
					psX509Cert_t **outcert, int32 flags);
PSPUBLIC void psX509FreeCert(psX509Cert_t *cert);


#ifdef USE_RSA
int32 x509ConfirmSignature(unsigned char *sigHash, unsigned char *sigOut,
							uint32 sigLen);
#endif

#ifdef USE_CERT_PARSE
PSPUBLIC int32 psX509AuthenticateCert(psPool_t *pool, psX509Cert_t *subjectCert,
					psX509Cert_t *issuerCert, psX509Cert_t **foundIssuer,
					void *hwCtx, void *poolUserPtr);
#endif

#ifdef USE_CRL
PSPUBLIC int32 psX509ParseCrl(psPool_t *pool, psX509Cert_t *CA, int append,
					unsigned char *crlBin, int32 crlBinLen, void *poolUserPtr);
#endif /* USE_CRL */
#endif /* USE_X509 */
/******************************************************************************/

/******************************************************************************/
PSPUBLIC int32 psInitPrng(psRandom_t *ctx, void *userPtr);
PSPUBLIC int32 psGetPrng(psRandom_t *ctx, unsigned char *bytes, uint32 size,
						void *userPtr);
PSPUBLIC int32 psGetPrngData(void *p_rng, unsigned char *rnd, size_t size);

#ifdef USE_YARROW
PSPUBLIC int32 psYarrowStart(psYarrow_t *ctx);
PSPUBLIC int32 psYarrowAddEntropy(unsigned char *in, uint32 inlen,
			psYarrow_t *prng);
PSPUBLIC int32 psYarrowReseed(psYarrow_t *ctx);
PSPUBLIC uint32 psYarrowRead(unsigned char *out, uint32 outlen, psYarrow_t *cx);
PSPUBLIC int32 psYarrowDone(psYarrow_t *ctx);
PSPUBLIC int32 psYarrowExport(unsigned char *out, uint32 *outlen,
			psYarrow_t *ctx);
PSPUBLIC int32 psYarrowImport(unsigned char *in, uint32 inlen, psYarrow_t *ctx);
#endif /* USE_YARROW */
/******************************************************************************/

/******************************************************************************/
/**
 * \name DER constants
 * These constants comply with DER encoded the ANS1 type tags.
 * DER encoding uses hexadecimal representation.
 * An example DER sequence is:\n
 * - 0x02 -- tag indicating INTEGER
 * - 0x01 -- length in octets
 * - 0x05 -- value
 * Such sequences are typically read into \c ::mbedtls_x509_buf.
 * \{
 */
#define MATRIXS_ASN1_BOOLEAN                 0x01
#define MATRIXS_ASN1_INTEGER                 0x02
#define MATRIXS_ASN1_BIT_STRING              0x03
#define MATRIXS_ASN1_OCTET_STRING            0x04
#define MATRIXS_ASN1_NULL                    0x05
#define MATRIXS_ASN1_OID                     0x06
#define MATRIXS_ASN1_UTF8_STRING             0x0C
#define MATRIXS_ASN1_SEQUENCE                0x10
#define MATRIXS_ASN1_SET                     0x11
#define MATRIXS_ASN1_PRINTABLE_STRING        0x13
#define MATRIXS_ASN1_T61_STRING              0x14
#define MATRIXS_ASN1_IA5_STRING              0x16
#define MATRIXS_ASN1_UTC_TIME                0x17
#define MATRIXS_ASN1_GENERALIZED_TIME        0x18
#define MATRIXS_ASN1_UNIVERSAL_STRING        0x1C
#define MATRIXS_ASN1_BMP_STRING              0x1E
#define MATRIXS_ASN1_PRIMITIVE               0x00
#define MATRIXS_ASN1_CONSTRUCTED             0x20
#define MATRIXS_ASN1_CONTEXT_SPECIFIC        0x80
/* \} name */
/* \} addtogroup asn1_module */

/*
 * CP Algorithm
 */
#define MATRIXS_AES_ECB			0x0001
#define MATRIXS_AES_CBC			0x0002
#define MATRIXS_AES_CTR			0x0003
#define MATRIXS_AES_CTS			0x0004
#define MATRIXS_AES_XTS			0x0005
#define MATRIXS_AES_GCM			0x0006
#define MATRIXS_AES_CCM			0x0007
#define MATRIXS_DES_ECB			0x0010
#define MATRIXS_DES_CBC			0x0020
#define MATRIXS_DES3_ECB		0x0030
#define MATRIXS_DES3_CBC		0x0040

/*
 * MAC Algorithm
 */
#define MATRIXS_HMAC_MD5		0x0000
#define MATRIXS_HMAC_SHA1		0x0001
#define MATRIXS_HMAC_SHA224		0x0002
#define MATRIXS_HMAC_SHA256		0x0003
#define MATRIXS_HMAC_SHA384		0x0004
#define MATRIXS_HMAC_SHA512		0x0005
#define MATRIXS_CMAC_AES		0x0010
#define MATRIXS_CBCMAC_AES		0x0020
#define MATRIXS_CBCMAC_DES		0x0021
#define MATRIXS_CBCMAC_DES3		0x0022

/*
 * RSA constants
 */
#define MATRIXS_CP_ENCRYPT		0x0000
#define MATRIXS_CP_DECRYPT		0x0001

/*
 * RSA constants
 */
#define MATRIXS_MD_MAX_SIZE     			64		/* longest known is SHA512 */
#define MATRIXS_MPI_MAX_SIZE 			  1024

#define MATRIXS_DSA_PUBLIC				  PUBKEY_TYPE
#define MATRIXS_DSA_PRIVATE     		  PRIVKEY_TYPE

#define MATRIXS_RSA_PUBLIC      		  PUBKEY_TYPE
#define MATRIXS_RSA_PRIVATE     		  PRIVKEY_TYPE

#define MATRIXS_RSA_PKCS_V15    			 0
#define MATRIXS_RSA_PKCS_V21    			 1

#define MATRIXS_RSA_SIGN        			 1
#define MATRIXS_RSA_CRYPT       			 2
#define MATRIXS_RSA_SALT_LEN_ANY    		-1

/*
 * Error codes
 */
#define MATRIXS_ERR_CP_CONT_INPUT_DATA		 			     1000
#define MATRIXS_ERR_CP_BAD_INPUT_DATA					  -0x4000

#define MATRIXS_ERR_MC_BAD_INPUT_DATA 					  -0x4010
#define MATRIXS_ERR_RSA_BAD_INPUT_DATA                    -0x4080  /**< Bad input parameters to function. */
#define MATRIXS_ERR_RSA_INVALID_PADDING                   -0x4100  /**< Input data contains invalid padding and is rejected. */
#define MATRIXS_ERR_RSA_KEY_GEN_FAILED                    -0x4180  /**< Something failed during generation of a key. */
#define MATRIXS_ERR_RSA_KEY_CHECK_FAILED                  -0x4200  /**< Key failed to pass the library's validity check. */
#define MATRIXS_ERR_RSA_PUBLIC_FAILED                     -0x4280  /**< The public key operation failed. */
#define MATRIXS_ERR_RSA_PRIVATE_FAILED                    -0x4300  /**< The private key operation failed. */
#define MATRIXS_ERR_RSA_VERIFY_FAILED                     -0x4380  /**< The PKCS#1 verification failed. */
#define MATRIXS_ERR_RSA_OUTPUT_TOO_LARGE                  -0x4400  /**< The output buffer for decryption is not large enough. */
#define MATRIXS_ERR_RSA_RNG_FAILED                        -0x4480  /**< The random generator failed to generate non-zeros. */

#define MATRIXS_ERR_DSA_SIGN_FAILED						  -0x4800
#define MATRIXS_ERR_DSA_VERIFY_FAILED					  -0x4810

typedef struct {
	size_t len;
	psDigestContext_t ctx;
} matrixs_md_context_t;

typedef struct {
	psAesKey_t	ctx;

	union {
	struct { unsigned char ecount[16];
			 unsigned int	      num;} ctr;
	struct { psAesKey_t			  ctx;
			 struct xts128_context  c;} xts;
	struct { unsigned int	   addlen;
			 unsigned int	   taglen;
			 struct ccm128_context  c;} ccm;
	struct { unsigned int	   taglen;
			 struct gcm128_context  c;} gcm;
	} mode;
} matrixs_cp_aes_t;

typedef struct {
	psDes3Key_t ctx;
} matrixs_cp_des_t;

typedef struct {
	psRsaKey_t ctx;
	matrixs_md_context_t hash;
} matrixs_rsa_context_t;

typedef struct {
	psDhKey_t ctx;
	psDhParams_t params;
} matrixs_dh_context_t;

typedef struct {
	psDsaKey_t ctx;
	psDsaSign_t sign;
	psDsaParams_t params;
} matrixs_dsa_context_t;

typedef struct {
	unsigned int	kind;		/* sym: cipher kind */
	unsigned int	flags;		/* flags */
	unsigned int	keylen;
	unsigned char	keyval[32];
	unsigned int	keylen2;
	unsigned char	keyval2[32];
	unsigned char   ivec[16];
	unsigned char	block[32];
	unsigned  int	blocklen;
	unsigned int	mode;		/* asym: public or private */
	unsigned int	paylen;		/* paylen */

	union {
		matrixs_cp_aes_t aes;
		matrixs_cp_des_t des;
		matrixs_dh_context_t  dh;
		matrixs_rsa_context_t rsa;
		matrixs_dsa_context_t dsa;
	} c;
} matrixs_cp_context_t;

typedef struct {
	unsigned char		 ipad[128];
	unsigned char		 opad[128];
	unsigned  int		 blocksize;
	matrixs_md_context_t md;
} matrixs_hmac_context_t;

typedef struct {
	psCmacContext_t 	 ctx;
} matrixs_cmac_context_t;

typedef struct {
	int32         		 last_len;
	unsigned char 		 last[16];
	unsigned char		 padding;	// 0: none 1:pkcs#5
	matrixs_cp_context_t cp;
} matrixs_cbcmac_context_t;

typedef struct {
	unsigned int	kind;
	unsigned int	keylen;
	unsigned char	keyval[128];
	unsigned char   ivec[16] ;

	union {
		matrixs_hmac_context_t	 hmac;
		matrixs_cmac_context_t 	 cmac;
		matrixs_cbcmac_context_t cbcmac;
	};
} matrixs_mc_context_t;

PSPUBLIC int  matrix_check_prime( unsigned char *buf, size_t buflen );
PSPUBLIC void matrixs_random(void *p_rng, unsigned char *salt, size_t saltlen);
PSPUBLIC int  matrixs_md_valid(matrixs_md_context_t *md_ctx);
PSPUBLIC void matrixs_md_starts(matrixs_md_context_t *md_ctx);
PSPUBLIC void matrixs_md_update(matrixs_md_context_t *md_ctx, unsigned char *input, size_t ilen);
PSPUBLIC void matrixs_md_finish(matrixs_md_context_t *md_ctx, unsigned char *output);
PSPUBLIC int  matrixs_mc_setkey( matrixs_mc_context_t *mc_ctx, unsigned int kind, unsigned char *key, unsigned int keylen);
PSPUBLIC int  matrixs_mc_starts( matrixs_mc_context_t *mac_ctx, unsigned char *ivec, size_t iveclen, unsigned char padding);
PSPUBLIC int  matrixs_mc_update( matrixs_mc_context_t *mac_ctx, unsigned char *input, size_t ilen);
PSPUBLIC int  matrixs_mc_finish( matrixs_mc_context_t *mac_ctx, unsigned char *mac, size_t *maclen);
PSPUBLIC int  matrixs_cp_setkey( matrixs_cp_context_t *cp_ctx, unsigned int kind, unsigned char *key, unsigned int keylen, unsigned char *key2, unsigned int keylen2);
PSPUBLIC int  matrixs_cp_starts( matrixs_cp_context_t *cp_ctx, unsigned char *ivec, size_t iveclen);
PSPUBLIC int  matrixs_cp_update( matrixs_cp_context_t *cp_ctx, int mode, unsigned char *input, size_t inlen, unsigned char *output, size_t *outlen);
PSPUBLIC int  matrixs_cp_finish( matrixs_cp_context_t *cp_ctx, int mode, unsigned char *input, size_t inlen, unsigned char *output, size_t *outlen);
PSPUBLIC int  matrixs_ae_setkey( matrixs_cp_context_t *mc_ctx, unsigned int kind, unsigned char *key, unsigned int keylen);
PSPUBLIC int  matrixs_ae_starts( matrixs_cp_context_t *cp_ctx, unsigned char *ivec, size_t iveclen, size_t taglen, size_t addlen, size_t paylen);
PSPUBLIC int  matrixs_ae_update_add( matrixs_cp_context_t *cp_ctx, unsigned char *add, size_t addlen);
PSPUBLIC int  matrixs_ae_update( matrixs_cp_context_t *cp_ctx, int mode, unsigned char *input, size_t inlen, unsigned char *output, size_t *outlen);
PSPUBLIC int  matrixs_ae_encrypt_finish( matrixs_cp_context_t *cp_ctx, unsigned char *input, size_t inlen, unsigned char *output, size_t *outlen, unsigned char *tag, size_t *taglen );
PSPUBLIC int  matrixs_ae_decrypt_finish( matrixs_cp_context_t *cp_ctx, unsigned char *input, size_t inlen, unsigned char *output, size_t *outlen, unsigned char *tag, size_t taglen );
PSPUBLIC int  matrixs_rsa_public(matrixs_rsa_context_t *rsa, unsigned char *input, size_t inlen, unsigned char *output, size_t *outlen);
PSPUBLIC int  matrixs_rsa_private(matrixs_rsa_context_t *rsa, unsigned char *input, size_t inlen,	unsigned char *output, size_t *outlen);
PSPUBLIC int  matrixs_oid_get_oid_by_md(matrixs_md_context_t *md_ctx, unsigned char **oid, size_t *olen);
PSPUBLIC int  matrixs_oid_check_oid_by_md(matrixs_md_context_t *md_ctx,	unsigned char *oid, size_t oidlen);
PSPUBLIC void matrixs_mgf_mask( unsigned char *dst, size_t dlen, unsigned char *src, size_t slen, matrixs_md_context_t *md_ctx );
PSPUBLIC int  matrixs_rsa_rsaes_oaep_encrypt(matrixs_rsa_context_t *rsa, int mode, unsigned char *input, size_t inlen, unsigned char *label, size_t label_len, unsigned char *output, void *p_rng);
PSPUBLIC int  matrixs_rsa_rsaes_oaep_decrypt( matrixs_rsa_context_t *rsa, int mode, unsigned char *input, size_t inlen, unsigned char *label, size_t label_len,	unsigned char *output, size_t *outlen, void *p_rng );
PSPUBLIC int  matrixs_rsa_rsaes_pkcs1_v15_encrypt( matrixs_rsa_context_t *rsa, int mode, unsigned char *input, size_t inlen, unsigned char *output, void *p_rng);
PSPUBLIC int  matrixs_rsa_rsaes_pkcs1_v15_decrypt(matrixs_rsa_context_t *rsa, int mode, unsigned char *input, size_t inlen, unsigned char *output, size_t *outlen, void *p_rng);
PSPUBLIC int  matrixs_rsa_rsassa_pss_sign(matrixs_rsa_context_t *rsa, int mode, unsigned char *hash, size_t hashlen, unsigned char *salt, size_t saltlen, unsigned char *sig, void *p_rng);
PSPUBLIC int  matrixs_rsa_rsassa_pss_verify(matrixs_rsa_context_t *rsa,	int mode, unsigned char *hash, size_t hashlen, unsigned char *salt, size_t saltlen, unsigned char *sig, void *p_rng);
PSPUBLIC int  matrixs_rsa_rsassa_pkcs1_v15_sign(matrixs_rsa_context_t *rsa,	int mode, unsigned char *hash, size_t hashlen, unsigned char *sig, void *p_rng);
PSPUBLIC int  matrixs_rsa_rsassa_pkcs1_v15_verify(matrixs_rsa_context_t *rsa, int mode, unsigned char *hash, size_t hashlen, unsigned char *sig, void *p_rng);
PSPUBLIC int  matrixs_dsa_sign(matrixs_dsa_context_t *dsa, unsigned char *hash, size_t hashlen, unsigned char *sig, size_t *siglen, void *p_rng);
PSPUBLIC int  matrixs_dsa_verify(matrixs_dsa_context_t *dsa, unsigned char *hash, size_t hashlen, unsigned char *sig, size_t siglen, void *p_rng);
/******************************************************************************/

#endif /* _h_PS_CRYPTOAPI */
/******************************************************************************/

