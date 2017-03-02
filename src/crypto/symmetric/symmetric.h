/**
 *	@file    symmetric.h
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	Header for internal symmetric key cryptography support.
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

#ifndef _h_PS_SYMMETRIC
#define _h_PS_SYMMETRIC

/******************************************************************************/
#ifdef USE_AES
/******************************************************************************/

typedef struct {
	uint32 eK[64], dK[64];
	int32 Nr;
} psAesKey_t;

typedef struct {
	psAesKey_t		key;
	int32			blocklen;
	unsigned char	IV[16];

#ifdef USE_AES_CTR
	unsigned int	UsedBlockNumber;
	unsigned char	EncryptedCount[16];
#endif
} psAesCipher_t;

#endif /* USE_AES */

/******************************************************************************/
#ifdef USE_SM4
/******************************************************************************/
/* SM4 operation context structure */
typedef struct {
	unsigned int  rk[32];
} psSm4Key_t;

#endif


#ifdef USE_IDEA
#define SSL_IDEA_KEY_LEN	16
#define SSL_IDEA_IV_LEN		8
#define SSL_IDEA_BLOCK_LEN	8

typedef struct {
	uint16	key_schedule[52];
} psIdeaKey_t;

typedef struct {
	psIdeaKey_t		key;
	uint32			IV[2];
	short			for_encryption;
	short			inverted;
} idea_CBC;
#endif
/******************************************************************************/

/******************************************************************************/
#ifdef USE_SEED
/******************************************************************************/
#define SSL_SEED_KEY_LEN	16
#define SSL_SEED_IV_LEN		16


typedef struct {
	uint32 K[32], dK[32];
} psSeedKey_t;

typedef struct {
	int32			blocklen;
	unsigned char	IV[16];
	psSeedKey_t		key;
} seed_CBC;

#endif /* USE_SEED */
/******************************************************************************/

/******************************************************************************/
#if defined(USE_3DES) || defined(USE_DES)
/******************************************************************************/
#define DES3_KEY_LEN	24
#define DES3_IV_LEN		8
#define DES_KEY_LEN		8

typedef struct {
	uint32 ek[3][32], dk[3][32];
} psDes3Key_t;

/*
	A block cipher CBC structure
 */
typedef struct {
	int32				blocklen;
	unsigned char		IV[8];
	psDes3Key_t			key;
} des3_CBC;

#endif /* USE_3DES || USE_DES */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_ARC4
typedef struct {
	unsigned char	state[256];
	uint32	byteCount;
	unsigned char	x;
	unsigned char	y;
} psRc4Key_t;
#endif /* USE_ARC4 */
/******************************************************************************/
#ifdef USE_RC2
typedef struct {
	unsigned xkey[64];
} psRc2Key_t;

typedef struct {
	int32				blocklen;
	unsigned char		IV[8];
	psRc2Key_t			key;
} rc2_CBC;
#endif /* USE_RC2 */
/******************************************************************************/
/*	Universal types and defines */
/******************************************************************************/
#define MAXBLOCKSIZE	24

typedef union {
#ifdef USE_RC2
	rc2_CBC		rc2;
#endif
#ifdef USE_ARC4
	psRc4Key_t	arc4;
#endif
#ifdef USE_3DES
	des3_CBC	des3;
#endif
#ifdef USE_AES
	psAesCipher_t	aes;
#endif
#ifdef USE_SEED
	seed_CBC	seed;
#endif
#ifdef USE_IDEA
	idea_CBC	idea;
#endif
} psCipherContext_t;

#define byte(x, n) (((x) >> (8 * (n))) & 255)

/******************************************************************************/
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;

/******************************************************************************/
typedef void (*block64_f)(const unsigned char in[8],
			unsigned char out[8],
			const void *key);

typedef void (*block128_f)(const unsigned char in[16],
			unsigned char out[16],
			const void *key);

typedef void (*cbc128_f)(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], int enc);

typedef void (*ctr128_f)(const unsigned char *in, unsigned char *out,
			size_t blocks, const void *key,
			const unsigned char ivec[16]);

typedef void (*ccm128_f)(const unsigned char *in, unsigned char *out,
			size_t blocks, const void *key,
			const unsigned char ivec[16],unsigned char cmac[16]);

/*
 * 32-bit integer manipulation macros (big endian)
 */
#define GETU32(p)       ((u32)(p)[0]<<24|(u32)(p)[1]<<16|(u32)(p)[2]<<8|(u32)(p)[3])
#define PUTU32(p,v)     ((p)[0]=(u8)((v)>>24),(p)[1]=(u8)((v)>>16),(p)[2]=(u8)((v)>>8),(p)[3]=(u8)(v))

#define REDUCE1BIT(V)	do { \
	if (sizeof(size_t)==8) { \
		u64 T = U64(0xe100000000000000) & (0-(V.lo&1)); \
		V.lo  = (V.hi<<63)|(V.lo>>1); \
		V.hi  = (V.hi>>1 )^T; \
	} \
	else { \
		u32 T = 0xe1000000U & (0-(u32)(V.lo&1)); \
		V.lo  = (V.hi<<63)|(V.lo>>1); \
		V.hi  = (V.hi>>1 )^((u64)T<<32); \
	} \
} while(0)
#define	PACK(s)			((size_t)(s)<<(sizeof(size_t)*8-16))
#define U64(C)     		C##ULL
#define assert(_exp) 	( (void)0 )

/******************************************************************************/
/* GCM definitions */

typedef struct { u64 hi,lo; } u128;

struct gcm128_context {
	/* Following 6 names follow names in GCM specification */
	union { u64 u[2]; u32 d[4]; u8 c[16]; } Yi,EKi,EK0,len,Xi,H;

	/* Relative position of Xi, H and pre-computed Htable is used
	 * in some assembler modules, i.e. don't change the order! */
	u128 Htable[16];

	unsigned int mres, ares;
	block128_f block;
	void *key;
};

struct xts128_context {
	void      *key1, *key2;
	block128_f block1,block2;
	union { u64 u[2]; u32 d[4]; u8 c[16]; } tweak, scratch;
};

struct ccm128_context {
	union { u64 u[2]; u8 c[16]; } nonce, cmac;
	u64 blocks;
	block128_f block;
	void *key;
	u8 flags0, flags1; u32 paylen;
};

/******************************************************************************/
/* Function definitions */
extern void ecb64_encrypt(const unsigned char *in, unsigned char *out,
		size_t len, const void *key, block64_f block);
extern void ecb64_decrypt(const unsigned char *in, unsigned char *out,
		size_t len, const void *key, block64_f block);

extern void ecb128_encrypt(const unsigned char *in, unsigned char *out,
		size_t len, const void *key, block128_f block);
extern void ecb128_decrypt(const unsigned char *in, unsigned char *out,
		size_t len, const void *key, block128_f block);

extern void cbc64_encrypt(const unsigned char *in, unsigned char *out,
		size_t len, const void *key,
		unsigned char ivec[8], block64_f block);
extern void cbc64_decrypt(const unsigned char *in, unsigned char *out,
		size_t len, const void *key,
		unsigned char ivec[8], block64_f block);

extern void cbc128_encrypt(const unsigned char *in, unsigned char *out,
		size_t len, const void *key,
		unsigned char ivec[16], block128_f block);
extern void cbc128_decrypt(const unsigned char *in, unsigned char *out,
		size_t len, const void *key,
		unsigned char ivec[16], block128_f block);

extern void ctr128_encrypt(const unsigned char *in, unsigned char *out,
		size_t len, const void *key,
		unsigned char ivec[16], unsigned char ecount_buf[16],
		unsigned int *num, block128_f block);
extern void ctr128_encrypt_ctr32(const unsigned char *in, unsigned char *out,
		size_t len, const void *key,
		unsigned char ivec[16], unsigned char ecount_buf[16],
		unsigned int *num, ctr128_f func);

extern size_t cts128_encrypt_block(const unsigned char *in, unsigned char *out,
		size_t len, const void *key,
		unsigned char ivec[16], block128_f block);
extern size_t cts128_encrypt(const unsigned char *in, unsigned char *out,
		size_t len, const void *key,
		unsigned char ivec[16], cbc128_f cbc);
extern size_t cts128_decrypt_block(const unsigned char *in, unsigned char *out,
		size_t len, const void *key,
		unsigned char ivec[16], block128_f block);
extern size_t cts128_decrypt(const unsigned char *in, unsigned char *out,
		size_t len, const void *key,
		unsigned char ivec[16], cbc128_f cbc);

extern size_t nistcts128_encrypt_block(const unsigned char *in, unsigned char *out,
		size_t len, const void *key,
		unsigned char ivec[16], block128_f block);
extern size_t nistcts128_encrypt(const unsigned char *in, unsigned char *out,
		size_t len, const void *key,
		unsigned char ivec[16], cbc128_f cbc);
extern size_t nistcts128_decrypt_block(const unsigned char *in, unsigned char *out,
		size_t len, const void *key,
		unsigned char ivec[16], block128_f block);
extern size_t nistcts128_decrypt(const unsigned char *in, unsigned char *out,
		size_t len, const void *key,
		unsigned char ivec[16], cbc128_f cbc);

extern void gcm128_init(struct gcm128_context *ctx,
		void *key, block128_f block);
extern void gcm128_setiv(struct gcm128_context *ctx,
		const unsigned char *iv, size_t len);
extern int gcm128_aad(struct gcm128_context *ctx,
		const unsigned char *aad, size_t len);
extern int gcm128_encrypt(struct gcm128_context *ctx,
		const unsigned char *in, unsigned char *out, size_t len);
extern int gcm128_decrypt(struct gcm128_context *ctx,
		const unsigned char *in, unsigned char *out,size_t len);
extern int gcm128_encrypt_ctr32(struct gcm128_context *ctx,
		const unsigned char *in, unsigned char *out,
		size_t len, ctr128_f stream);
extern int gcm128_decrypt_ctr32(struct gcm128_context *ctx,
		const unsigned char *in, unsigned char *out,
		size_t len, ctr128_f stream);
extern int gcm128_finish(struct gcm128_context *ctx,
		const unsigned char *tag, size_t len);
extern void gcm128_tag(struct gcm128_context *ctx,
		unsigned char *tag, size_t len);

extern void ccm128_init(struct ccm128_context *ctx,
		unsigned int M, unsigned int L, void *key, block128_f block);
extern int ccm128_setiv(struct ccm128_context *ctx,
		const unsigned char *nonce, size_t nlen, size_t mlen);
extern void ccm128_aad(struct ccm128_context *ctx,
		const unsigned char *aad, size_t alen);
extern int ccm128_encrypt(struct ccm128_context *ctx,
		const unsigned char *inp, unsigned char *out, size_t len);
extern int ccm128_decrypt(struct ccm128_context *ctx,
		const unsigned char *inp, unsigned char *out, size_t len);
extern int ccm128_encrypt_ccm64(struct ccm128_context *ctx,
		const unsigned char *inp, unsigned char *out, size_t len,
		ccm128_f stream);
extern int ccm128_decrypt_ccm64(struct ccm128_context *ctx,
		const unsigned char *inp, unsigned char *out, size_t len,
		ccm128_f stream);
extern size_t ccm128_tag(struct ccm128_context *ctx,
		unsigned char *tag, size_t len);

extern int nistccm128_encrypt_block(struct ccm128_context *ctx,
		const unsigned char *inp, unsigned char *out, size_t len);
extern int nistccm128_encrypt_finish(struct ccm128_context *ctx,
		const unsigned char *inp, unsigned char *out, size_t len);
extern int nistccm128_decrypt_block(struct ccm128_context *ctx,
		const unsigned char *inp, unsigned char *out, size_t len);
extern int nistccm128_decrypt_finish(struct ccm128_context *ctx,
		const unsigned char *inp, unsigned char *out, size_t len);

extern int xts128_encrypt(const struct xts128_context *ctx,
		const unsigned char iv[16], const unsigned char *inp,
		unsigned char *out, size_t len, int enc);
extern void xts128_init(struct xts128_context *ctx,
		const unsigned char iv[16],
		void *key1, void *key2, block128_f block);
extern int xts128_update(struct xts128_context *ctx,
		const unsigned char *inp, unsigned char *out, size_t len);
extern int xts128_finish(struct xts128_context *ctx,
		const unsigned char *inp, unsigned char *out, size_t len, int enc);
#endif /* _h_PS_SYMMETRIC */
/******************************************************************************/
