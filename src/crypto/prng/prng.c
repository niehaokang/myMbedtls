/**
 *	@file    prng.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	Psuedo random number generation.
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
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/entropy_poll.h>

static short gPrngInit = 0;
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;




void psOpenPrng(void) {

	gPrngInit = 1;

	mbedtls_ctr_drbg_init( &g_ctr_drbg );
	mbedtls_entropy_init( &g_entropy );
	mbedtls_entropy_add_source( &g_entropy,
			mbedtls_hardware_poll, NULL,
			MBEDTLS_ENTROPY_MIN_PLATFORM, MBEDTLS_ENTROPY_SOURCE_STRONG );
	mbedtls_ctr_drbg_seed( &g_ctr_drbg,
			mbedtls_entropy_func, &g_entropy, NULL, 0);

	return ;
};

void psClosePrng(void) {

};

/*
	Allow NULL context if caller is just doing a single read
*/
int32 psGetPrngData(void *p_rng, unsigned char *rnd, size_t size)
{
	if ( p_rng != NULL ) {
		return mbedtls_ctr_drbg_random( p_rng, rnd, size );
	}

	if ( gPrngInit == 0 ) {
		//printf("keymaster open prng\n");
		psOpenPrng();
	}

	return mbedtls_ctr_drbg_random( &g_ctr_drbg, rnd, size );
}

/*	Main PRNG retrieval API for Matrix based apps to lock all PRNG and entropy
	fetches */
	#if 0
int32 matrixCryptoGetPrngData(unsigned char *bytes, uint32 size, void *userPtr)
{
	((void)userPtr);

	return psGetPrngData( NULL, bytes, size );
}
#endif

int32 matrixCryptoGetPrngData(unsigned char *bytes, uint32 size, void *userPtr)
{
     ((void)userPtr);
     int ret = 0;

     ret = psGetPrngData( NULL, bytes, size );
     if ( ret != 0 ) return ret;

     return size;
}


#if 0
#ifdef USE_MULTITHREADING
static psMutex_t			prngLock;
#endif

static psRandom_t gMatrixPrng;
static short	gPrngInit = 0;

/* One-time global prng lock creation and prng context */
void psOpenPrng(void)
{
#ifdef USE_MULTITHREADING
	psCreateMutex(&prngLock);
#endif
	/* NOTE: if a PRNG is enabled, the low level psGetEntropy call can't
		have a useful userPtr context becuase there will be no session
		context at this early stage */
	psInitPrng(&gMatrixPrng, NULL);
	gPrngInit = 1;
	return;
}
/* One-time global prng lock destruction */
void psClosePrng(void)
{
#ifdef USE_MULTITHREADING
	psDestroyMutex(&prngLock);
#endif
	return;
}

/*	Main PRNG retrieval API for Matrix based apps to lock all PRNG and entropy
	fetches */
int32 matrixCryptoGetPrngData(unsigned char *bytes, uint32 size, void *userPtr)
{
	int32	rc;

	if (gPrngInit == 0) {
		return PS_FAILURE;
	}
#ifdef USE_MULTITHREADING
	psLockMutex(&prngLock);
#endif /* USE_MULTITHREADING */
	rc = psGetPrng(&gMatrixPrng, bytes, size, userPtr);
#ifdef USE_MULTITHREADING
	psUnlockMutex(&prngLock);
#endif /* USE_MULTITHREADING */
	return rc;
}

int32 psGetPrngData(void *p_rng, unsigned char *bytes, size_t size)
{
	typedef void (*randfunc)(unsigned char*, uint32);

	if ( p_rng ) {
		((randfunc)p_rng)(bytes, size); return 0;
	}

	psGetPrng(NULL, bytes, (uint32)size, NULL);
	return 0;
}

/*
	Priority order of PRNG algorithms and then default GetEntropy if none.
	Does an initial entropy source and reseeding
*/
int32 psInitPrng(psRandom_t *ctx, void *userPtr)
{
#if defined(USE_FORTUNA) || defined(USE_YARROW)
	unsigned char	entropyBytes[RANDOM_ENTROPY_BYTES];
	int32			rc;
#endif

	ctx->bytecount = 0;

#if defined(USE_FORTUNA) || defined(USE_YARROW)
	if ((rc = psGetEntropy(entropyBytes, RANDOM_ENTROPY_BYTES, userPtr)) < 0) {
		return rc;
	}
#endif

#ifdef USE_YARROW
	if ((rc = psYarrowStart(&ctx->yarrow)) < 0) {
		return rc;
	}
	if ((rc = psYarrowAddEntropy(entropyBytes, RANDOM_ENTROPY_BYTES,
			&ctx->yarrow)) < 0) {
		return rc;
	}
	if ((rc = psYarrowReseed(&ctx->yarrow)) < 0) {
		return rc;
	}
#endif
	return PS_SUCCESS;
}

/*
	Performs the read
*/
static int32 readRandomData(psRandom_t *ctx, unsigned char *bytes, uint32 size,
				void *userPtr)
{
#if defined(USE_FORTUNA) || defined(USE_YARROW)
	unsigned char	entropyBytes[RANDOM_ENTROPY_BYTES];
	int32			rc;
#endif
/*
	Return random data.  The defines above control how often to add
	entropy and reseed the key.
*/
	ctx->bytecount += size;

#ifdef USE_YARROW
	if (ctx->bytecount >= RANDOM_BYTES_BEFORE_ENTROPY) {
		ctx->bytecount = 0;
		if ((rc = psGetEntropy(entropyBytes, RANDOM_ENTROPY_BYTES, userPtr))
				< 0) {
			return rc;
		}
		if ((rc = psYarrowAddEntropy(entropyBytes, RANDOM_ENTROPY_BYTES,
				&ctx->yarrow)) < 0) {
			return rc;
		}
		if ((rc = psYarrowReseed(&ctx->yarrow)) < 0) {
			return rc;
		}
	}
	return psYarrowRead(bytes, size, &ctx->yarrow);
#endif
/*
	If no PRNG algorithms defined, default to the low level GetEntropy function
	for all the randomness
*/
	return psGetEntropy(bytes, size, userPtr);
}

/*
	Allow NULL context if caller is just doing a single read
*/
int32 psGetPrng(psRandom_t *ctx, unsigned char *bytes, uint32 size,
			void *userPtr)
{
	psRandom_t		lctx;

	if (ctx == NULL) {
		psInitPrng(&lctx, userPtr);
		return readRandomData(&lctx, bytes, size, userPtr);
	}
	return readRandomData(ctx, bytes, size, userPtr);
}
#endif

