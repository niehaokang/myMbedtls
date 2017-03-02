/**
 *	@file    dsa.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	 The DSA publickey algorithm.
 */
/*
 *	Copyright (c) 2013-2015 INSIDE Secure Corporation
 *	Copyright (c) PeerSec Networks, 2002-2011
 *	All Rights Reserved
 *
 *	The latest version of this code is available at http://www.???.org
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
#include "../mbedtls/bignum.h"
#include "../mbedtls/entropy.h"
#include "../mbedtls/entropy_poll.h"
#include "../mbedtls/ctr_drbg.h"

/******************************************************************************/
#ifdef USE_DSA
/******************************************************************************/

#define DSA_PUBLIC		0x01
#define DSA_PRIVATE		0x02

/*
	Hash
*/
static int psdsa_hash(unsigned char *data, size_t size,
		unsigned char *digest, size_t digest_size)
{
	int ret = 0;
	psDigestContext_t md;

	switch (digest_size)
	{
		case SHA224_HASH_SIZE: {
			psSha224Init(&md);
			psSha224Update(&md, data, size);
			psSha224Final(&md, digest);
			break;
		}
		case SHA256_HASH_SIZE:{
			psSha256Init(&md);
			psSha256Update(&md, data, size);
			psSha256Final(&md, digest);
			break;
		}
		case SHA384_HASH_SIZE:{
			psSha384Init(&md);
			psSha384Update(&md, data, size);
			psSha384Final(&md, digest);
			break;
		}
		case SHA512_HASH_SIZE:{
			psSha512Init(&md);
			psSha512Update(&md, data, size);
			psSha512Final(&md, digest);
			break;
		}
		default:{
			psSha1Init(&md);
			psSha1Update(&md, data, size);
			psSha1Final(&md, digest);
			break;
		}
	}

	return ret;
}

/*
	Generate a random number N with given bitlength (note: MSB can be 0)
*/
static int psdsa_rand_bits(psPool_t *pool,
		mbedtls_mpi *N, int bits, void *p_rng)
{
	int ret = 0, bytes;
	unsigned char mask, *rbuf;

	bytes = ( bits +7 ) >> 3;
	mask = 0xff << ( 8 - bits % 8 );

	rbuf = (unsigned char *)psMalloc(pool, bytes);
	if ( rbuf == NULL) {
		return PS_MEM_FAIL;
	}

	psGetPrngData(p_rng, rbuf, bytes);

	rbuf[0] &= ~mask;
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( N, rbuf, bytes ) );

cleanup:
	if (rbuf != NULL) psFree(pool, rbuf);

	return ret;
}

/*
 * Valid sizes, according to FIPS 186-3 are (p_bits, q_bits)
 * (1024, 160), (2048, 224), (2048, 256), (3072, 256).
 */
int32 psDsaParamsGen(psPool_t *pool, psDsaParams_t *params,
		unsigned int p_bits, unsigned int q_bits, void *p_rng)
{
	int ret = 0, i = 0, j = 0, len = 0;
	unsigned char seeds[64], digest[64], *wbuf;

	unsigned int L, N, n;
	unsigned int digest_size, found_p, found_q, counter;

	mbedtls_mpi P, Q, G, U, S, W, X, Y, E, H, T2S, T2Q, T2L1, T2N1;

	/* FIPS-186-4 A.1.1.2 Generation of the Probable Primes p and q Using an Approved Hash Function
	 *
	 * L = The desired length of the prime p (in bits e.g. L = 1024)
	 * N = The desired length of the prime q (in bits e.g. N = 160)
	 * seedlen = The desired bit length of the domain parameter seed; seedlen shallbe equal to or greater than N
	 * outlen  = The bit length of Hash function
	 *
	 * 1.  Check that the (L, N)
	 * 2.  If (seedlen <N), then return INVALID.
	 * 3.  n = ceil(L / outlen) - 1
	 * 4.  b = L- 1 - (n * outlen)
	 * 5.  domain_parameter_seed = an arbitrary sequence of seedlen bits
	 * 6.  U = Hash (domain_parameter_seed) mod 2^(N-1)
	 * 7.  q = 2^(N-1) + U + 1 - (U mod 2)
	 * 8.  Test whether or not q is prime as specified in Appendix C.3
	 * 9.  If q is not a prime, then go to step 5.
	 * 10. offset = 1
	 * 11. For counter = 0 to (4L- 1) do {
	 *       For j=0 to n do {
	 *         Vj = Hash ((domain_parameter_seed+ offset + j) mod 2^seedlen)
	 *       }
	 *       W = V0 + (V1 *2^outlen) + ... + (Vn-1 * 2^((n-1) * outlen)) + ((Vn mod 2^b) * 2^(n * outlen))
	 *       X = W + 2^(L-1)           Comment: 0 <= W < 2^(L-1); hence 2^(L-1) <= X < 2^L
	 *       c = X mod 2*q
	 *       p = X - (c - 1)           Comment: p ~ 1 (mod 2*q)
	 *       If (p >= 2^(L-1)) {
	 *         Test whether or not p is prime as specified in Appendix C.3.
	 *         If p is determined to be prime, then return VALID and the values of p, qand (optionally) the values of domain_parameter_seed and counter
	 *       }
	 *       offset = offset + n + 1   Comment: Increment offset
	 *     }
	 */

	/* M-R tests (when followed by one Lucas test) according FIPS-186-4 - Appendix C.3 - table C.1 */
	L = p_bits; N = q_bits;

	if		(N <= 160) digest_size = SHA1_HASH_SIZE;
	else if	(N <= 224) digest_size = SHA224_HASH_SIZE;
	else if	(N <= 256) digest_size = SHA256_HASH_SIZE;
	else if	(N <= 384) digest_size = SHA384_HASH_SIZE;
	else if	(N <= 512) digest_size = SHA512_HASH_SIZE;
	else	return PS_ARG_FAIL;

	/* ------------------------------------------------------------------------------- */
	n = ((L + (digest_size << 3) - 1) / (digest_size << 3)) - 1;
	wbuf = (unsigned char *)psMalloc(pool, (n + 1) * digest_size);
	if ( wbuf == NULL) {
		return PS_MEM_FAIL;
	}

	mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q ); mbedtls_mpi_init( &G ); mbedtls_mpi_init( &U );
	mbedtls_mpi_init( &S ); mbedtls_mpi_init( &W );	mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y );
	mbedtls_mpi_init( &E ); mbedtls_mpi_init( &H );

	mbedtls_mpi_init( &T2S ); mbedtls_mpi_init( &T2Q );
	mbedtls_mpi_init( &T2L1 ); mbedtls_mpi_init( &T2N1 );

	// L: {1024, 2048, 3072}  N: {160, 224, 256}
	MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &T2L1, 2 ) ); // T2L1 = 2^(L - 1)
	MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &T2L1, (L - 1)) );


	MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &T2N1, 2 ) ); // T2N1 = 2^(N - 1)
	MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &T2N1, (N - 1)) );

	MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &T2S, 2 ) );  // T2S  = 2^(N    )
	MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &T2S , (N    )) );

	for (found_p = 0; !found_p;)
	{
		/* q */
		for (found_q = 0; !found_q;)
		{
			psGetPrngData(p_rng, seeds, (N >> 3));
			psdsa_hash(seeds, (N >> 3), digest, digest_size);	/* 20, 28, 32, 48, 64 */

			MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &U, digest, digest_size ) );
			MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &U, &U, &T2N1 ) );
			MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &Q, &U, &T2N1 ) );

			if (!(Q.p[0] & 1))
				MBEDTLS_MPI_CHK( mbedtls_mpi_add_int( &Q, &Q, 1 ) );
			if ( (ret =  mbedtls_mpi_is_prime( &Q, p_rng, NULL )) == 0 ) {
				found_q = 1; break; /* once q was found, not generate q any more. */
			}
		}

		/* p */
		MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &S, seeds, (N >> 3) ) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &T2Q, &Q, &Q ) );

		for (counter = 0; counter < (4 * L) && !found_p; counter++)
		{
			for (j = 0; j <= n; j++)
			{
				/* S = (S + 1) mod T2S */
				MBEDTLS_MPI_CHK( mbedtls_mpi_add_int( &S, &S, 1 ) );
				MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &S, &S, &T2S ) );

				i = mbedtls_mpi_size(  &S );
				if ( i > (N >> 3) ) memset(seeds, 0x00, (N >> 3));
				MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &S, seeds, i ) );

				psdsa_hash(seeds, (N >> 3), &wbuf[(n - j) * digest_size], digest_size);
			}

			MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &W, wbuf, (n + 1) * digest_size ) );
			MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &W, &W, &T2L1 ) );
			MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &X, &W, &T2L1 ) );
			MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &Y, &X, &T2Q ) );
			MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &P, &Y, 1 ) );
			MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &P, &X, &P ) );

			/* p >= 2^(L - 1)*/
			if ( mbedtls_mpi_cmp_mpi(&P, &T2L1) >= 0 ) {
				if ( (ret =  mbedtls_mpi_is_prime( &P, p_rng, NULL )) == 0 ) {
					found_p = 1; break; /* once p was found, not generate p any more. */
				}
			}
		}
	}

	/* FIPS-186-4 A.2.1 Unverifiable Generation of the Generator g
	 * 1. e = (p - 1)/q
	 * 2. h = any integer satisfying: 1 < h < (p - 1)
	 *    h could be obtained from a random number generator or from a counter that changes after each use
	 * 3. g = h^e mod p
	 * 4. if (g == 1), then go to step 2.
	 *
	 */
	MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &E, &P, 1 ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_div_mpi( &E, &Y, &E, &Q ) );

	/* e = (p - 1)/q */
	j = mbedtls_mpi_bitlen( &P );
	do
	{
		do
		{
			MBEDTLS_MPI_CHK( psdsa_rand_bits(pool, &H, j, p_rng) );

			/* 2 < h < p */
			if ( mbedtls_mpi_cmp_int(&H,  2) > 0 &&
				 mbedtls_mpi_cmp_mpi(&H, &P) < 0)
				break;
		} while (1);

		/* h is randon and 1 < h < (p-1) */
		MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &H, &H, 1 ) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &G, &H, &E, &P, NULL ) );

		if ( mbedtls_mpi_cmp_int( &G, 1 ) != 0 )
			break;

	} while (1);

	params->pool = pool;

    len = mbedtls_mpi_size( &P );
    pstm_init_for_read_unsigned_bin(pool, &params->p , len);
    pstm_copy_unsigned_bin(&params->p, (unsigned char *)P.p, len);

    len = mbedtls_mpi_size( &Q );
    pstm_init_for_read_unsigned_bin(pool, &params->q , len);
    pstm_copy_unsigned_bin(&params->q, (unsigned char *)Q.p, len);

    len = mbedtls_mpi_size( &G );
    pstm_init_for_read_unsigned_bin(pool, &params->g , len);
    pstm_copy_unsigned_bin(&params->g, (unsigned char *)G.p, len);

cleanup:

	if (wbuf != NULL) psFree(pool, wbuf);

	mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q ); mbedtls_mpi_free( &G ); mbedtls_mpi_free( &U );
	mbedtls_mpi_free( &S ); mbedtls_mpi_free( &W ); mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y );
	mbedtls_mpi_free( &E ); mbedtls_mpi_free( &H );

	mbedtls_mpi_free( &T2S ); mbedtls_mpi_free( &T2Q );
	mbedtls_mpi_free( &T2L1 ); mbedtls_mpi_free( &T2N1 );

	if( ret != 0 ) {
		return PS_FAILURE;
	}

	return 0;
}

/*
	Create a DSA key (with given params)
*/
int32 psDsaKeyGen(psPool_t *pool, psDsaKey_t *key,
		 psDsaParams_t *params, void *p_rng)
{
	unsigned char temp[512];
	int ret = 0, qbits = 0, len = 0;
	mbedtls_mpi P, Q, G, X, Y;

	mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q ); mbedtls_mpi_init( &G );
	mbedtls_mpi_init( &X ); mbedtls_mpi_init( &Y );

	len = pstm_unsigned_bin_size( &params->p );
	pstm_to_unsigned_bin(pool, &params->p, temp);
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &P, temp, len ) );
	len = pstm_unsigned_bin_size( &params->q );
	pstm_to_unsigned_bin(pool, &params->q, temp);
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &Q, temp, len ) );
	len = pstm_unsigned_bin_size( &params->g );
	pstm_to_unsigned_bin(pool, &params->g, temp);
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &G, temp, len ) );

	qbits = mbedtls_mpi_bitlen( &Q );
	do
	{
		//MBEDTLS_MPI_CHK( psdsa_rand_bits(pool, &X, qbits, p_rng) );
		MBEDTLS_MPI_CHK( psdsa_rand_bits(pool, &X, qbits, mbedtls_ctr_drbg_random) );

		/* private key x should be from range: 1 <= x <= q-1 (see FIPS 186-4 B.1.2) */
		if ( mbedtls_mpi_cmp_int(&X,  0) > 0 &&
			 mbedtls_mpi_cmp_mpi(&X, &Q) < 0)
			break;
	} while (1);

	MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &Y, &G, &X, &P, NULL ) );

	key->type = DSA_PRIVATE;

    len = mbedtls_mpi_size( &X );
    pstm_init_for_read_unsigned_bin(pool, &key->priv , len);
    pstm_copy_unsigned_bin(&key->priv, (unsigned char *)X.p, len);

    len = mbedtls_mpi_size( &Y );
	pstm_init_for_read_unsigned_bin(pool, &key->pub , len);
	pstm_copy_unsigned_bin(&key->pub, (unsigned char *)Y.p, len);

cleanup:

	mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q ); mbedtls_mpi_free( &G );
	mbedtls_mpi_free( &X ); mbedtls_mpi_free( &Y );

	if( ret != 0 ) {
		return PS_FAILURE;
	}

	return 0;
}

/*
	Sign a hash with DSA (R, S)
*/
int32 psDsaSignHash(psPool_t *pool, psDsaKey_t *key,
		psDsaParams_t *params, unsigned char *in, uint32 inLen,
		psDsaSign_t *sig, void *p_rng)
{
	unsigned char temp[512];
	int ret = 0, qbits = 0, len = 0;
	mbedtls_mpi P, Q, G, X, R, S, K, T, Kinv;

	/* types valid? */
	if (key->type != DSA_PRIVATE) {
		psTraceCrypto("Bad private key format for DSA premaster\n");
		return PS_ARG_FAIL;
	}

	mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q ); mbedtls_mpi_init( &G );
	mbedtls_mpi_init( &X ); mbedtls_mpi_init( &R ); mbedtls_mpi_init( &S );
	mbedtls_mpi_init( &K ); mbedtls_mpi_init( &T ); mbedtls_mpi_init( &Kinv );

	len = pstm_unsigned_bin_size( &params->p );
	pstm_to_unsigned_bin(pool, &params->p, temp);
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &P, temp, len ) );
	len = pstm_unsigned_bin_size( &params->q );
	pstm_to_unsigned_bin(pool, &params->q, temp);
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &Q, temp, len ) );
	len = pstm_unsigned_bin_size( &params->g );
	pstm_to_unsigned_bin(pool, &params->g, temp);
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &G, temp, len ) );

	len = pstm_unsigned_bin_size( &key->priv );
	pstm_to_unsigned_bin(pool, &key->priv, temp);
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &X, temp, len ) );

	/*
	 * if the digest length is greater than the size of q use the
	 * mbedtls_mpi_bitlen( &Q ) leftmost bits of the digest, see
	 * fips 186-3, 4.2
	 * */
	qbits = mbedtls_mpi_bitlen( &Q );
	if (inLen > (qbits >> 3)) {
		inLen = (qbits >> 3);
	}

	do
	{
		/* generate random k */
		do
		{
			MBEDTLS_MPI_CHK( psdsa_rand_bits(pool, &K, qbits, p_rng) );
			/* 0 < k < q */
			if ( mbedtls_mpi_cmp_int(&K,  0) > 0 &&
				 mbedtls_mpi_cmp_mpi(&K, &Q) < 0)
			{
				/* Test GCD */
				MBEDTLS_MPI_CHK( mbedtls_mpi_gcd( &T, &K, &Q  ) );
				if (mbedtls_mpi_cmp_int( &T, 1 ) == 0) break;
			}
		} while (1);

		/* r = (g^k mod p) mod q */
		MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &R, &G, &K, &P, NULL ) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &R, &R, &Q ) );

		if (mbedtls_mpi_cmp_int(&R,  0) == 0) continue;

		/* a. Kinv = k^-1 mod q */
		MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &Kinv, &K, &Q ) );

		/* b. s = H(m) + xr */
		MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &T, in, inLen ) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &S, &X, &R ) );
		MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &S, &S, &T ) );

		/* c. s = (H(m) + xr) * (k^-1 mod q) */
		MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &S, &S, &Kinv ) );

		/* d. s = ((H(m) + xr) * (k^-1 mod q)) mod q */
		/* => s = ((H(m) + xr) * (k^-1)) mod q */
		MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &S, &S, &Q  ) );

		if (mbedtls_mpi_cmp_int(&S,  0) == 0) continue;

	} while ( 0 );

	len = mbedtls_mpi_size( &R );
	pstm_init_for_read_unsigned_bin(pool, &sig->r , len);
	pstm_copy_unsigned_bin(&sig->r, (unsigned char *)R.p, len);

	len = mbedtls_mpi_size( &S );
	pstm_init_for_read_unsigned_bin(pool, &sig->s , len);
	pstm_copy_unsigned_bin(&sig->s, (unsigned char *)S.p, len);

cleanup:

	mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q ); mbedtls_mpi_free( &G );
	mbedtls_mpi_free( &X ); mbedtls_mpi_free( &R ); mbedtls_mpi_free( &S );
	mbedtls_mpi_free( &K ); mbedtls_mpi_free( &T ); mbedtls_mpi_free( &Kinv );

	if( ret != 0 ) {
		return PS_FAILURE;
	}

	return 0;
}

/*
	Verify a hash with DSA
*/
int32 psDsaVerifyHash(psPool_t *pool, psDsaKey_t *key,
		psDsaParams_t *params, unsigned char *in, uint32 inLen,
		psDsaSign_t *sig)
{
	unsigned char temp[512];
	int ret = 0, len = 0;
	mbedtls_mpi P, Q, G, Y, R, S, W, U1, U2, V, T;

	mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q ); mbedtls_mpi_init( &G );
	mbedtls_mpi_init( &Y ); mbedtls_mpi_init( &R ); mbedtls_mpi_init( &S );
	mbedtls_mpi_init( &W ); mbedtls_mpi_init( &U1); mbedtls_mpi_init( &U2);
	mbedtls_mpi_init( &V ); mbedtls_mpi_init( &T );

	len = pstm_unsigned_bin_size( &params->p );
	pstm_to_unsigned_bin(pool, &params->p, temp);
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &P, temp, len ) );
	len = pstm_unsigned_bin_size( &params->q );
	pstm_to_unsigned_bin(pool, &params->q, temp);
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &Q, temp, len ) );
	len = pstm_unsigned_bin_size( &params->g );
	pstm_to_unsigned_bin(pool, &params->g, temp);
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &G, temp, len ) );

	len = pstm_unsigned_bin_size( &key->pub );
	pstm_to_unsigned_bin(pool, &key->pub, temp);
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &Y, temp, len ) );

	len = pstm_unsigned_bin_size( &sig->r );
	pstm_to_unsigned_bin(pool, &sig->r, temp);
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &R, temp, len ) );
	len = pstm_unsigned_bin_size( &sig->s );
	pstm_to_unsigned_bin(pool, &sig->s, temp);
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &S, temp, len ) );

	/* neither r or s can be null or > q */
	if (mbedtls_mpi_cmp_int(&R, 0) == 0 || mbedtls_mpi_cmp_mpi(&R, &Q) > 0 ||
		mbedtls_mpi_cmp_int(&S, 0) == 0 || mbedtls_mpi_cmp_mpi(&S, &Q) > 0)
	{
		psTraceCrypto("Bad private key format for DSA premaster\n");
		ret = PS_ARG_FAIL; goto cleanup;
	}

	/* a. w  = s^-1 mod q */
	MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &W, &S, &Q ) );

	/* b. u1 = m * w mod q */
	MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &U1, in, inLen ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( &U1, &U1, &W, &Q ) );

	/* c. u2 = r * w mod q */
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( &U2, &R , &W, &Q ) );

	/* d. u1 = g^u1 mod p */
	MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T, &G, &U1, &P, NULL ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &U1, &T ) );

	/* e. u2 = y^u2 mod p*/
	MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T, &Y, &U2, &P, NULL ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &U2, &T ) );

	/* d. v  = u1 * u2 mod q = g^u1 * y^u2 mod p mod q */
	MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( &V, &U1, &U2, &P ) );
	MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &V, &V, &Q ) );

	 /* if r = v then successful */
	if (mbedtls_mpi_cmp_mpi(&R, &V) != 0) {
		ret = PS_FAILURE;
	}

cleanup:

	mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q ); mbedtls_mpi_free( &G );
	mbedtls_mpi_free( &Y ); mbedtls_mpi_free( &R ); mbedtls_mpi_free( &S );
	mbedtls_mpi_free( &W ); mbedtls_mpi_free( &U1); mbedtls_mpi_free( &U2);
	mbedtls_mpi_free( &V ); mbedtls_mpi_free( &T );

	if( ret != 0 ) {
		return PS_FAILURE;
	}

	return 0;
}

#endif
