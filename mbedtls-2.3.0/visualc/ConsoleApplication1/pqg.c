/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * PQG parameter generation/verification.  Based on FIPS 186-3.
 */
#ifdef FREEBL_NO_DEPEND
#include "stubs.h"
#endif

//#include "prerr.h"
//#include "secerr.h"
//
//#include "prtypes.h"
//#include "blapi.h"
//#include "secitem.h"
//#include "mpi.h"
//#include "mpprime.h"
//#include "mplogic.h"
//#include "secmpi.h"
#include<stdlib.h>
#include<string.h>
#include <mbedtls/bignum.h>
#include <mbedtls/sha512.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

typedef enum _SECStatus {
	SECWouldBlock = -2,
	SECFailure = -1,
	SECSuccess = 0
} SECStatus;

#define MAX_ITERATIONS 1000 /* Maximum number of iterations of primegen */

typedef enum {
    FIPS186_1_TYPE,   /* Probablistic */
    FIPS186_3_TYPE,   /* Probablistic */
    FIPS186_3_ST_TYPE /* Shawe-Taylor provable */
} pqgGenType;

#define PR_BITS_PER_BYTE 8
#define MD2_LENGTH 16    /* Bytes */
#define MD5_LENGTH 16    /* Bytes */
#define SHA1_LENGTH 20   /* Bytes */
#define SHA256_LENGTH 32 /* bytes */
#define SHA384_LENGTH 48 /* bytes */
#define SHA512_LENGTH 64 /* bytes */
#define HASH_LENGTH_MAX SHA512_LENGTH
#define MAX_ST_SEED_BITS (HASH_LENGTH_MAX * PR_BITS_PER_BYTE)
typedef struct SECItemStr SECItem;
typedef enum {
	siBuffer = 0,
	siClearDataBuffer = 1,
	siCipherDataBuffer = 2,
	siDERCertBuffer = 3,
	siEncodedCertBuffer = 4,
	siDERNameBuffer = 5,
	siEncodedNameBuffer = 6,
	siAsciiNameString = 7,
	siAsciiString = 8,
	siDEROID = 9,
	siUnsignedInteger = 10,
	siUTCTime = 11,
	siGeneralizedTime = 12,
	siVisibleString = 13,
	siUTF8String = 14,
	siBMPString = 15
} SECItemType;

struct SECItemStr {
	SECItemType type;
	unsigned char *data;
	unsigned int len;
};
#define DSA_MAX_P_BITS	3072
typedef int               mp_err;
#define  MP_NEG    1
#define  MP_ZPOS   0

#define  MP_OKAY          0 /* no error, all is well */
#define  MP_YES           0 /* yes (boolean result)  */
#define  MP_NO           -1 /* no (boolean result)   */
#define  MP_MEM          -2 /* out of memory         */
#define  MP_RANGE        -3 /* argument out of range */
#define  MP_BADARG       -4 /* invalid parameter     */
#define  MP_UNDEF        -5 /* answer is undefined   */
#define  MP_LAST_CODE    MP_UNDEF
typedef int PRIntn;
typedef PRIntn PRBool;
#define PR_TRUE 1
#define PR_FALSE 0
typedef unsigned int PRUint32;
typedef unsigned int     mp_digit;
#define MP_DIGIT_MAX INT_MAX
#define CHECK_SEC_OK(func)         \
    if (SECSuccess != (rv = func)) \
    goto cleanup
#define CHECK_MPI_OK(func)      \
    if (MP_OKAY > (err = func)) \
    goto cleanup
#define  ARGCHK(X,Y)  {if(!(X)){return (Y);}}

static SECStatus
HASH_HashBuf( unsigned char *dest,
	const unsigned char *src, PRUint32 src_len)
{
	mbedtls_sha512(src, src_len, dest,0);
	return SECSuccess;
}

#define PR_Free free
void
PORT_Free(void *ptr)
{
	if (ptr) {
		PR_Free(ptr);
	}
}

void
PORT_ZFree(void *ptr, size_t len)
{
	if (ptr) {
		memset(ptr, 0, len);
		PR_Free(ptr);
	}
}

void
SECITEM_ZfreeItem(SECItem *zap, PRBool freeit)
{
	if (zap) {
		PORT_ZFree(zap->data, zap->len);
		zap->data = 0;
		zap->len = 0;
		if (freeit) {
			PORT_ZFree(zap, sizeof(SECItem));
		}
	}
}

static SECStatus
addToSeed(const SECItem *seed,
	int addend,
	int seedlen, /* g in 186-1 */
	SECItem *seedout)
{
	mbedtls_mpi s; 
	mbedtls_mpi t;
	size_t len=0;
	SECStatus ret = SECSuccess;
	mbedtls_mpi_init(&s) ;  
	mbedtls_mpi_init(&t);
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&s, seed->data, seed->len)); /* s = seed */
								
	if (addend >= 0) {
		MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&s, &s, addend)); /* seed += addend */
	}
	else {
		ret = SECFailure;
		goto cleanup;
	}
	/*sum = s mod 2**seedlen */
	MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&t, 1));
	MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&t, seedlen));
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&s,&s ,&t)); 
	if (seedout->data != NULL) {
		SECITEM_ZfreeItem(seedout, PR_FALSE);
	}
	len = mbedtls_mpi_size(&s);
	if (len <= 0)
	{
		ret= -2;
		goto cleanup;
	}
	seedout->data = (unsigned char*)malloc(len );
	if (seedout->data == NULL) {
		ret = -3;
		goto cleanup;
	}
	seedout->len = len;
	ret = mbedtls_mpi_write_binary(&s, seedout->data, seedout->len); 

cleanup:
	mbedtls_mpi_free(&t);
	mbedtls_mpi_free(&s);
	return ret;
}
void
SECITEM_FreeItem(SECItem *zap, PRBool freeit)
{
	if (zap) {
		free(zap->data);
		zap->data = 0;
		zap->len = 0;
		if (freeit) {
			free(zap);
		}
	}
}

static SECStatus
addToSeedThenHash(const SECItem *seed,
	int addend,
	int seedlen, /* g in 186-1 */
	unsigned char *hashOutBuf)
{
	SECItem str = { 0, 0, 0 };
	SECStatus rv;
	rv = addToSeed(seed, addend, seedlen, &str);
	if (rv != SECSuccess) {
		return rv;
	}
	rv = HASH_HashBuf(hashOutBuf, str.data, str.len); /* hash result */
	if (str.data)
		SECITEM_ZfreeItem(&str, PR_FALSE);
	return rv;
}

//#include"primes.h"
static SECStatus
makePrimefromPrimesShaweTaylor(
	unsigned int length,             /* input. Length of prime in bits. */
	mbedtls_mpi *c0,                      /* seed prime */
	mbedtls_mpi *q,                       /* sub prime, can be 1 */
	mbedtls_mpi *prime,                   /* output.  */
	SECItem *prime_seed,             /* input/output.  */
	unsigned int *prime_gen_counter) /* input/output.  */
{
	mbedtls_mpi c;
	mbedtls_mpi c0_2;
	mbedtls_mpi t;
	mbedtls_mpi a;
	mbedtls_mpi z;
	mbedtls_mpi two_length_minus_1;
	SECStatus rv = SECFailure;
	int hashlen = SHA512_LENGTH;
	int outlen = hashlen * PR_BITS_PER_BYTE;
	int offset;
	unsigned char bit, mask;
	/* x needs to hold roundup(L/outlen)*outlen.
	* This can be no larger than L+outlen-1, So we set it's size to
	* our max L + max outlen and know we are safe */
	unsigned char x[DSA_MAX_P_BITS / 8 + HASH_LENGTH_MAX];
	mp_err err = MP_OKAY;
	int i;
	int iterations;
	int old_counter;
	size_t stmp = 0;
	 
	mbedtls_mpi_init(&c);
	mbedtls_mpi_init(&c0_2);
	mbedtls_mpi_init(&t);
	mbedtls_mpi_init(&a);
	mbedtls_mpi_init(&z);
	mbedtls_mpi_init(&two_length_minus_1);

	/*
	** There is a slight mapping of variable names depending on which
	** FIPS 186 steps are being carried out. The mapping is as follows:
	**  variable          A.1.2.1           C.6
	**    c0                p0               c0
	**    q                 q                1
	**    c                 p                c
	**    c0_2            2*p0*q            2*c0
	**    length            L               length
	**    prime_seed       pseed            prime_seed
	**  prime_gen_counter pgen_counter     prime_gen_counter
	**
	** Also note: or iterations variable is actually iterations+1, since
	** iterations+1 works better in C.
	*/

	/* Step 4/16 iterations = ceiling(length/outlen)-1 */
	iterations = (length + outlen - 1) / outlen; /* NOTE: iterations +1 */
												 /* Step 5/17 old_counter = prime_gen_counter */
	old_counter = *prime_gen_counter;
	/*
	** Comment: Generate a pseudorandom integer x in the interval
	** [2**(lenght-1), 2**length].
	**
	** Step 6/18 x = 0
	*/
	memset(x, 0, sizeof(x));
	/*
	** Step 7/19 for i = 0 to iterations do
	**  x = x + (HASH(prime_seed + i) * 2^(i*outlen))
	*/
	for (i = 0; i < iterations; i++) {
		/* is bigger than prime_seed should get to */
		CHECK_SEC_OK(addToSeedThenHash( prime_seed, i,
			MAX_ST_SEED_BITS, &x[(iterations - i - 1) * hashlen]));
	}
	/* Step 8/20 prime_seed = prime_seed + iterations + 1 */
	CHECK_SEC_OK(addToSeed(prime_seed, iterations+1, MAX_ST_SEED_BITS,
		prime_seed));
	/*
	** Step 9/21 x = 2 ** (length-1) + x mod 2 ** (length-1)
	**
	**   This step mathematically sets the high bit and clears out
	**  all the other bits higher than length. 'x' is stored
	**  in the x array, MSB first. The above formula gives us an 'x'
	**  which is length bytes long and has the high bit set. We also know
	**  that length <= iterations*outlen since
	**  iterations=ceiling(length/outlen). First we find the offset in
	**  bytes into the array where the high bit is.
	*/
	offset = (outlen * iterations - length) / PR_BITS_PER_BYTE;
	/* now we want to set the 'high bit', since length may not be a
	* multiple of 8,*/
	bit = 1 << ((length - 1) & 0x7); /* select the proper bit in the byte */
									 /* we need to zero out the rest of the bits in the byte above */
	mask = (bit - 1);
	/* now we set it */
	x[offset] = (mask & x[offset]) | bit;
	/*
	** Comment: Generate a candidate prime c in the interval
	** [2**(lenght-1), 2**length].
	**
	** Step 10 t = ceiling(x/(2q(p0)))
	** Step 22 t = ceiling(x/(2(c0)))
	*/
	CHECK_MPI_OK(mbedtls_mpi_read_binary(&t, &x[offset],
		hashlen * iterations - offset)); /* t = x */
	CHECK_MPI_OK(mbedtls_mpi_mul_mpi(&c0_2, c0, q));                                   /* c0_2 is now c0*q */
	CHECK_MPI_OK(mbedtls_mpi_add_mpi(&c0_2, &c0_2, &c0_2));                            /* c0_2 is now 2*q*c0 */
	CHECK_MPI_OK(mbedtls_mpi_add_mpi(&t, &t, &c0_2));                                  /* t = x+2*q*c0 */
	
	CHECK_MPI_OK(mbedtls_mpi_sub_int(&t, &t, 1));                          /* t = x+2*q*c0 -1 */
																		  /* t = floor((x+2qc0-1)/2qc0) = ceil(x/2qc0) */
	CHECK_MPI_OK(mbedtls_mpi_div_mpi(&t, NULL, &t, &c0_2));
	/*
	** step 11: if (2tqp0 +1 > 2**length), then t = ceiling(2**(length-1)/2qp0)
	** step 12: t = 2tqp0 +1.
	**
	** step 23: if (2tc0 +1 > 2**length), then t = ceiling(2**(length-1)/2c0)
	** step 24: t = 2tc0 +1.
	*/
	CHECK_MPI_OK(mbedtls_mpi_lset(&two_length_minus_1, 1));
	CHECK_MPI_OK(mbedtls_mpi_shift_l(&two_length_minus_1, length - 1)); 
step_23:
	CHECK_MPI_OK(mbedtls_mpi_mul_mpi(&c, &t, &c0_2));                /* c = t*2qc0 */
	CHECK_MPI_OK(mbedtls_mpi_add_int(&c, &c, 1));        /* c= 2tqc0 + 1*/
	
	if ((stmp=mbedtls_mpi_bitlen(&c)) > length) {            /* if c > 2**length */
		CHECK_MPI_OK(mbedtls_mpi_sub_int(&t, &c0_2, 1)); /* t = 2qc0-1 */
														/* t = 2**(length-1) + 2qc0 -1 */
		CHECK_MPI_OK(mbedtls_mpi_add_mpi(&t, &two_length_minus_1, &t));
		/* t = floor((2**(length-1)+2qc0 -1)/2qco)
		*   = ceil(2**(lenght-2)/2qc0) */
		
		CHECK_MPI_OK(mbedtls_mpi_div_mpi(&t, NULL, &t, &c0_2));
		CHECK_MPI_OK(mbedtls_mpi_mul_mpi(&c, &t, &c0_2));
		CHECK_MPI_OK(mbedtls_mpi_add_int(&c,  &c, 1)); /* c= 2tqc0 + 1*/
	}
	/* Step 13/25 prime_gen_counter = prime_gen_counter + 1*/
	(*prime_gen_counter)++;
	/*
	** Comment: Test the candidate prime c for primality; first pick an
	** integer a between 2 and c-2.
	**
	** Step 14/26 a=0
	*/
	memset(x, 0, sizeof(x)); /* use x for a */
								  /*
								  ** Step 15/27 for i = 0 to iterations do
								  **  a = a + (HASH(prime_seed + i) * 2^(i*outlen))
								  **
								  ** NOTE: we reuse the x array for 'a' initially.
								  */
	for (i = 0; i < iterations; i++) {
		/* MAX_ST_SEED_BITS is bigger than prime_seed should get to */
		CHECK_SEC_OK(addToSeedThenHash(prime_seed, i,
			MAX_ST_SEED_BITS, &x[(iterations - i - 1) * hashlen]));
	}
	/* Step 16/28 prime_seed = prime_seed + iterations + 1 */
	CHECK_SEC_OK(addToSeed(prime_seed, iterations+1, MAX_ST_SEED_BITS,
		prime_seed));
	/* Step 17/29 a = 2 + (a mod (c-3)). */
	CHECK_MPI_OK(mbedtls_mpi_read_binary(&a, x, iterations * hashlen)); 

	CHECK_MPI_OK(mbedtls_mpi_sub_int(&z,&c,  3)); /* z = c -3 */
	CHECK_MPI_OK(mbedtls_mpi_mod_mpi(&a, &a,&z));            /* a = a mod c -3 */
	CHECK_MPI_OK(mbedtls_mpi_add_int(&a, &a,  2)); /* a = 2 + a mod c -3 */
												 /*
												 ** Step 18 z = a**(2tq) mod p.
												 ** Step 30 z = a**(2t) mod c.
												 */
	CHECK_MPI_OK(mbedtls_mpi_mul_mpi(&z, q, &t));          /* z = tq */
	CHECK_MPI_OK(mbedtls_mpi_add_mpi(&z, &z, &z));         /* z = 2tq */
	CHECK_MPI_OK(mbedtls_mpi_exp_mod(&z, &a, &z, &c, NULL)); /* z = a**(2tq) mod c */
											  /*
											  ** Step 19 if (( 1 == GCD(z-1,p)) and ( 1 == z**p0 mod p )), then
											  ** Step 31 if (( 1 == GCD(z-1,c)) and ( 1 == z**c0 mod c )), then
											  */
	CHECK_MPI_OK(mbedtls_mpi_sub_int(&a,&z, 1));
	
	CHECK_MPI_OK(mbedtls_mpi_gcd(&a, &a, &c));
	
	if (mbedtls_mpi_cmp_int(&a, 1) == 0) {
		CHECK_MPI_OK(mbedtls_mpi_exp_mod(&a,&z,c0,&c,NULL));//a = z^c0 mod c
		if (mbedtls_mpi_cmp_int(&a, 1) == 0) {
			/* Step 31.1 prime = c */
			CHECK_MPI_OK(mbedtls_mpi_copy(prime, &c));
			/*
			** Step 31.2 return Success, prime, prime_seed,
			**    prime_gen_counter
			*/
			rv = SECSuccess;
			goto cleanup;
		}
	}
	/*
	** Step 20/32 If (prime_gen_counter > 4 * length + old_counter then
	**   return (FAILURE, 0, 0, 0).
	** NOTE: the test is reversed, so we fall through on failure to the
	** cleanup routine
	*/
 
	if (*prime_gen_counter < (4 * length + old_counter)) {
		/* Step 21/33 t = t + 1 */
		CHECK_MPI_OK(mbedtls_mpi_add_int(&t,&t, 1));
		/* Step 22/34 Go to step 23/11 */
		goto step_23;
	}

	/* if (prime_gencont > (4*length + old_counter), fall through to failure */
	rv = SECFailure; /* really is already set, but paranoia is good */

cleanup:
	mbedtls_mpi_free(&c);
	mbedtls_mpi_free(&c0_2);
	mbedtls_mpi_free(&t);
	mbedtls_mpi_free(&a);
	mbedtls_mpi_free(&z);
	mbedtls_mpi_free(&two_length_minus_1);
	memset(x, 0, sizeof(x));
	if (err) {
		//MP_TO_SEC_ERROR(err);
		rv = SECFailure;
	}
	if (rv == SECFailure) {
		mbedtls_mpi_free(prime); mbedtls_mpi_init(prime);
		mbedtls_mpi_lset(prime,0);
		if (prime_seed->data) {
			SECITEM_FreeItem(prime_seed, PR_FALSE);
		}
		*prime_gen_counter = 0;
	}
	return rv;
}
SECStatus
SECITEM_CopyItem( SECItem *to, const SECItem *from)
{
	to->type = from->type;
	if (from->data && from->len) {
		to->data = (unsigned char *)malloc(from->len);
		if (!to->data) {
			return SECFailure;
		}
		memcpy(to->data, from->data, from->len);
		to->len = from->len;
	}
	else {
		/*
		* If from->data is NULL but from->len is nonzero, this function
		* will succeed.  Is this right?
		*/
		to->data = 0;
		to->len = 0;
	}
	return SECSuccess;
}
mp_err    s_mpp_divp(mbedtls_mpi *a, const mp_digit *vec, int size, int *which)
{
	mp_err    res;
	mp_digit  rem;

	int     ix;

	for (ix = 0; ix < size; ix++) {
		
		if ((res = mbedtls_mpi_mod_int(&rem, a, vec[ix])) != MP_OKAY)
			return res;
		if (rem == 0) {
			if (which)
				*which = ix;
			return MP_YES;
		}
	}

	return MP_NO;

} /* end s_mpp_divp() */

mp_err  mpp_divis_vector(mbedtls_mpi *a, const mp_digit *vec, int size, int *which)
{
	ARGCHK(a != NULL && vec != NULL && size > 0, MP_BADARG);

	return s_mpp_divp(a, vec, size, which);

} /* end mpp_divis_vector() */

  /* }}} */

  /* {{{ mpp_divis_primes(a, np) */

  /*
  mpp_divis_primes(a, np)

  Test whether a is divisible by any of the first 'np' primes.  If it
  is, returns MP_YES and sets *np to the value of the digit that did
  it.  If not, returns MP_NO.
  */
mp_err  mpp_divis_primes(mbedtls_mpi *a, mp_digit *np)
{
	int     size, which;
	mp_err  res;

	ARGCHK(a != NULL && np != NULL, MP_BADARG);

	size = (int)*np;
	if (size > prime_tab_size)
		size = prime_tab_size;

	res = mpp_divis_vector(a, prime_tab, size, &which);
	if (res == MP_YES)
		*np = prime_tab[which];

	return res;

} /* end mpp_divis_primes() */
void dumpi(mbedtls_mpi *i,const char* str)
{
	int len = mbedtls_mpi_size(i);
	unsigned char* buf = malloc(len);
	mbedtls_mpi_write_binary(i, buf, len);
	printf("%s:",str);
	for (int i = 0; i < len; i++)
		printf("%02x",buf[i]);
	printf("\n");
	free(buf);
}
int is_prime(mbedtls_mpi *i)
{
	int err = 0;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	CHECK_MPI_OK(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		"123",
		3) );
	CHECK_MPI_OK(mbedtls_mpi_is_prime(i, mbedtls_ctr_drbg_random, &ctr_drbg));
cleanup:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return err;
}
static SECStatus
makePrimefromSeedShaweTaylor(
	unsigned int length,             /* input.  Length of prime in bits. */
	const SECItem *input_seed,       /* input.  */
	mbedtls_mpi *prime,                   /* output.  */
	SECItem *prime_seed,             /* output.  */
	unsigned int *prime_gen_counter) /* output.  */
{
	mbedtls_mpi c;
	mbedtls_mpi c0;
	mbedtls_mpi one;
	SECStatus rv = SECFailure;
	int hashlen = SHA512_LENGTH;
	int outlen = hashlen * PR_BITS_PER_BYTE;
	int offset;
	unsigned char bit, mask;
	unsigned char x[HASH_LENGTH_MAX * 2];
	mp_digit dummy;
	mp_err err = MP_OKAY;
	int i;


	mbedtls_mpi_init(&c) ;
	mbedtls_mpi_init(&c0) ;
	mbedtls_mpi_init(&one) ; 

	/* Step 1. if length < 2 then return (FAILURE, 0, 0, 0) */
	if (length < 2) {
		rv = SECFailure;
		goto cleanup;
	}
	/* Step 2. if length >= 33 then goto step 14 */
	if (length >= 33) {
		CHECK_MPI_OK(mbedtls_mpi_lset(&one, 1)); 

		/* Step 14 (status, c0, prime_seed, prime_gen_counter) =
		** (ST_Random_Prime((ceil(length/2)+1, input_seed)
		*/
		rv = makePrimefromSeedShaweTaylor( (length + 1) / 2 + 1,
			input_seed, &c0, prime_seed, prime_gen_counter);
		/* Step 15 if FAILURE is returned, return (FAILURE, 0, 0, 0). */
		if (rv != SECSuccess) {
			goto cleanup;
		}
		/* Steps 16-34 */
		rv = makePrimefromPrimesShaweTaylor( length, &c0, &one,
			prime, prime_seed, prime_gen_counter);
		goto cleanup; /* we're done, one way or the other */
	}
	/* Step 3 prime_seed = input_seed */
	CHECK_SEC_OK(SECITEM_CopyItem( prime_seed, input_seed));
	/* Step 4 prime_gen_count = 0 */
	*prime_gen_counter = 0;

step_5:
	/* Step 5 c = Hash(prime_seed) xor Hash(prime_seed+1). */
	CHECK_SEC_OK(HASH_HashBuf( x, prime_seed->data, prime_seed->len));
	CHECK_SEC_OK(addToSeedThenHash( prime_seed, 1,
		MAX_ST_SEED_BITS, &x[hashlen]));
	for (i = 0; i < hashlen; i++) {
		x[i] = x[i] ^ x[i + hashlen];
	}
	/* Step 6 c = 2**length-1 + c mod 2**length-1 */
	/*   This step mathematically sets the high bit and clears out
	**  all the other bits higher than length. Right now c is stored
	**  in the x array, MSB first. The above formula gives us a c which
	**  is length bytes long and has the high bit set. We also know that
	**  length < outlen since the smallest outlen is 160 bits and the largest
	**  length at this point is 32 bits. So first we find the offset in bytes
	**  into the array where the high bit is.
	*/
	offset = (outlen - length) / PR_BITS_PER_BYTE;
	/* now we want to set the 'high bit'. We have to calculate this since
	* length may not be a multiple of 8.*/
	bit = 1 << ((length - 1) & 0x7); /* select the proper bit in the byte */
									 /* we need to zero out the rest of the bits  in the byte above */
	mask = (bit - 1);
	/* now we set it */
	x[offset] = (mask & x[offset]) | bit;
	/* Step 7 c = c*floor(c/2) + 1 */
	/* set the low bit. much easier to find (the end of the array) */
	x[hashlen - 1] |= 1;
	/* now that we've set our bits, we can create our candidate "c" */
	CHECK_MPI_OK(mbedtls_mpi_read_binary(&c, &x[offset], hashlen - offset));
	/* Step 8 prime_gen_counter = prime_gen_counter + 1 */
	(*prime_gen_counter)++;
	/* Step 9 prime_seed = prime_seed + 2 */
	CHECK_SEC_OK(addToSeed(prime_seed, 2, MAX_ST_SEED_BITS, prime_seed));
	/* Step 10 Perform deterministic primality test on c. For example, since
	** c is small, it's primality can be tested by trial division, See
	** See Appendic C.7.
	**
	** We in fact test with trial division. mpi has a built int trial divider
	** that divides all divisors up to 2^16.
	*/
	if (prime_tab[prime_tab_size - 1] < 0xFFF1) {
		/* we aren't testing all the primes between 0 and 2^16, we really
		* can't use this construction. Just fail. */
		rv = SECFailure;
		goto cleanup;
	}
	dummy = prime_tab_size;
	err = mpp_divis_primes(&c, &dummy);
	/* Step 11 if c is prime then */
	if (err == MP_NO) {
		/* Step 11.1 prime = c */
		
		CHECK_MPI_OK(mbedtls_mpi_copy(prime, &c));
		/* Step 11.2 return SUCCESS prime, prime_seed, prime_gen_counter */
		err = MP_OKAY;
		rv = SECSuccess;
		goto cleanup;
	}
	else if (err != MP_YES) {
		goto cleanup; /* function failed, bail out */
	}
	else {
		/* reset mp_err */
		err = MP_OKAY;
	}
	/*
	** Step 12 if (prime_gen_counter > (4*len))
	** then return (FAILURE, 0, 0, 0))
	** Step 13 goto step 5
	*/
	if (*prime_gen_counter <= (4 * length)) {
		goto step_5;
	}
	/* if (prime_gencont > 4*length), fall through to failure */
	rv = SECFailure; /* really is already set, but paranoia is good */

cleanup:
	mbedtls_mpi_free(&c);
	mbedtls_mpi_free(&c0);
	mbedtls_mpi_free(&one);
	memset(x, 0, sizeof(x));
	if (err) {
		//MP_TO_SEC_ERROR(err);
		rv = SECFailure;
	}
	if (rv == SECFailure) {
		mbedtls_mpi_free(prime); mbedtls_mpi_init(prime);
		mbedtls_mpi_lset(prime, 0);
		if (prime_seed->data) {
			SECITEM_FreeItem(prime_seed, PR_FALSE);
		}
		*prime_gen_counter = 0;
	}

	return rv;
}


int gen_prime_from_seed(unsigned int length, unsigned char *seed, int slen, mbedtls_mpi *prime)
{
	SECItem prime_seed;
	SECItem input_seed;
	unsigned int prime_gen_counter = 1;
	input_seed.data = seed;
	input_seed.len = slen;
	int r =  makePrimefromSeedShaweTaylor(length, &input_seed, prime, &prime_seed, &prime_gen_counter);
	if (r != 0)
	{
		printf(" %u,", prime_gen_counter);
	}
	return r;
}

//=============================s==method 2 from New_rsa() from nss ==================================================================
//
//#define MAX_PRIME_GEN_ATTEMPTS 10
//#define SIEVE_SIZE 32*1024
//#define MP_CHECKOK(x)          \
//    if (MP_OKAY > (res = (x))) \
//    goto CLEANUP
//
//typedef unsigned int mp_size;
//
//mp_err mpp_sieve(mbedtls_mpi *trial, const mp_digit *primes, mp_size nPrimes,
//	unsigned char *sieve, mp_size nSieve)
//{
//	mp_err       res;
//	mp_digit     rem;
//	mp_size      ix;
//	unsigned long offset;
//
//	memset(sieve, 0, nSieve);
//
//	for (ix = 0; ix < nPrimes; ix++) {
//		mp_digit prime = primes[ix];
//		mp_size  i;
//		if ((res = mbedtls_mpi_mod_int(&rem, trial, prime)) != MP_OKAY)
//			return res;
//
//		if (rem == 0) {
//			offset = 0;
//		}
//		else {
//			offset = prime - (rem / 2);
//		}
//		for (i = offset; i < nSieve; i += prime) {
//			sieve[i] = 1;
//		}
//	}
//
//	return MP_OKAY;
//}
//
//
//mp_err mpp_make_prime(mbedtls_mpi *start, mp_size nBits,	unsigned long * nTries, int(*f_rng)(void *, unsigned char *, size_t),
//	void *p_rng)
//{
//	mp_err        res;
//	unsigned int           i = 0;
//	mbedtls_mpi        trial;
//	mbedtls_mpi        q;
//	mp_size       num_tests;
//	unsigned char *sieve;
//
//	ARGCHK(start != 0, MP_BADARG);
//	ARGCHK(nBits > 16, MP_RANGE);
//
//	sieve = malloc(SIEVE_SIZE);
//	ARGCHK(sieve != NULL, MP_MEM);
//
//	mbedtls_mpi_init(&trial) ;
//	mbedtls_mpi_init(&q) ;
//	/* values taken from table 4.4, HandBook of Applied Cryptography */
//	if (nBits >= 1300) {
//		num_tests = 2;
//	}
//	else if (nBits >= 850) {
//		num_tests = 3;
//	}
//	else if (nBits >= 650) {
//		num_tests = 4;
//	}
//	else if (nBits >= 550) {
//		num_tests = 5;
//	}
//	else if (nBits >= 450) {
//		num_tests = 6;
//	}
//	else if (nBits >= 400) {
//		num_tests = 7;
//	}
//	else if (nBits >= 350) {
//		num_tests = 8;
//	}
//	else if (nBits >= 300) {
//		num_tests = 9;
//	}
//	else if (nBits >= 250) {
//		num_tests = 12;
//	}
//	else if (nBits >= 200) {
//		num_tests = 15;
//	}
//	else if (nBits >= 150) {
//		num_tests = 18;
//	}
//	else if (nBits >= 100) {
//		num_tests = 27;
//	}
//	else
//		num_tests = 50;
//	 
//	MP_CHECKOK(mbedtls_mpi_set_bit(start, nBits - 1, 1));
//	MP_CHECKOK(mbedtls_mpi_set_bit(start, 0, 1));
//	for (i = mbedtls_mpi_bitlen(start) - 1; i >= nBits; --i) {
//		MP_CHECKOK(mbedtls_mpi_set_bit(start, i, 0));
//	}
//	/* start sieveing with prime value of 3. */
//	MP_CHECKOK(mpp_sieve(start, prime_tab + 1, prime_tab_size - 1,
//		sieve, SIEVE_SIZE));
//
// 
//#define FPUTC(x,y) 
//	res = MP_NO;
//	for (i = 0; i < SIEVE_SIZE; ++i) {
//		if (sieve[i])	/* this number is composite */
//			continue;
//		MP_CHECKOK(mbedtls_mpi_add_int(&trial, start, 2 * i));
//		FPUTC('.', stderr);
//		/* run a Fermat test */
//		//res = mpp_fermat(&trial, 2);
//		//if (res != MP_OKAY) {
//		//	if (res == MP_NO)
//		//		continue;	/* was composite */
//		//	goto CLEANUP;
//		//}
//
//		//FPUTC('+', stderr);
//		/* If that passed, run some Miller-Rabin tests	*/
//		 
//		res= mbedtls_mpi_is_prime(&trial, f_rng,p_rng);
//		//res = mpp_pprime(&trial, num_tests);
//		if (res != MP_OKAY) {
//				continue;	/* was composite */
//		} 
//		break;
//		 
//	} /* end of loop through sieved values */
//	if (res == MP_YES)
//	{
//		mbedtls_mpi_swap(&trial, start);
//	}
//CLEANUP:
//	mbedtls_mpi_free(&trial);
//	mbedtls_mpi_free(&q);
//	if (nTries)
//		*nTries += i;
//	if (sieve != NULL) {
//		memset(sieve, 0, SIEVE_SIZE);
//		free(sieve);
//	}
//	return res;
//}
//
////primelen is bytes
//
//int generate_prime(mbedtls_mpi *prime, int primeLen, int(*f_rng)(void *, unsigned char *, size_t),
//	void *p_rng)
//{
//	mp_err err = MP_OKAY;
//	SECStatus rv = SECSuccess;
//	unsigned long counter = 0;
//	int piter;
//	unsigned char *pb = NULL;
//	pb = malloc(primeLen);
//	if (!pb) {
// 
//		goto cleanup;
//	}
//	for (piter = 0; piter < MAX_PRIME_GEN_ATTEMPTS; piter++) {
//		CHECK_SEC_OK(mbedtls_mpi_fill_random(prime, primeLen, f_rng, p_rng));
//		prime->p[0] |= 2;
//		mbedtls_mpi_set_bit(prime, primeLen*8 - 1, 1);
//		mbedtls_mpi_set_bit(prime, primeLen*8 - 2, 1); 
//
//		prime->p[0] |= 1;
//		//dumpi(prime, "prime? is ? ");
//		err = mpp_make_prime(prime, primeLen * 8,  &counter,f_rng,p_rng);
//		if (err != MP_NO)
//			goto cleanup;
//		/* keep going while err == MP_NO */
//	}
//cleanup:
//	if (pb)
//		free(pb);
//	if (err) {
//		rv = SECFailure;
//	}
//	return rv;
//}
//
//int mbedtls_mpi_gen_prime2(mbedtls_mpi *X, size_t nbits, int dh_flag,
//	int(*f_rng)(void *, unsigned char *, size_t),
//	void *p_rng)
//{
//	return generate_prime(X, nbits / 8, f_rng, p_rng);
//}
