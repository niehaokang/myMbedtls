/**
 * sm3.c - SM3 Hash algorithm
 *
 *
 * Testing data from SM3 Standards specification
 * http://www.oscca.gov.cn/News/201012/News_1199.htm
 *
 * sample 1:
 * input: "abc"
 * output: 66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0
 *
 * sample 2:
 * input: "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
 * output: debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732
 **/

#include "../cryptoApi.h"

#ifdef USE_SM3

#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))

#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))


#define LSL(x, n) (((x) & 0xFFFFFFFF) << n)
#define RO2L(x, n) (LSL((x), n) | ((x) >> (32 - n)))

#define P0(x) ((x) ^ RO2L((x), 9) ^ RO2L((x), 17))
#define P1(x) ((x) ^ RO2L((x), 15) ^ RO2L((x), 23))

/**
 * switch big/little endian based on 32bit integer
 */
#define L2B_ENDIAN_UINT(n, b, i)			\
{							\
	(n) = ((unsigned int)(b)[(i)] << 24)		\
		| ((unsigned int)(b)[(i) + 1] << 16)	\
		| ((unsigned int)(b)[(i) + 2] <<  8)	\
		| ((unsigned int)(b)[(i) + 3]);		\
}

#define B2L_ENDIAN_UINT(n, b, i)			\
{                                                       \
	(b)[(i)] = (unsigned char)((n) >> 24);		\
	(b)[(i) + 1] = (unsigned char)((n) >> 16);	\
	(b)[(i) + 2] = (unsigned char)((n) >>  8);	\
	(b)[(i) + 3] = (unsigned char)((n));		\
}


static void sm3_CF_process(struct sm3_state *ctx, unsigned char data[64])
{
	unsigned int SS1, SS2, TT1, TT2, W[68], W1[64];
	unsigned int A, B, C, D, E, F, G, H;
	unsigned int T[64];
	int j;
#ifndef ONE_STEP
	unsigned int Temp1, Temp2, Temp3, Temp4, Temp5;
#endif

	for (j = 0; j < 16; j++)
		T[j] = 0x79CC4519;
	for (j = 16; j < 64; j++)
		T[j] = 0x7A879D8A;

	L2B_ENDIAN_UINT(W[0], data, 0);
	L2B_ENDIAN_UINT(W[1], data, 4);
	L2B_ENDIAN_UINT(W[2], data, 8);
	L2B_ENDIAN_UINT(W[3], data, 12);
	L2B_ENDIAN_UINT(W[4], data, 16);
	L2B_ENDIAN_UINT(W[5], data, 20);
	L2B_ENDIAN_UINT(W[6], data, 24);
	L2B_ENDIAN_UINT(W[7], data, 28);
	L2B_ENDIAN_UINT(W[8], data, 32);
	L2B_ENDIAN_UINT(W[9], data, 36);
	L2B_ENDIAN_UINT(W[10], data, 40);
	L2B_ENDIAN_UINT(W[11], data, 44);
	L2B_ENDIAN_UINT(W[12], data, 48);
	L2B_ENDIAN_UINT(W[13], data, 52);
	L2B_ENDIAN_UINT(W[14], data, 56);
	L2B_ENDIAN_UINT(W[15], data, 60);

	for (j = 16; j < 68; j++) {
#ifdef ONE_STEP
		W[j] = P1(W[j - 16] ^ W[j - 9] ^ RO2L(W[j - 3], 15)) ^ \
		       RO2L(W[j - 13], 7) ^ W[j - 6];
#else
		Temp1 = W[j - 16] ^ W[j - 9];
		Temp2 = RO2L(W[j - 3], 15);
		Temp3 = Temp1 ^ Temp2;
		Temp4 = P1(Temp3);
		Temp5 = RO2L(W[j - 13], 7) ^ W[j - 6];
		W[j] = Temp4 ^ Temp5;
#endif
	}

	for (j =  0; j < 64; j++) {
		W1[j] = W[j] ^ W[j + 4];
	}

	A = ctx->iter_V[0];
	B = ctx->iter_V[1];
	C = ctx->iter_V[2];
	D = ctx->iter_V[3];
	E = ctx->iter_V[4];
	F = ctx->iter_V[5];
	G = ctx->iter_V[6];
	H = ctx->iter_V[7];

	for (j = 0; j < 16; j++) {
		SS1 = RO2L((RO2L(A, 12) + E + RO2L(T[j], j)), 7);
		SS2 = SS1 ^ RO2L(A, 12);
		TT1 = FF0(A, B, C) + D + SS2 + W1[j];
		TT2 = GG0(E, F, G) + H + SS1 + W[j];
		D = C;
		C = RO2L(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = RO2L(F, 19);
		F = E;
		E = P0(TT2);
	}

	for (j = 16; j < 64; j++) {
		SS1 = RO2L((RO2L(A, 12) + E + RO2L(T[j], j)), 7);
		SS2 = SS1 ^ RO2L(A, 12);
		TT1 = FF1(A, B, C) + D + SS2 + W1[j];
		TT2 = GG1(E, F, G) + H + SS1 + W[j];
		D = C;
		C = RO2L(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = RO2L(F, 19);
		F = E;
		E = P0(TT2);
	}

	ctx->iter_V[0] ^= A;
	ctx->iter_V[1] ^= B;
	ctx->iter_V[2] ^= C;
	ctx->iter_V[3] ^= D;
	ctx->iter_V[4] ^= E;
	ctx->iter_V[5] ^= F;
	ctx->iter_V[6] ^= G;
	ctx->iter_V[7] ^= H;
}

/* initialize the operation context of SM3 */
int psSm3Init(psDigestContext_t *md)
{
	md->sm3.total[0] = 0;
	md->sm3.total[1] = 0;

	md->sm3.iter_V[0] = 0x7380166F;
	md->sm3.iter_V[1] = 0x4914B2B9;
	md->sm3.iter_V[2] = 0x172442D7;
	md->sm3.iter_V[3] = 0xDA8A0600;
	md->sm3.iter_V[4] = 0xA96F30BC;
	md->sm3.iter_V[5] = 0x163138AA;
	md->sm3.iter_V[6] = 0xE38DEE4D;
	md->sm3.iter_V[7] = 0xB0FB0E4E;

	return 0;
}

/* update data and get the intermediate result. */
int psSm3Update(psDigestContext_t *md, unsigned char *buf, int len)
{
	int fill;
	unsigned int left;

	if ( len <= 0 )
		return 1;

	left = md->sm3.total[0] & 0x3F;
	fill = 64 - left;

	md->sm3.total[0] += len;
	md->sm3.total[0] &= 0xFFFFFFFF;

	if (md->sm3.total[0] < (unsigned int)len)
		md->sm3.total[1]++;

	if (left && (len >= fill)) {
		memcpy((void *)(md->sm3.buffer + left), (void *)buf, fill);
		sm3_CF_process(&md->sm3, md->sm3.buffer);
		buf += fill;
		len  -= fill;
		left = 0;
	}

	while (len >= 64) {
		sm3_CF_process(&md->sm3, buf);
		buf += 64;
		len  -= 64;
	}

	if (len > 0) {
		memcpy((void *)(md->sm3.buffer + left), (void *)buf, len);
	}

	return 0;
}

static const unsigned char sm3_padding[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* get the final result to output. */
int psSm3Final(psDigestContext_t *md, unsigned char *hash)
{
	unsigned int last, padn;
	unsigned int high, low;
	unsigned char msglen[8];

	high = (md->sm3.total[0] >> 29) | (md->sm3.total[1] <<  3);
	low  = (md->sm3.total[0] <<  3);

	B2L_ENDIAN_UINT(high, msglen, 0);
	B2L_ENDIAN_UINT(low, msglen, 4);

	last = md->sm3.total[0] & 0x3F;
	padn = (last < 56) ? (56 - last) : (120 - last);

	psSm3Update(md, (unsigned char *)sm3_padding, padn);
	psSm3Update(md, msglen, 8);

	B2L_ENDIAN_UINT(md->sm3.iter_V[0], hash, 0);
	B2L_ENDIAN_UINT(md->sm3.iter_V[1], hash, 4);
	B2L_ENDIAN_UINT(md->sm3.iter_V[2], hash,  8);
	B2L_ENDIAN_UINT(md->sm3.iter_V[3], hash, 12);
	B2L_ENDIAN_UINT(md->sm3.iter_V[4], hash, 16);
	B2L_ENDIAN_UINT(md->sm3.iter_V[5], hash, 20);
	B2L_ENDIAN_UINT(md->sm3.iter_V[6], hash, 24);
	B2L_ENDIAN_UINT(md->sm3.iter_V[7], hash, 28);

	return 0;
}

#endif
