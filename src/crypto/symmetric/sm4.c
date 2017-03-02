/*
 * SM4 Encryption alogrithm (SMS4 algorithm)
 * GM/T 0002-2012 Chinese National Standard ref:http://www.oscca.gov.cn/
 *
 *
 * Test vector 1
 * plain: 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
 * key:   01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
 *	   round key and temp computing result:
 *	   rk[ 0] = f12186f9 X[ 0] = 27fad345
 * 		    rk[ 1] = 41662b61 X[ 1] = a18b4cb2
 *		    rk[ 2] = 5a6ab19a X[ 2] = 11c1e22a
 *		    rk[ 3] = 7ba92077 X[ 3] = cc13e2ee
 *		    rk[ 4] = 367360f4 X[ 4] = f87c5bd5
 *		    rk[ 5] = 776a0c61 X[ 5] = 33220757
 *		    rk[ 6] = b6bb89b3 X[ 6] = 77f4c297
 *		    rk[ 7] = 24763151 X[ 7] = 7a96f2eb
 *		    rk[ 8] = a520307c X[ 8] = 27dac07f
 *		    rk[ 9] = b7584dbd X[ 9] = 42dd0f19
 *		    rk[10] = c30753ed X[10] = b8a5da02
 *		    rk[11] = 7ee55b57 X[11] = 907127fa
 *		    rk[12] = 6988608c X[12] = 8b952b83
 *		    rk[13] = 30d895b7 X[13] = d42b7c59
 *		    rk[14] = 44ba14af X[14] = 2ffc5831
 *		    rk[15] = 104495a1 X[15] = f69e6888
 *		    rk[16] = d120b428 X[16] = af2432c4
 *		    rk[17] = 73b55fa3 X[17] = ed1ec85e
 *		    rk[18] = cc874966 X[18] = 55a3ba22
 *		    rk[19] = 92244439 X[19] = 124b18aa
 *		    rk[20] = e89e641f X[20] = 6ae7725f
 *		    rk[21] = 98ca015a X[21] = f4cba1f9
 *		    rk[22] = c7159060 X[22] = 1dcdfa10
 *		    rk[23] = 99e1fd2e X[23] = 2ff60603
 *		    rk[24] = b79bd80c X[24] = eff24fdc
 *		    rk[25] = 1d2115b0 X[25] = 6fe46b75
 *		    rk[26] = 0e228aeb X[26] = 893450ad
 *		    rk[27] = f1780c81 X[27] = 7b938f4c
 *		    rk[28] = 428d3654 X[28] = 536e4246
 *		    rk[29] = 62293496 X[29] = 86b3e94f
 *		    rk[30] = 01cf72e5 X[30] = d206965e
 *		    rk[31] = 9124a012 X[31] = 681edf34
 * cypher: 68 1e df 34 d2 06 96 5e 86 b3 e9 4f 53 6e 42 46
 *
 * test vector 2
 * the same key and plain 1000000 times coumpting
 * plain:  01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
 * key:    01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
 * cypher: 59 52 98 c7 c6 fd 27 1f 04 02 f8 04 c3 3d 3f 66
*/

#include "../cryptoApi.h"

#ifdef USE_SM4

/* switch big/little endian */
#define L2B_ENDIAN_UINT(n, b, i)				\
{								\
	(n) = ((unsigned int) (b)[(i)] << 24)			\
		| ((unsigned int) (b)[(i) + 1] << 16)		\
		| ((unsigned int) (b)[(i) + 2] <<  8)		\
		| ((unsigned int) (b)[(i) + 3]);		\
}

#define B2L_ENDIAN_UINT(n, b, i)			        \
{								\
	(b)[(i)] = (unsigned char) ((n) >> 24);			\
	(b)[(i) + 1] = (unsigned char) ((n) >> 16);		\
	(b)[(i) + 2] = (unsigned char) ((n) >>  8);		\
	(b)[(i) + 3] = (unsigned char) ((n));			\
}

/* rotate shift left marco definition */
#define LSL(x, n) (((x) & 0xFFFFFFFF) << n)
#define RO2L(x, n) (LSL((x), n) | ((x) >> (32 - n)))

/* expanded SM4 Sboxe: 8bits input convert to 8 bits output */
static const unsigned char Sbox[16][16] = {
	{0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05},
	{0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},
	{0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62},
	{0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6},
	{0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8},
	{0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35},
	{0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87},
	{0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e},
	{0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1},
	{0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3},
	{0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f},
	{0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51},
	{0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8},
	{0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0},
	{0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84},
	{0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48}
};

/* system parameter */
static const unsigned int FK[4] = {
	0xa3b1bac6, 0x56aa3350,
	0x677d9197, 0xb27022dc
};

/* fixed parameter */
static const unsigned int CK[32] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};


/*
 * sm4_Sbox - get the related value from Sbox.
 * @a: 0x00~0xFF (8 bits unsigned value).
 */
static unsigned char sm4_Sbox(unsigned char a)
{
	unsigned char *sb = (unsigned char *)Sbox;
	unsigned char sbv = (unsigned char)(sb[a]);

	return sbv;
}

/* sm4_T - T(.) = L(t(.)) */
static unsigned int sm4_T(unsigned int ka)
{
	unsigned int bb = 0;
	unsigned int C = 0;
	unsigned char a[4];
	unsigned char b[4];

	B2L_ENDIAN_UINT(ka, a, 0)
	b[0] = sm4_Sbox(a[0]);
	b[1] = sm4_Sbox(a[1]);
	b[2] = sm4_Sbox(a[2]);
	b[3] = sm4_Sbox(a[3]);
	L2B_ENDIAN_UINT(bb, b, 0)
	C =bb ^ (RO2L(bb, 2)) ^ (RO2L(bb, 10)) ^ (RO2L(bb, 18)) ^ (RO2L(bb, 24));

	return C;
}

/* sm4_F - the iterating function to encrypt or decrypt the contents */
static inline unsigned int sm4_F(unsigned int x0, unsigned int x1,
				 unsigned int x2, unsigned int x3,
				 unsigned int rk)
{
	return (x0 ^ sm4_T(x1 ^ x2 ^ x3 ^ rk));
}

/* sm4_Tt - T'(.) = L'(t(.)) */
static unsigned int sm4_Tt(unsigned int ka)
{
	unsigned int bb = 0;
	unsigned int rk = 0;
	unsigned char a[4];
	unsigned char b[4];

	B2L_ENDIAN_UINT(ka, a, 0)
	b[0] = sm4_Sbox(a[0]);
	b[1] = sm4_Sbox(a[1]);
	b[2] = sm4_Sbox(a[2]);
	b[3] = sm4_Sbox(a[3]);
	L2B_ENDIAN_UINT(bb, b, 0)
	rk = bb ^ (RO2L(bb, 13)) ^ (RO2L(bb, 23));

	return rk;
}

static int sm4_rk(psSm4Key_t *ctx, const unsigned char key[16])
{
	unsigned int MK[4];
	unsigned int K[36];
	unsigned int i;

	L2B_ENDIAN_UINT(MK[0], key, 0);
	L2B_ENDIAN_UINT(MK[1], key, 4);
	L2B_ENDIAN_UINT(MK[2], key, 8);
	L2B_ENDIAN_UINT(MK[3], key, 12);
	K[0] = MK[0] ^ FK[0];
	K[1] = MK[1] ^ FK[1];
	K[2] = MK[2] ^ FK[2];
	K[3] = MK[3] ^ FK[3];
	/* 32 is ruled by the specification of SM4. */
	for(i = 0; i < 32; i++)
	{
		K[i + 4] = K[i] ^ (sm4_Tt(K[i + 1] ^ K[i + 2] ^
					  K[i + 3] ^ CK[i]));
		ctx->rk[i] = K[i + 4];
	}

	return 0;
}

int32 psSm4InitKey(const unsigned char *key, uint32 keylen,
						psSm4Key_t *skey)
{
	if (key == NULL || skey == NULL) {
		psTraceCrypto("Bad args to psSm4InitKey\n");
		return PS_ARG_FAIL;
	}

	if (keylen != 16) {
		psTraceCrypto("Invalid SM4 key length\n");
		return CRYPT_INVALID_KEYSIZE;
	}

	sm4_rk(skey, key);

	return PS_SUCCESS;
}

void psSm4EncryptBlock(const unsigned char *pt, unsigned char *ct,
						psSm4Key_t *skey)
{
	unsigned int i = 0;
	unsigned int buf[36];

	if (pt == NULL || ct == NULL || skey == NULL) {
		return;
	}

	memset(buf, 0, sizeof(buf));

	L2B_ENDIAN_UINT(buf[0], pt, 0);
	L2B_ENDIAN_UINT(buf[1], pt, 4);
	L2B_ENDIAN_UINT(buf[2], pt, 8);
	L2B_ENDIAN_UINT(buf[3], pt, 12);

	/* 32 is ruled by the specification of SM4. */
	while(i < 32) {
		buf[i + 4] = sm4_F(buf[i], buf[i + 1], buf[i + 2], buf[i + 3], skey->rk[i]);
		i++;
	}

	B2L_ENDIAN_UINT(buf[35], ct, 0);
	B2L_ENDIAN_UINT(buf[34], ct, 4);
	B2L_ENDIAN_UINT(buf[33], ct, 8);
	B2L_ENDIAN_UINT(buf[32], ct, 12);

	return ;
}

void psSm4DecryptBlock(const unsigned char *ct, unsigned char *pt,
						psSm4Key_t *skey)
{
	unsigned int i = 0;
	unsigned int buf[36];

	if (pt == NULL || ct == NULL || skey == NULL) {
		return;
	}

	memset(buf, 0, sizeof(buf));

	L2B_ENDIAN_UINT(buf[0], ct, 0);
	L2B_ENDIAN_UINT(buf[1], ct, 4);
	L2B_ENDIAN_UINT(buf[2], ct, 8);
	L2B_ENDIAN_UINT(buf[3], ct, 12);

	/* 32 is ruled by the specification of SM4. */
	while(i < 32) {
		buf[i + 4] = sm4_F(buf[i], buf[i + 1], buf[i + 2], buf[i + 3], skey->rk[31-i]);
		i++;
	}

	B2L_ENDIAN_UINT(buf[35], pt, 0);
	B2L_ENDIAN_UINT(buf[34], pt, 4);
	B2L_ENDIAN_UINT(buf[33], pt, 8);
	B2L_ENDIAN_UINT(buf[32], pt, 12);

	return ;
}

#endif
