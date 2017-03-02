// ConsoleApplication1.cpp : 定义控制台应用程序的入口点。
//g++     ConsoleApplication1.cpp   -o ConsoleApplication1 -I../../include/ -L../../library/ -lmbedcrypto -fpermissive -lssl -lcrypto
//diff -Naur  mbedtls-2.3.0 mbedtls-2.3.0-bean  -x '*.gitignore' -x '*.yml' -x 'Debug' -x 'VS2010'     > bean.patch
//#$mkdir tmp
//#$cd tmp
//#$cp .. / mbedtls - 2.3.0 . - rf
//#$cp .. / bean.patch .
//#$patch - p0 --dry - run < bean.patch
//	#$patch - p0  < bean.patch
//	#$cd mbedtls - 2.3.0
//	#$make
//	#$make check
//#include "stdafx.h"
#include<mbedtls/aes.h>
#include<mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<stdint.h>

#include<openssl/rsa.h>
#include<openssl/bn.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha1.h>
#include"ut_pf_cp.h"
#include<windows.h>
extern "C" void sbox_mask_self_test(void);
extern "C" void mask_sbox_init(void);
void dump(char* str, unsigned char *d, int dlen)
{
	printf("dump %s (%d) : ",str,dlen);
	for (int i = 0; i < dlen; i++)
		printf("%02x",d[i]);
	printf("\n");
}
 
/*
void dumpbn(char* str, mbedtls_mpi *X)
{
unsigned char output[256] = { 0 };
int olen = 256;
olen = mbedtls_mpi_size(X);
int ret = mbedtls_mpi_write_binary(X, output, olen);
if (ret != 0)
printf("mbedtls_mpi_write_binary err %x", ret*-1);


printf("dump %s (%d) : ", str, olen);
for (int i = 0; i < olen; i++)
printf("%02x", output[i]);
printf("\n");
}*/
#define CHK if (ret != 0) { printf("%d:%d",__LINE__,ret); }
void test_aes256(void) {
	mbedtls_aes_context ectx;
	mbedtls_aes_context dctx;
	mbedtls_aes_init(&ectx);
	mbedtls_aes_init(&dctx);
	
	//from fips-197
	const unsigned char d[] = { 0X00, 0X11, 0X22, 0X33, 0X44, 0X55, 0X66, 0X77, 0X88, 0X99, 0XAA, 0XBB, 0XCC, 0XDD, 0XEE, 0XFF };
	const unsigned char key[] = { 0X00,0X01,0X02,0X03,0X04,0X05,0X06,0X07,0X08,0X09,0X0A,0X0B,0X0C,0X0D,0X0E,0X0F,
		0X10,0X11,0X12,0X13,0X14,0X15,0X16,0X17,0X18,0X19,0X1A,0X1B,0X1C,0X1D,0X1E,0X1F };
	int ret = 0;
	ret = mbedtls_aes_gen_mask_bytes(&ectx); CHK;
	dump("rnd1:", ectx.maskbytes, 16);
	ret = mbedtls_aes_setkey_enc(&ectx, key, 256); CHK;
	ret = mbedtls_aes_gen_mask_bytes(&dctx); CHK;
	dump("rnd2:", dctx.maskbytes, 16);
	ret = mbedtls_aes_setkey_dec(&dctx, key, 256); CHK;

	unsigned char output[16] = { 0 };
	ret = mbedtls_aes_gen_mask_bytes(&dctx); CHK;
	ret = mbedtls_aes_crypt_ecb(&ectx,
		MBEDTLS_AES_ENCRYPT,
		d,
		output); CHK;
	dump("cipher text", output, 16);
	unsigned char output2[16] = { 0 };
	ret = mbedtls_aes_gen_mask_bytes(&dctx); CHK;
	ret = mbedtls_aes_crypt_ecb(&dctx,
		MBEDTLS_AES_DECRYPT,
		output,
		output2); CHK;
	dump("plain  text", output2, 16);
	mbedtls_aes_free(&ectx);
	mbedtls_aes_free(&dctx);
}

//we need define this function in ut_* sdk .
//
extern "C" int mbedtls_hardware_poll(void *data,
	unsigned char *output, size_t len, size_t *olen)
{
	unsigned long timer = 100;
	((void)data);
	*olen = 0;

	if (len < sizeof(unsigned long))
		return(0);
	time_t t=time(NULL);
	memcpy(output, &t, sizeof(time_t));
	
	*olen = sizeof(time_t);
	return 0;
}
struct dl {
	uint8_t d[256 * 2];
	uint32_t dlen;

};
static uint8_t rsan[] = { 0XFA,0XE4,0XF4,0X5D,0XFE,0XC5,0X85,0X58,0X77,0XCF,0X7F,0XA9,0XEC,0X76,0XA9,0X6A,
	0X00,0X55,0XEB,0X2F,0X75,0XC1,0XEC,0XF1,0XB5,0XAA,0XB1,0XC5,0X01,0X22,0XE1,0X85,
	0X6A,0X3B,0XCF,0XEE,0XF4,0XF6,0X13,0X8E,0X22,0XC8,0X1D,0XA0,0XA0,0X22,0X82,0X08,
	0X98,0XD8,0X2E,0X6A,0X35,0XD7,0XCF,0X54,0X87,0X66,0XAC,0X83,0XCC,0X76,0XEC,0X89,
	0XF3,0X1D,0X4F,0XB8,0XB0,0XFF,0X95,0X3D,0XEC,0X4B,0X31,0X8E,0X14,0XE1,0X17,0X55,
	0XEB,0XD1,0XB4,0X5A,0XFD,0X6C,0X33,0XED,0X93,0XF1,0X9B,0X19,0X77,0X76,0X19,0X6C,
	0XE6,0X67,0XD8,0X20,0XDC,0X6E,0XC3,0X7C,0XEB,0XED,0X9D,0XE6,0XD9,0X64,0X65,0XD6,
	0X72,0X48,0XBE,0X4C,0XC0,0X8F,0X63,0X0F,0X85,0X96,0XFF,0X47,0X38,0XD8,0XA3,0X62,
	0XAD,0X02,0X0B,0XB5,0X54,0XF2,0XEF,0X09,0X03,0X0D,0X57,0XE8,0X25,0X20,0X4A,0XA9,
	0XDB,0X2D,0XEB,0XEA,0XA9,0X45,0XAC,0X84,0X65,0XEC,0XCF,0XDF,0XEF,0X8B,0XFB,0X88,
	0X05,0X27,0X2D,0XB0,0XF4,0X8D,0X93,0XC3,0X60,0XED,0XFC,0X54,0XAE,0XBA,0XAD,0X2B,
	0X94,0XD8,0X58,0XFF,0X49,0X1F,0X0C,0X5F,0XDF,0X15,0XAF,0X64,0XCC,0XFD,0XD6,0X84,
	0X37,0X2D,0X86,0X5C,0XEA,0XA6,0X8E,0XB2,0X05,0XC9,0XBD,0X39,0X08,0X6D,0XE0,0XB0,
	0X03,0X46,0XC9,0XEC,0X6C,0XEA,0XF9,0XF5,0XA5,0X8E,0XBB,0X69,0X44,0X38,0X37,0X30,
	0X35,0XD5,0X0B,0X90,0XCB,0X7F,0X39,0X3C,0XBF,0XF0,0X04,0X2F,0XF8,0X87,0X18,0X4A,
	0X06,0X79,0X3A,0X72,0X7F,0XB0,0XE1,0X07,0X66,0X76,0X97,0XC2,0X82,0XBD,0X23,0X6D };


static uint8_t rsad[] = { 0X89,0X68,0X9D,0XA1,0X61,0X28,0X62,0XA8,0X9A,0X2D,0XAD,0X98,0XAD,0XE6,0X2B,0X50,
0XDF,0XD0,0X2E,0X97,0X76,0XA1,0XF8,0X18,0X45,0X4B,0XB0,0X42,0XDA,0X25,0X75,0X68,
0X31,0X4F,0X82,0XC9,0X37,0XA6,0X11,0XFD,0XB5,0X74,0XEE,0X2D,0X0B,0XA6,0XFA,0X9A,
0XA4,0XC3,0X39,0X60,0X78,0X0E,0XB3,0X01,0X73,0X8A,0XBB,0X0F,0X10,0X0B,0X4D,0XEF,
0X1B,0X94,0X41,0X16,0X40,0XF2,0X29,0X95,0X99,0X75,0X71,0X35,0X84,0X9F,0XE6,0XBC,
0XEB,0X03,0X96,0X08,0X83,0X65,0X20,0X67,0X8C,0XB0,0X35,0X26,0XD4,0X73,0X7C,0XE7,
0X54,0XA5,0X29,0X0C,0X8E,0X4D,0XA7,0X89,0X22,0X59,0XA8,0X32,0X47,0X7B,0XA1,0XFE,
0XB9,0XE6,0XB7,0X3A,0XA7,0XF7,0X9F,0XE4,0X5F,0X60,0XDC,0X7C,0XF0,0X58,0X4D,0XDA,
0X66,0X95,0XB4,0XF8,0X8A,0X28,0XCE,0X90,0X16,0X43,0X3F,0X1B,0XF8,0X69,0XAF,0X65,
0X2A,0X32,0X3D,0X21,0X25,0X03,0X41,0X9F,0X74,0XED,0X2F,0X2B,0XD4,0X5A,0XDE,0X4E,
0X73,0X35,0X73,0XD2,0XC0,0X42,0XFB,0X26,0X0A,0X5C,0XA5,0X2B,0XBE,0X24,0XA3,0X2B,
0XB3,0XB6,0X51,0XF8,0X20,0XBA,0X39,0XE8,0X14,0X10,0X32,0X1C,0XFC,0XBA,0X1D,0XDF,
0X8A,0X4A,0X50,0X68,0X5E,0X1B,0XD3,0X92,0XE4,0XF7,0X33,0X92,0X25,0X49,0XFC,0XFB,
0X04,0XC4,0X08,0X77,0X3B,0X18,0X9A,0X00,0X09,0XFB,0X11,0X84,0X3F,0X64,0X3B,0XE3,
0X30,0X3E,0X77,0X4C,0X7A,0XD2,0XEA,0X22,0X85,0XB6,0XCB,0X85,0XFB,0X23,0X1A,0XF5,
0X59,0XBE,0X7F,0X7B,0X71,0XBD,0XD5,0X61,0XEE,0X4C,0XC4,0X7D,0X99,0X7A,0X03,0XA1 };


static uint8_t rsae[] = { 0X01,0X00,0X01 };

static uint8_t rsap[] = { 0XFE,0X26,0X31,0XCF,0X78,0X51,0X32,0X2A,0X35,0XA5,0X5A,0XE0,0X9D,0X71,0X54,0X29,
0XA9,0X8F,0X31,0X2A,0X56,0XE8,0X18,0XBC,0XE4,0X65,0XB6,0X5F,0XD7,0X8E,0X9D,0XCA,
0XBB,0X31,0XF6,0XCF,0X18,0X22,0XB4,0X89,0XAB,0X29,0X9C,0X46,0XE7,0X7B,0X80,0X57,
0XEB,0X56,0X97,0XFA,0X2B,0X3C,0X0F,0X0E,0XE2,0X2D,0X55,0X06,0X03,0XBD,0XFD,0XEE,
0XFE,0XA6,0XF2,0X92,0X58,0XE3,0X57,0X9F,0XBF,0XE5,0X20,0X17,0X99,0X2C,0XB7,0X6E,
0XDD,0XDD,0XC1,0XDA,0X40,0X65,0XC4,0X68,0XEA,0X37,0X04,0X8D,0X0A,0XEF,0XB5,0X01,
0X9F,0X93,0XA8,0X37,0X3B,0XE5,0X80,0XE7,0XD6,0X42,0XE3,0X87,0X07,0X4C,0X5B,0XBC,
0X8E,0X16,0XED,0X96,0X0B,0XB0,0X0D,0X3B,0X3A,0XAF,0X59,0XDD,0XD4,0X9F,0X50,0X05 };


static uint8_t rsaq[] = { 0XFC,0XB8,0XB1,0X29,0XDC,0X40,0X55,0X73,0XDC,0X9C,0X23,0X1F,0X1C,0XE2,0XFE,0X95,
0X2E,0X14,0X5C,0X40,0XA7,0X02,0X49,0X4A,0XA1,0X2B,0X52,0X02,0X72,0X7A,0XBF,0X59,
0X95,0X29,0X61,0X3F,0X2A,0X4F,0XB3,0XBB,0X81,0XDE,0X15,0X58,0XE4,0XC0,0X1C,0X5B,
0X1B,0X04,0X74,0XB1,0XA6,0X44,0XA7,0XA4,0X10,0XB6,0X4C,0X15,0X3B,0X54,0X77,0XE8,
0X29,0X48,0XF4,0XD0,0X7A,0X77,0X90,0XA2,0X3F,0XC5,0XD7,0X57,0X90,0X0C,0X45,0XED,
0X22,0XEF,0X5C,0X1B,0XEF,0X1C,0XC3,0X50,0X68,0X28,0X61,0X78,0X50,0XA5,0X2F,0X0B,
0X75,0X99,0X5A,0XA7,0XEC,0X39,0X97,0X50,0X28,0X18,0X92,0XFA,0X6A,0XC7,0X14,0X0C,
0X6D,0X6F,0XDD,0X41,0X52,0XE4,0XA0,0X13,0X61,0XDB,0X8C,0X88,0X11,0X3C,0XAA,0X49 };


static uint8_t rsadp[] = { 0XDF,0XA2,0X34,0X4A,0X5F,0X90,0XF3,0X17,0X79,0X45,0X1B,0X86,0X72,0X83,0XFA,0X8E,
0XFE,0X88,0XE5,0XB6,0X5F,0XEA,0XB3,0X79,0XE3,0X70,0X2C,0XDE,0X81,0X0B,0X19,0X85,
0XFE,0XDA,0XA4,0X56,0XEE,0XE1,0XFB,0X02,0XF8,0XFE,0X10,0X69,0XC3,0XDF,0X44,0XBC,
0X18,0X75,0X86,0X1D,0XB8,0X55,0X8C,0XDA,0X87,0XE3,0X63,0XE1,0X7B,0X01,0X7F,0XA5,
0X01,0XA7,0X5D,0XE3,0XB1,0X1B,0XBB,0X4A,0XF2,0XCC,0X67,0X44,0XDC,0XA0,0X20,0X79,
0X09,0XF9,0XCC,0X4E,0X84,0X44,0X08,0X64,0X59,0X54,0X38,0X48,0XF3,0XCA,0XA1,0XF7,
0XDF,0XB7,0X4A,0X59,0XEF,0XF6,0XAF,0X4B,0X51,0X9A,0X62,0X23,0XBB,0X24,0X51,0XC4,
0XC5,0X33,0X1F,0XB4,0XDC,0X6B,0XF9,0XF8,0X98,0X57,0X1C,0X38,0XBA,0X93,0XC5,0X11 };


static uint8_t rsadq[] = { 0X98,0X47,0XA9,0XE9,0X31,0X60,0X4A,0X9D,0X6F,0XF7,0X5D,0X6A,0X67,0XFB,0X97,0XAF,
0XC8,0X7E,0X58,0X40,0X54,0XE2,0X19,0XCB,0XB0,0X65,0XEC,0X1A,0XB1,0X64,0XA9,0X5C,
0X8F,0X76,0XC9,0XB4,0X48,0X08,0X92,0XA2,0X8F,0XD4,0X84,0X44,0X76,0X42,0X14,0X54,
0X09,0X69,0X9B,0XEF,0X57,0XE2,0XD2,0XA9,0X17,0XB0,0XE1,0X13,0X82,0X16,0X99,0XD1,
0XF8,0XDE,0X8F,0X35,0XF8,0X35,0X87,0X9F,0X5C,0X92,0X17,0XFA,0X19,0X40,0X6B,0XFA,
0X42,0X2C,0XBC,0XF1,0XD0,0X19,0X22,0XCF,0X96,0X93,0X8E,0X77,0XF3,0X10,0X35,0XD2,
0XCF,0XDF,0XC2,0X32,0XA1,0X32,0XEA,0XAC,0X50,0X1C,0XCE,0XA3,0XBA,0X27,0X8F,0X3B,
0X15,0XCE,0X6C,0X21,0XEA,0X92,0XFC,0XA9,0XF1,0X33,0X5B,0XF0,0XB9,0X82,0X36,0X91 };


static uint8_t rsau[] = { 0X56,0XF6,0X48,0XB3,0XDB,0XD8,0XA4,0XEF,0X09,0X2A,0XDA,0XE8,0X7B,0X26,0XD9,0XB8,
0XF8,0X66,0XBE,0X85,0X76,0X65,0X56,0X56,0XF6,0X65,0XC6,0XAF,0XC2,0XCD,0X7A,0X52,
0XA8,0XA8,0XED,0X7A,0X0F,0X8F,0XAE,0XCC,0XA3,0XF2,0X2D,0X38,0XC2,0X87,0XD4,0X42,
0XE6,0XAF,0X54,0X91,0XE8,0X1B,0XE6,0X53,0XF0,0XF4,0XFC,0X1F,0X69,0X22,0X46,0XE1,
0X64,0X2E,0X39,0X5D,0XF6,0X5B,0X3B,0X27,0XB7,0XF8,0X6D,0XF4,0XF3,0X6F,0X96,0X0E,
0X56,0X6F,0X4C,0XD0,0X87,0XBD,0XF4,0XA9,0X01,0XB9,0X7E,0X62,0X55,0XA8,0X9A,0XA0,
0X06,0XF0,0X9B,0XF2,0X4B,0X7B,0X34,0XF4,0XE3,0XAF,0XC1,0X02,0X8A,0X46,0XB5,0XEE,
0X77,0X76,0XC8,0X75,0X79,0XB7,0X97,0XB2,0X9C,0X23,0X03,0X03,0XBB,0XE9,0X80,0X06 };
static uint8_t* keys[] = {
	rsan,rsad,rsae,rsap,rsaq,rsadp,rsadq,rsau
};
struct myrsakey {
	dl all[8];//ndedpdqu
};

#define Cnovert2Bin(cnt,bn) \
	if (!(ret = key->all[(cnt)].dlen = BN_bn2bin((bn),key->all[(cnt)].d)))\
	{\
		printf("%d:BN_bn2bin  %d \n", __LINE__, ret);\
		goto end;\
	}
//else \
//	{ \
//		dump("key",key->all[(cnt)].d,key->all[(cnt)].dlen); \
//	}\
	//memcpy( key->all[(cnt)].d, keys[(cnt)] , key->all[(cnt)].dlen ); 
 
int get_key_from_openssl(int bits, myrsakey* key, RSA *rsa)
{

	int ret = 0;
	
	BIGNUM *e = NULL;
	e = BN_new();//no NULL check
	if (!(ret = BN_set_word(e, RSA_F4)))
		goto end;
	DWORD s = GetTickCount();  
	if (!(ret=RSA_generate_key_ex(rsa, bits, e, NULL)))
		goto end;
	DWORD ee = GetTickCount();
	printf("rsa gen take %u ms\n", ee - s); 
	if (!(ret = RSA_check_key(rsa)))
	{
		printf("rsa key gen err %d\n",ret);
		goto end;
	}
	//int BN_bn2bin(const BIGNUM *a, unsigned char *to)
	Cnovert2Bin(0, rsa->n);
	Cnovert2Bin(1, rsa->d);
	Cnovert2Bin(2, rsa->e);
	Cnovert2Bin(3, rsa->p);
	Cnovert2Bin(4, rsa->q);
	Cnovert2Bin(5, rsa->dmp1);
	Cnovert2Bin(6, rsa->dmq1);
	Cnovert2Bin(7, rsa->iqmp);
 
	
end:
	BN_free(e);
	
	return ret;

}

static int myrand(void *rng_state, unsigned char *output, size_t len)
{
	size_t use_len;
	int rnd;

	if (rng_state != NULL)
		rng_state = NULL;

	while (len > 0)
	{
		use_len = len;
		if (use_len > sizeof(int))
			use_len = sizeof(int);

		rnd = rand();
		memcpy(output, &rnd, use_len);
		output += use_len;
		len -= use_len;
	}

	return(0);
}


#define CHK2(f) do { if( ( ret = f ) != 0 ) goto end; } while( 0 )
#define KEY_LEN 256
int get_test_data_from_openssl()
{
	myrsakey key;
	RSA *rsa = NULL;
	int ret = 0;
	rsa = RSA_new();// NULL check
	if ((ret = get_key_from_openssl(KEY_LEN*8, &key, rsa)) < 0)
	{
		printf("get_key_from_openssl err %d\n", ret);
		goto end;
	}
	const unsigned char d[256] = { 0X00, 0X11, 0X22, 0X33, 0X44, 0X55, 0X66, 0X77, 0X88, 0X99, 0XAA, 0XBB, 0XCC, 0XDD, 0XEE, 0XFF 
	,0X00, 0X11, 0X22, 0X33, 0X44, 0X55, 0X66, 0X77, 0X88, 0X99, 0XAA, 0XBB, 0XCC, 0XDD, 0XEE, 0XFF };
	unsigned char out[1024] = { 0 };
	unsigned char out2[1024] = { 0 };
	if ((ret = RSA_private_encrypt(256,d,out,rsa, RSA_NO_PADDING)) < 0)
	{
		printf("RSA_private_encrypt err %d\n", ret);
		goto end;
	}
	dump("openssl output ", out, ret);

	//calc with mbedtls==================================
	mbedtls_rsa_context rsa2;
	mbedtls_rsa_init(&rsa2, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);

	rsa2.len = KEY_LEN;
	CHK2(mbedtls_mpi_read_binary(&rsa2.N, key.all[0].d, key.all[0].dlen));
	CHK2(mbedtls_mpi_read_binary(&rsa2.D, key.all[1].d, key.all[1].dlen));
	CHK2(mbedtls_mpi_read_binary(&rsa2.E, key.all[2].d, key.all[2].dlen));
	CHK2(mbedtls_mpi_read_binary(&rsa2.P, key.all[3].d, key.all[3].dlen));
	CHK2(mbedtls_mpi_read_binary(&rsa2.Q, key.all[4].d, key.all[4].dlen));
	CHK2(mbedtls_mpi_read_binary(&rsa2.DP, key.all[5].d, key.all[5].dlen));
	CHK2(mbedtls_mpi_read_binary(&rsa2.DQ, key.all[6].d, key.all[6].dlen));
	CHK2(mbedtls_mpi_read_binary(&rsa2.QP, key.all[7].d, key.all[7].dlen));
 
	size_t len = KEY_LEN;
	 
	CHK2(mbedtls_rsa_private(&rsa2, myrand, NULL, d, out2));
	dump("mbedtls output ", out2, KEY_LEN);

	CHK2(memcmp(out, out2, KEY_LEN));
	
	//check error ?
	size_t olen = 256;
	mbedtls_pk_context pk;
	mbedtls_pk_init(&pk);
	ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) ;
	mbedtls_rsa_context *rsap = mbedtls_pk_rsa(pk);
	rsap->len = 256;
	mbedtls_mpi_copy(&rsap->N, &rsa2.N); 
	mbedtls_mpi_copy(&rsap->D, &rsa2.D);
	mbedtls_mpi_copy(&rsap->E, &rsa2.E);
	mbedtls_mpi_copy(&rsap->P, &rsa2.P);
	mbedtls_mpi_copy(&rsap->Q, &rsa2.Q);
	mbedtls_mpi_copy(&rsap->DP, &rsa2.DP);
	mbedtls_mpi_copy(&rsap->DQ, &rsa2.DQ);
	mbedtls_mpi_copy(&rsap->QP, &rsa2.QP);

	ret = mbedtls_pk_encrypt(&pk, d, 200,
		out, &olen, 256,
		myrand, NULL);
	size_t o2len = 256;
	ret = mbedtls_pk_decrypt(&pk, out, olen,
		out2, &o2len, 256,
		myrand, NULL);
	dump("mbedtls_pk_encrypt output ", out, olen);
	dump("mbedtls_pk_decrypt output ", out2, o2len);

end:
	RSA_free(rsa);
	return ret;
}
#define MBEDRET(err,f) do { if( ( r = f ) < 0 ) r -= err<<16; if (r<0) goto end;} while( 0 )
void test_rsa2048()
{
	int r = 0;
	MBEDRET(4, get_test_data_from_openssl());
  
	MBEDRET(5,mbedtls_rsa_self_test(1));
end:
	printf("r end with ret = %x\n", -r);
}

void testmrsa()
{
	mbedtls_rsa_context ctx;
	uint32_t  exponent = 65537;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "what_is_this_string :)";
	 
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	int r = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char *)pers, strlen(pers));

	mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V15, 0);
	DWORD s = GetTickCount();
	r = mbedtls_rsa_gen_key(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg, 2048, exponent); 
	DWORD e = GetTickCount();
	printf("rsa gen take %u ms\n",e-s);
	uint8_t n[1024] = { 0 };
	int nlen = mbedtls_mpi_size(&ctx.N);
	r = mbedtls_mpi_write_binary(&ctx.N, n, nlen);
	dump("n output ", n, nlen);
	printf("nlen is %d\n",nlen);
}

//#define RSAENC_NOCTR
#define RSASIGN_NOCTR
void testrsakey(int act,int hashlen)
{
	ut_int32_t r = 0;
	ut_pf_cp_context_t *ctx = NULL;
	unsigned char n[1024] = { 0 };
	ut_uint32_t nlen = 1024;
	unsigned char d[1024] = { 0 };
	ut_uint32_t dlen = 1024;
	unsigned char e[1024] = { 0 };
	ut_uint32_t elen = 1024;
	unsigned char p[1024] = { 0 };
	ut_uint32_t plen = 1024;
	unsigned char q[1024] = { 0 };
	ut_uint32_t qlen = 1024;
	unsigned char dp[1024] = { 0 };
	ut_uint32_t dplen = 1024;
	unsigned char dq[1024] = { 0 };
	ut_uint32_t dqlen = 1024;
	unsigned char u[1024] = { 0 };
	ut_uint32_t ulen = 1024;

	unsigned char dout[1024] = { 0 };
	ut_uint32_t  doutlen = 1024;
	unsigned char dout2[1024] = { 0 };
	ut_uint32_t  dout2len = 1024;
	unsigned char data[256] = { 0X00, 0X11, 0X22, 0X33, 0X44, 0X55, 0X66, 0X77, 0X88, 0X99, 0XAA, 0XBB, 0XCC, 0XDD, 0XEE, 0XFF };
	printf("act is %x\n",act);
	r = ut_pf_cp_open(&ctx, UT_PF_CP_CLS_GK, UT_PF_CP_ACT_GK_RSA_CRT); 
	if (r < 0) {
		printf("call ut_pf_cp_open failed !!! r=%d\n", r);
		ut_pf_cp_close(ctx);
		return;
	}
	DWORD s = GetTickCount();
	r =ut_pf_cp_gk_rsakey( ctx,2048,e,  &elen,
		n, &nlen,
		d, &dlen,
		p, &plen,
		q, &qlen,
		dp,&dplen,
		dq,&dqlen,
		u,&ulen);
	DWORD ee = GetTickCount();
	printf("rsa gen take %u ms\n", ee - s);
	if (r < 0) {
		printf("call ut_pf_cp_gk_rsakey failed !!! r=%d\n", r);
		ut_pf_cp_close(ctx);
		return;
	}
	//dump("rsa gen key  n  is ", n, nlen);
	//dump("rsa gen key  d  is ", d, dlen);
	//dump("rsa gen key  e  is ", e, elen);

	ut_pf_cp_context_t *ctx2 = NULL;
	r = ut_pf_cp_open(&ctx2, UT_PF_CP_CLS_AC, act);
	if (r < 0) {
		printf("call ut_pf_cp_open 2 failed !!! r=%d\n", r);
		ut_pf_cp_close(ctx2);
		ut_pf_cp_close(ctx);
		return;
	}

#ifdef RSASIGN_NOCTR
	r = ut_pf_cp_ac_rsasig_crt(ctx2 , n, nlen,e,elen, p, plen, q, qlen, dp,  dplen, dq, dqlen,u, ulen,
		NULL, 0,
		data,   hashlen, dout, &doutlen);
	//r = ut_pf_cp_ac_rsasig(ctx2, n, nlen, d, dlen, e, elen, NULL, 0, data, hashlen, dout, &doutlen);
	if (r < 0) {
		printf("call ut_pf_cp_rsasign failed !!! r=%d\n", r);
		ut_pf_cp_close(ctx2);
		ut_pf_cp_close(ctx);
		return;
	}

	//dump("rsa sig  is ", dout, doutlen);
	r = ut_pf_cp_ac_rsavfy(ctx2, n, nlen, e, elen, NULL, 0, data, hashlen, dout, doutlen);
	if (r < 0) {
		printf("call ut_pf_cp_rsaverify failed !!! r=%d\n", r);
		ut_pf_cp_close(ctx2);
		ut_pf_cp_close(ctx);
		return;
	}
	else
		printf("call ut_pf_cp_rsa verify success  r=%d\n", r);
#endif

#ifdef RSAENC_NOCTR
	r = ut_pf_cp_ac_rsaenc(ctx2,n, nlen, e,  elen,NULL,0,data, hashlen, dout, &doutlen);
	if (r < 0) {
		printf("call ut_pf_cp_ac_rsaenc failed !!! r=%d\n", r);
		ut_pf_cp_close(ctx2);
		ut_pf_cp_close(ctx);
		return;
	}
	dump("ut_pf_cp_ac_rsaenc  output   is ", dout, doutlen);
	r = ut_pf_cp_ac_rsadec_crt( ctx2,
		n, nlen, e, elen,
		p, plen,
		q, qlen,
		dp, dplen,
		dq, dqlen,
		u, ulen,
		NULL, 0,
		dout, doutlen,
		dout2, &dout2len);

	//r= ut_pf_cp_ac_rsadec(ctx2, n, nlen,d,dlen, e, elen,
	//	NULL, 0,
	//	dout, doutlen,
	//	dout2, &dout2len);
	if (r < 0) {
		printf("call ut_pf_cp_ac_rsadec failed ! r=%d\n", r);
		ut_pf_cp_close(ctx2);
		ut_pf_cp_close(ctx);
		return;
	}
	
	dump("ut_pf_cp_ac_rsadec  output   is ", dout2, dout2len);
#endif


	ut_pf_cp_close(ctx);
	ut_pf_cp_close(ctx2);
} 
 
//https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_Sources_Building_Testing
//https://ftp.mozilla.org/pub/security/nss/releases/NSS_3_27_RTM/src/
//length x bits
//extern "C" int gen_prime_from_seed(unsigned int length, unsigned char *seed, int slen, mbedtls_mpi *prime);
//void testprime()
//{
//	int length = 16;
//	mbedtls_mpi X;
//	mbedtls_mpi_init(&X);
//	unsigned char seed[64] = { 0XA3,0X25,0XC9,0XA7,0XC4,0XF0,0X54,0X96,0X0B,0X64,0XF3,0XB1,0X58,0X4F,0X5E,0X51 };
//	int i = 0;
//	for (i = 0; i < 1000000; i++)
//	{
//		int r = gen_prime_from_seed(length, seed, 64, &X);
//		if (r == 0)break;
//		printf(" %d", r);
//		mbedtls_sha512(seed, 64, seed,0);
//	}
//	printf("\nfindit i=%d\n",i);
//}

void testprime2()
{
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_mpi x;

	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	int xxx = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char*)"123",
		3);
	for (int i = 0; i < 100; i++) {
		mbedtls_mpi_init(&x);
		DWORD ss = GetTickCount();
		int r = mbedtls_mpi_gen_prime(&x, 1024,0, mbedtls_ctr_drbg_random, &ctr_drbg);
		DWORD ee = GetTickCount();
		int r2 = mbedtls_mpi_is_prime(&x, mbedtls_ctr_drbg_random, &ctr_drbg);
		int blen = mbedtls_mpi_bitlen(&x);
		mbedtls_mpi_free(&x);
		printf("time is :%dms,  r=%d,%d,blen=%d\n", ee - ss, r, r2, blen);
		if (r < 0 || r2 < 0)
		{
			printf("what\n");
		}
	}
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
}
void testaesxts()
{
	ut_int32_t r = 0;
	ut_pf_cp_context_t *ctx = NULL;
	ut_pf_cp_context_t *ctx2 = NULL;
	unsigned char d[] = { 0X00, 0X11, 0X22, 0X33, 0X44, 0X55, 0X66, 0X77, 0X88, 0X99, 0XAA, 0XBB, 0XCC, 0XDD, 0XEE, 0XFF };
	unsigned char key[] = { 0X00,0X01,0X02,0X03,0X04,0X05,0X06,0X07,0X08,0X09,0X0A,0X0B,0X0C,0X0D,0X0E,0X0F,
		0X10,0X11,0X12,0X13,0X14,0X15,0X16,0X17,0X18,0X19,0X1A,0X1B,0X1C,0X1D,0X1E,0X1F };
	unsigned char dout[] = { 0X00, 0X11, 0X22, 0X33, 0X44, 0X55, 0X66, 0X77, 0X88, 0X99, 0XAA, 0XBB, 0XCC, 0XDD, 0XEE, 0XFF };
	ut_uint32_t doutlen = 16;
	unsigned char dout2[] = { 0X00, 0X11, 0X22, 0X33, 0X44, 0X55, 0X66, 0X77, 0X88, 0X99, 0XAA, 0XBB, 0XCC, 0XDD, 0XEE, 0XFF };
	ut_uint32_t doutlen2 = 16;
	r = ut_pf_cp_open(&ctx, UT_PF_CP_CLS_SC, UT_PF_CP_ACT_SC_AES_XTS);
	if (r < 0) {
		printf("call ut_pf_cp_open failed !!! r=%d\n", r);
		ut_pf_cp_close(ctx);
		return;
	}
	r = ut_pf_cp_open(&ctx2, UT_PF_CP_CLS_SC, UT_PF_CP_ACT_SC_AES_XTS);
	if (r < 0) {
		printf("call ut_pf_cp_open failed !!! r=%d\n", r);
		ut_pf_cp_close(ctx);
		return;
	}

	r = ut_pf_cp_sc_starts(ctx, key, sizeof(key), NULL, 0, 1);
	if (r < 0) {
		printf("call ut_pf_cp_sc_starts  failed !!! r=%d\n", r);
		ut_pf_cp_close(ctx);
		return;
	}
	r = ut_pf_cp_sc_finish(ctx, d, sizeof(d), dout, &doutlen);
	if (r < 0) {
		printf("call ut_pf_cp_sc_update  failed !!! r=%d\n", r);
		ut_pf_cp_close(ctx);
		return;
	}

	dump("d is ", d, 16);
	dump("dout is ", dout, doutlen);
	r = ut_pf_cp_sc_starts(ctx2, key, sizeof(key), NULL, 0, 0);
	if (r < 0) {
		printf("call ut_pf_cp_sc_starts  failed !!! r=%d\n", r);
		ut_pf_cp_close(ctx2);
		return;
	}
	r = ut_pf_cp_sc_finish(ctx2, dout, doutlen, dout2, &doutlen2);
	if (r < 0) {
		printf("call ut_pf_cp_sc_update  failed !!! r=%d\n", r);
		ut_pf_cp_close(ctx2);
		return;
	}
	dump("dout2 is ", dout2, doutlen2);
	ut_pf_cp_close(ctx);
	ut_pf_cp_close(ctx2);
}
int main()
{ 
	unsigned int a = 8;
	unsigned int b = 7;
	int x = b - a;
	testaesxts();
	//testprime2();
	//mask_sbox_init();
	//sbox_mask_self_test();
	//testmrsa();
	//test_aes256();
	//test_rsa2048();
#ifdef RSASIGN_NOCTR
	//for (int i = 0; i<100; i++)testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_MD5, 16);
	//testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA1, 20);
	
	//testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA224, 28);
	//testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA256, 32);
	//testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA384, 48);
	//testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5_SHA512, 64);
	//testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA1, 20);
	//testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA224, 28);
	//testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA256, 32);
	//testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA384, 48);
	//testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_PSS_MGF_SHA512, 64);
#endif
#ifdef RSAENC_NOCTR
	//testrsakey(UT_PF_CP_ACT_AC_RSA_NOPAD, 256);
	//testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_V1_5, 123);
	//testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA1, 124);
	//testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA224, 125);
	//testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA256, 126);
	//testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA384, 127);
	//testrsakey(UT_PF_CP_ACT_AC_RSA_PKCS1_OAEP_MGF1_SHA512, 128);
#endif	 
    return 0;
}

