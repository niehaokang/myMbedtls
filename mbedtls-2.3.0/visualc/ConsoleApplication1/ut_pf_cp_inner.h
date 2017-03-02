#ifndef UT_PF_CP_INNER_H__
#define UT_PF_CP_INNER_H__

typedef unsigned long long ut_uint64_t;
typedef long long           ut_int64_t;
typedef unsigned int       ut_uint32_t;
typedef int                 ut_int32_t;
typedef unsigned short     ut_uint16_t;
typedef short               ut_int16_t;
typedef unsigned char       ut_uint8_t;
typedef char                 ut_int8_t;
typedef unsigned long       ut_mword_t; /*machine word*/
typedef unsigned long         ut_cap_t;
typedef unsigned long        ut_addr_t;
typedef unsigned long        ut_size_t;
typedef long            ut_ssize_t;
typedef long            ut_off_t;

#include <mbedtls/aes.h>
#include <mbedtls/bignum.h>
#include <mbedtls/bn_mul.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/entropy_poll.h>
#include <mbedtls/rsa.h>
typedef unsigned char		u8;
typedef unsigned short		u16;
typedef unsigned int		u32;
typedef unsigned long long	u64;
typedef struct __ut_pf_cp_info_t_ {
	ut_uint32_t		ver;
	ut_uint32_t		cls[7][4];	// [0]:md [1]:sc [2]:mc [3]:ae [4]:ac [5]:gk [6]:rd
} ut_pf_cp_info_t;
 
typedef enum {
	UTPFCP_CIPHER_DEC = 0,
    UTPFCP_CIPHER_ENC 
} ut_pf_cp_cipher_id_t;
typedef void(*block128_f)(const unsigned char in[16],
	unsigned char out[16],
	const void *key);
struct xts128_context {
	void      *key1, *key2;
	block128_f block1, block2;
	union { u64 u[2]; u32 d[4]; u8 c[16]; } tweak, scratch;
};

typedef struct __sc_context_t {
	int 								 enc;//ut_pf_cp_cipher_id_t
	union {
 
		struct {
			mbedtls_aes_context		key;
			unsigned char			 vec[16];
			union {
				struct {
					unsigned char ecount[16];
					unsigned int	     num;
				} ctr;
				struct {
					mbedtls_aes_context	 key;
					struct xts128_context  c;
				} xts;
			} mode;
		} aes;
	};
} sc_context_t;

typedef struct __ae_context_t {
	int 								 enc;
	struct {
		mbedtls_aes_context			 key;
		unsigned char				 vec[16];
		union {
			struct {
				unsigned int		  addlen;
				unsigned int		  taglen; 

				unsigned char		    *add;
				unsigned int		  curlen;
			} ccm;
			struct {
				unsigned int		  taglen; 
			} gcm;
		} mode;
	} aes;
} ae_context_t;

typedef struct __mc_context_t {
	union {
		struct {
			unsigned char 		   ipad[128];
			unsigned char 		   opad[128];
			unsigned int 		   blocksize; 
		} hmac;

		struct {
			unsigned int 		    last_len;
			unsigned char 		    last[16];
			unsigned char 		      k1[16];
			unsigned char 		      k2[16];
			sc_context_t 		          sc;
		} cmac;

		struct {
			unsigned int 		    last_len;
			unsigned char 		    last[16];
			sc_context_t			      sc;
		} ccmc;
	} ;
} mc_context_t;

typedef struct __ac_context_t {
	int 								 enc;
	int 								 pub;
	union {
		struct {
			mbedtls_rsa_context			key;
			mbedtls_ctr_drbg_context	rng_ctx;
			mbedtls_entropy_context		entropy_ctx;
		} rsa;
	} ;
} ac_context_t;

typedef struct __gk_context_t {

} gk_context_t;

struct __ut_pf_cp_context_t {
	int 							   cls;
	int 							  action;
	int 							   state;
	int							     use_hwc;
	union { 
		sc_context_t 					  sc;
		mc_context_t 					  mc;
		ae_context_t 					  ae;
		ac_context_t 					  ac;
		gk_context_t 					  gk;
		void						    *hwc;
	} 								  cipher;
} ;

typedef enum {
	UTPFCP_SUCCESS = 0,
    UTPFCP_ERR_SETKEY ,
	UTPFCP_ERR_INVALID_PARAMS ,
	UTPFCP_ERR_MALLOC_FAILED ,
	UTPFCP_ERR_UNKNOWN_ACTION,
	UTPFCP_ERR_RNG_STAT_NULL,
	UTPFCP_ERR_RNG_SEED,
	UTPFCP_ERR_RSA,
	UTPFCP_ERR_TOOSMALLLEN,
	UTPFCP_ERR_MPI,
} ut_pf_cp_error_id_t;

//err is 0x**** ,mbedtls is -0x****,so we combine them.

#define MBEDRET(err,f) do { if( ( r = f ) < 0 ) r -= err<<16; if (r<0) goto end;} while( 0 )
#define MBEDRET2(err,f) do { if( ( r = f ) < 0 ) r -= err<<16; if (r<0) goto end2;} while( 0 ) 
#define MBEDRET3(f) do { if( ( r = f ) < 0 )   goto end;} while( 0 ) 




#endif
