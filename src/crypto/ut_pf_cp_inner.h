#ifndef UT_PF_CP_INNER_H__
#define UT_PF_CP_INNER_H__
 
#include <ut_sys_type.h>
#include <ut_sys_util.h>
#include "cryptoApi.h"
#include <contrib/libutcrypto/ut_pf_cp_hwc.h>
#include <mbedtls/aes.h>
#include <mbedtls/bignum.h>
#include <mbedtls/bn_mul.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/entropy_poll.h>
#include <mbedtls/rsa.h>

typedef struct __ut_pf_cp_info_t_ {
	ut_uint32_t		ver;
	ut_uint32_t		cls[7][4];	// [0]:md [1]:sc [2]:mc [3]:ae [4]:ac [5]:gk [6]:rd
} ut_pf_cp_info_t;

typedef struct __md_context_t {
	union {
		struct {
			psDigestContext_t 			 ctx;
		} sm3;
		struct {
			psDigestContext_t 			 ctx;
		} md5;
		struct {
			psDigestContext_t 			 ctx;
		} sha1;
		struct {
			psDigestContext_t 			 ctx;
		} sha224;
		struct {
			psDigestContext_t 			 ctx;
		} sha256;
		struct {
			psDigestContext_t 			 ctx;
		} sha384;
		struct {
			psDigestContext_t 			 ctx;
		} sha512;
	} ;
} md_context_t;

typedef enum {
	UTPFCP_CIPHER_DEC = 0,
    UTPFCP_CIPHER_ENC 
} ut_pf_cp_cipher_id_t;

typedef struct __sc_context_t {
	int 								 enc;//ut_pf_cp_cipher_id_t
	union {
		struct {
			psSm4Key_t 				 	 key;
			unsigned char			 vec[16];
		} sm4;
		struct {
			psDes3Key_t 				 key;
			unsigned char			 vec[16];
		} des;
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
	} ;
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
				struct ccm128_context  	   c;

				unsigned char		    *add;
				unsigned int		  curlen;
			} ccm;
			struct {
				unsigned int		  taglen;
				struct gcm128_context  	   c;
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
			md_context_t 		          md;
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
	union {
		struct {
		} rsa;
		struct {
		} ecc;
	} ;
} gk_context_t;

struct __ut_pf_cp_context_t {
	int 							   class;
	int 							  action;
	int 							   state;
	int							     use_hwc;
	union {
		md_context_t 					  md;
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
	UTPFCP_ERR_UNKNOWN ,
    UTPFCP_ERR_SETKEY ,
	UTPFCP_ERR_INVALID_PARAMS ,
	UTPFCP_ERR_MALLOC_FAILED ,
	UTPFCP_ERR_UNKNOWN_ACTION,
	UTPFCP_ERR_RNG_STAT_NULL,
	UTPFCP_ERR_RNG_SEED,
	UTPFCP_ERR_RSA,
	UTPFCP_ERR_TOOSMALLLEN,
	UTPFCP_ERR_MPI,
	UTPFCP_ERR_LOADBIGINT ,
	UTPFCP_ERR_LOADECCPARAM
} ut_pf_cp_error_id_t;

//err is 0x**** ,mbedtls is -0x****,so we combine them.
#define MBEDRET(err,f) do { if( ( r = f ) < 0 ) r -= err<<16; if (r<0) goto end;} while( 0 )
#define MBEDRET2(err,f) do { if( ( r = f ) < 0 ) r -= err<<16; if (r<0) goto end2;} while( 0 ) 
#define MBEDRET3(f) do { if( ( r = f ) < 0 )   goto end;} while( 0 ) 
//#define PERF_TEST	
	
#endif
