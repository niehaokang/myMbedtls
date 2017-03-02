#ifndef __LIBMATRIX_S_H__
#define __LIBMATRIX_S_H__

#ifdef __cplusplus
    extern "C" {
#endif

/******************************************************************************/
/* Configurable features */
/******************************************************************************/
/*
	If enabled, calls to the psError set of APIs will perform a platform
	abort on the exeutable to aid in debugging.
*/
/* #define HALT_ON_PS_ERROR */ /* NOT RECOMMENDED FOR PRODUCTION BUILDS */

/******************************************************************************/
/*
	Turn on the psTraceCore set of APIs for log trace of the core module
*/
/* #define USE_CORE_TRACE */


/******************************************************************************/
/*
	Include the osdepMutex family of APIs
*/
/* #define USE_MULTITHREADING */

/******************************************************************************/
/*
	Use C_GenerateRandom for entropy gathering
*/
/* #define USE_PKCS11_ENTROPY */


/******************************************************************************/
/*
	Platform detection based on compiler settings
	@see http://sourceforge.net/p/predef/wiki/Home/
*/
/* Determine the operating system (if any) */
#if 0
#if defined(__linux__) /* Linux and Android */
 #define POSIX
 #define LINUX
 #define MATRIX_USE_FILE_SYSTEM
#elif defined(__APPLE__) && defined(__MACH__) /* Mac OS X */
 #define POSIX
 #define OSX
 #define HAVE_NATIVE_INT64
 #define MATRIX_USE_FILE_SYSTEM
#elif defined(_WIN32) /* Windows */
 #define WIN32
 #define HAVE_NATIVE_INT64
 #define MATRIX_USE_FILE_SYSTEM
#endif
#else
 #define SOTER
#endif

/* For others such as FREERTOS, define in build system */

/* Determine which assembly language optimizations we can use */
#if defined(__GNUC__) || defined(__clang__) /* Only supporting gcc-like */
#if defined(__x86_64__)
 #define PSTM_X86_64
 #define PSTM_64BIT /* Supported by architecture */
#elif defined(__i386__)
 #define PSTM_X86
#elif defined(__arm__)
 #define PSTM_ARM
 //__aarch64__ /* 64 bit arm */
 //__thumb__ /* Thumb mode */
#elif defined(__mips__)
 #define PSTM_MIPS
#endif
#endif /* GNUC/CLANG */

/* Try to determine if the compiler/platform supports 64 bit integer ops */
#if !defined(HAVE_NATIVE_INT64) && defined(__SIZEOF_LONG_LONG__)
 #define HAVE_NATIVE_INT64 /* Supported by compiler */
#endif

/* Detect endian */
#if defined __LITTLE_ENDIAN__ || defined __i386__ || defined __x86_64__ || \
	defined _M_X64 || defined _M_IX86 || \
	defined __ARMEL__ || defined __MIPSEL__
 #define __ORDER_LITTLE_ENDIAN__ 1234
 #define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
#endif
#ifdef __BYTE_ORDER__        /* Newer GCC and LLVM */
 #if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
  #define ENDIAN_LITTLE
 #else
  #define ENDIAN_BIG
 #endif
 #ifdef PSTM_64BIT
  #define ENDIAN_64BITWORD
 #else
  #define ENDIAN_32BITWORD
 #endif
#else
 #if (defined(_MSC_VER) && defined(WIN32)) || \
   (defined(__GNUC__) && (defined(__DJGPP__) || defined(__CYGWIN__) || \
   defined(__MINGW32__) || defined(__i386__)))
  #define ENDIAN_LITTLE
  #define ENDIAN_32BITWORD
 #else
  #warning "Cannot determine endianness, using neutral"
 #endif
/* #define ENDIAN_LITTLE */
/* #define ENDIAN_BIG */

/* #define ENDIAN_32BITWORD */
/* #define ENDIAN_64BITWORD */
#endif

#if (defined(ENDIAN_BIG) || defined(ENDIAN_LITTLE)) && \
!(defined(ENDIAN_32BITWORD) || defined(ENDIAN_64BITWORD))
#error You must specify a word size as well as endianness
#endif

#if !(defined(ENDIAN_BIG) || defined(ENDIAN_LITTLE))
#define ENDIAN_NEUTRAL
#endif

/******************************************************************************/
/*
	APIs that must be implemented on every platform
*/

#ifdef WIN32
 #ifndef _USRDLL
  #define PSPUBLIC extern __declspec(dllimport)
 #else
  #define PSPUBLIC extern __declspec(dllexport)
 #endif
#else
 #define PSPUBLIC extern
#endif /* !WIN32 */

extern int	osdepTraceOpen(void);
extern void	osdepTraceClose(void);
extern int	osdepTimeOpen(void);
extern void	osdepTimeClose(void);
extern int	osdepEntropyOpen(void);
extern void	osdepEntropyClose(void);
#ifdef HALT_ON_PS_ERROR
 extern void	osdepBreak(void);
#endif

#ifndef min
 #define min(a,b)    (((a) < (b)) ? (a) : (b))
#endif /* min */

/******************************************************************************/
/*
	If the Makefile specifies that MatrixSSL does not currently have
	a layer for the given OS, or the port is to "bare metal" hardware,
	do basic defines here and include externally provided file "matrixos.h".
	In addition, if building for such a platform, a C file defining the above
	functions must be linked with the final executable.
*/
#ifdef PS_UNSUPPORTED_OS
 #include "matrixos.h"
#else
/******************************************************************************/
/*
	Supported Platforms below. The implementations of the apis are in
	platform specific directories, such as core/POSIX and core/ECOS

	POSIX define is used for Linux and Mac OS X
*/
#include <stdio.h>

#ifndef POSIX
 #if defined(LINUX) || defined(OSX)
  #define POSIX
 #endif
#endif

#if defined(POSIX)
 #include <stdint.h>
 typedef int32_t int32;
 typedef uint32_t uint32;
 typedef int16_t int16;
 typedef uint16_t uint16;
 typedef uint8_t uint8;
 #ifdef HAVE_NATIVE_INT64
  typedef int64_t int64;
  typedef uint64_t uint64;
 #endif
#elif defined(WIN32)
 #include <windows.h>
 #define strcasecmp lstrcmpiA
 #define snprintf _snprintf
 typedef signed long int32;
 typedef unsigned long uint32;
 typedef signed short int16;
 typedef unsigned short uint16;
 typedef unsigned char uint8;
 #ifdef HAVE_NATIVE_INT64
  typedef unsigned long long	uint64;
  typedef signed long long	int64;
 #endif
#elif defined(METAL)
 typedef signed long int32;
 typedef unsigned long uint32;
 typedef signed short int16;
 typedef unsigned short uint16;
 #ifdef HAVE_NATIVE_INT64
  typedef unsigned long long	uint64;
  typedef signed long long	int64;
 #endif
#elif defined(SOTER)
 typedef signed long int32;
 typedef unsigned long uint32;
 typedef signed short int16;
 typedef unsigned short uint16;
 #ifdef HAVE_NATIVE_INT64
  typedef unsigned long long uint64;
  typedef signed long long	int64;
 #endif
#endif

/******************************************************************************/
/*
	Secure memset
*/
#if defined(WIN32)
 #undef memset_s
 #define memset_s(A,B,C,D) SecureZeroMemory(A,D)
#elif defined(OSX)
 #define __STDC_WANT_LIB_EXT1__ 1
 #include <string.h>
#else
 #include <string.h>
 typedef size_t rsize_t;
 typedef int errno_t;
 extern errno_t memset_s(void *s, rsize_t smax, int c, rsize_t n);
#endif

/******************************************************************************/
/*
	Hardware Abstraction Layer
*/
/* Hardware Abstraction Layer - define functions in HAL directory */
#if defined(POSIX) || defined(WIN32) || defined(ECOS) || defined(FREERTOS) || defined(SOTER)
 #define halOpen() 0
 #define halClose()
 #define halAlert()
#else
 extern int		halOpen(void);
 extern void	halAlert(void);
 extern void	halClose(void);
#endif /* HAL */

/******************************************************************************/
/*
	OS-specific psTime_t types

	Make psTime_t an opaque time value.
*/

/* #define USE_HIGHRES_TIME */

#if defined(POSIX)
 #ifndef USE_HIGHRES_TIME
  #include <sys/time.h>
  #include <time.h>
  typedef struct timeval psTime_t;
 #else
  #if defined(__APPLE__) || defined(__tile__)
   typedef uint64_t psTime_t;
  #else
   typedef struct timespec psTime_t;
  #endif
  extern int64_t psDiffUsecs(psTime_t then, psTime_t now);
 #endif
#elif defined(WIN32)
 typedef LARGE_INTEGER psTime_t;
#elif defined(METAL)
 typedef unsigned int psTime_t;
#elif defined(VXWORKS)
 typedef struct {
	long sec;
	long usec;
 } psTime_t;
#elif defined(SOTER)
 #include <sys/time.h>
 #include <time.h>
 typedef struct timeval psTime_t;
#endif

/******************************************************************************/
/*
	Raw trace and error
*/
PSPUBLIC void _psTrace(char *msg);
PSPUBLIC void _psTraceInt(char *msg, int32 val);
PSPUBLIC void _psTraceStr(char *msg, char *val);
PSPUBLIC void _psTracePtr(char *message, void *value);
PSPUBLIC void psTraceBytes(char *tag, unsigned char *p, int l);

PSPUBLIC void _psError(char *msg);
PSPUBLIC void _psErrorInt(char *msg, int32 val);
PSPUBLIC void _psErrorStr(char *msg, char *val);

/******************************************************************************/
/*
	Core trace
*/
#ifndef USE_CORE_TRACE
 #define psTraceCore(x)
 #define psTraceStrCore(x, y)
 #define psTraceIntCore(x, y)
 #define psTracePtrCore(x, y)
#else
 #define psTraceCore(x) _psTrace(x)
 #define psTraceStrCore(x, y) _psTraceStr(x, y)
 #define psTraceIntCore(x, y) _psTraceInt(x, y)
 #define psTracePtrCore(x, y) _psTracePtr(x, y)
#endif /* USE_CORE_TRACE */

/******************************************************************************/
/*
	HALT_ON_PS_ERROR define at compile-time determines whether to halt on
	psAssert and psError calls
*/
#define psAssert(C)  if (C) ; else \
 {halAlert();_psTraceStr("psAssert %s", __FILE__);_psTraceInt(":%d ", __LINE__);\
 _psError(#C);}

#define psError(a) \
 halAlert();_psTraceStr("psError %s", __FILE__);_psTraceInt(":%d ", __LINE__); \
 _psError(a);

#define psErrorStr(a,b) \
 halAlert();_psTraceStr("psError %s", __FILE__);_psTraceInt(":%d ", __LINE__); \
 _psErrorStr(a,b)

#define psErrorInt(a,b) \
 halAlert();_psTraceStr("psError %s", __FILE__);_psTraceInt(":%d ", __LINE__); \
 _psErrorInt(a,b)

/******************************************************************************/
/*
	OS specific file system apis
*/
#ifdef MATRIX_USE_FILE_SYSTEM
 #ifdef POSIX
  #include <sys/stat.h>
 #endif /* POSIX */
#endif /* MATRIX_USE_FILE_SYSTEM */

/******************************************************************************/
/*
	Defines to make library multithreading safe
*/
#ifdef USE_MULTITHREADING

extern int32 osdepMutexOpen(void);
extern int32 osdepMutexClose(void);

#if defined(WIN32)
 typedef CRITICAL_SECTION psMutex_t;
#elif defined(POSIX)
 #include <string.h>
 #include <pthread.h>
 typedef pthread_mutex_t psMutex_t;
#elif defined(VXWORKS)
 #include "semLib.h"
 typedef SEM_ID	psMutex_t;
#elif defined(SOTER)
 #include <semaphore.h>
 typedef sem_t	psMutex_t;
#else
 #error psMutex_t must be defined
#endif /* OS specific mutex */

#endif /* USE_MULTITHREADING */

/******************************************************************************/

#endif /* !PS_UNSUPPORTED_OS */

/********************************** Defines ***********************************/
/*
*	Fast circular doubly-linked list and branchless macro-functions.
*	Provides a struct-independent way to have a small head and hang a list
*	of structs off of it. Examples of use:
*
*	typedef struct {
*		int bar;
*		DLListEntry List;
*	} foo;
*
*  Define foo list head:
*      DLListEntry FooListHead;
*
*  Init for list head:
*      DLListInit(&FooListHead);
*
*	Define and init list head:
*		DEFINE_DLLIST(FooListHead);
*			or
*		static DEFINE_DLLIST(FooListHead);
*
*  Insert *pMyFoo after the head:
*      foo *pMyFoo;
*      pMyFoo = malloc(sizeof(foo));
*      DLListInsertHead(&FooListHead, &pMyFoo->List);
*
*  Do the same but place at tail:
*      DLListInsertTail(&FooListHead, &pMyFoo->List);
*
*  Given a foo that you know is in a list, detach it from the list:
*      DLListRemove(&pMyFoo->List);
*
*  Detach and return the list entry for the head item:
*      DLListEntry *pList;
*      pList = DLListGetHead(&FooListHead);
*      pMyFoo = DLListGetContainer(pList, foo, List);
*
*  Iterate the entire list:
*      DLListEntry *pList;
*      pList = FooListHead.pNext;
*      while (pList != &FooListHead) {
*          pCurFoo = DLListGetContainer(pList, foo, List);
*          ... (do something with the current foo)
*          pList = pList->pNext;
*      }
*
*  Iterate the entire list, removing each item (e.g. on all-list destruction):
*      DLListEntry *pList;
*      while (!DLListIsEmpty(&FooListHead)) {
*          pList = DLListGetHead(&FooListHead);
*          pMyFoo = DLListGetContainer(pList, foo, List);
*          DestroyFoo(pMyFoo);
*          free(pMyFoo);
*      }
*/
typedef struct _DLListEntry {
struct _DLListEntry *pNext, *pPrev;
} DLListEntry;

#define DEFINE_DLLIST(x) DLListEntry x = { .pNext = &x, .pPrev = &x };

#define DLListInit(__pList)  \
(__pList)->pNext = (__pList)->pPrev = (__pList)

/* Inserts an item as the first item of the list */
#define DLListInsertHead(__pHead, __pNode) {  \
psAssert((__pHead) != (__pNode));  \
(__pNode)->pNext = (__pHead)->pNext;  \
(__pNode)->pPrev = (__pHead);  \
(__pHead)->pNext->pPrev = (__pNode);  \
(__pHead)->pNext = (__pNode);  \
}

/* Inserts an item as the last in the list */
#define DLListInsertTail(__pHead, __pNode) {  \
psAssert((__pHead) != (__pNode));  \
(__pNode)->pNext = (__pHead);  \
(__pNode)->pPrev = (__pHead)->pPrev;  \
(__pHead)->pPrev->pNext = (__pNode);  \
(__pHead)->pPrev = (__pNode);  \
}

/* Detaches node from current position in the list. */
#define DLListRemove(__pNode) {  \
(__pNode)->pNext->pPrev = (__pNode)->pPrev;  \
(__pNode)->pPrev->pNext = (__pNode)->pNext;  \
}

#define DLListIsEmpty(__pHead) ((__pHead)->pNext == (__pHead))

/*
Gets the pointer to the containing object given the DLList pointer,
the type name of the struct, and the name of the DLList field within
the struct.
*/
#define DLListGetContainer(__pDLList, __ContainerType, __DLListFieldName)  \
((__ContainerType *)((char *)(__pDLList) -  \
(long)(&((__ContainerType *)0)->__DLListFieldName)))

/*
Detaches first list item after the head and returns a pointer to it.
List must not be empty.
*/
#define DLListGetHead(__pHead)  \
(__pHead)->pNext;  \
(__pHead)->pNext->pNext->pPrev = (__pHead);  \
(__pHead)->pNext = (__pHead)->pNext->pNext;

/*
Detaches list list item before the head and returns a pointer to it.
List must not be empty.
*/
#define DLListGetTail(__pHead)  \
(__pHead)->pPrev;  \
(__pHead)->pPrev->pPrev->pNext = (__pHead);  \
(__pHead)->pPrev = (__pHead)->pPrev->pPrev;

/******************************************************************************/
/*
Simpler, single linked list
*/
typedef struct psList {
unsigned char	*item;
uint32			len;
struct psList	*next;
} psList_t;

/******************************************************************************/
/*
*/
#ifdef PS_UNSUPPORTED_OS
#include "matrixos.h"
#else
/******************************************************************************/
/*
*/

#include <string.h> /* memset, memcpy */

#define MATRIX_NO_POOL		(void *)0x0

/******************************************************************************/
/*
Native memory routines
*/
#include <stdlib.h> 		/* malloc, free, etc... */

#define MAX_MEMORY_USAGE	0
#define psOpenMalloc()		0
#define psCloseMalloc()
#define psDefineHeap(A, B)
#define psAddPoolCache(A, B)
#define psMalloc(A, B)		malloc(B)
#define psCalloc(A, B, C)	calloc(B, C)
#define psMallocNoPool		malloc
#define psRealloc(A, B, C)	realloc(A, B)
#define psFree(A, B)		free(A)
#define psMemset			memset
#define psMemcpy			memcpy

typedef int32 psPool_t;

/******************************************************************************/

#endif /* !PS_UNSUPPORTED_OS */

/******************************************************************************/
/*
psCore return codes
*/
#define PS_CORE_IS_OPEN		1

/******************************************************************************/
/*
Universal return codes
*/
#define PS_SUCCESS			0
#define PS_FAILURE			-1

/*	NOTE: Failure return codes MUST be < 0 */
/*	NOTE: The range for core error codes should be between -2 and -29 */
#define PS_ARG_FAIL			-6	/* Failure due to bad function param */
#define PS_PLATFORM_FAIL	-7	/* Failure as a result of system call error */
#define PS_MEM_FAIL			-8	/* Failure to allocate requested memory */
#define PS_LIMIT_FAIL		-9	/* Failure on sanity/limit tests */
#define PS_UNSUPPORTED_FAIL	-10 /* Unimplemented feature error */
#define PS_DISABLED_FEATURE_FAIL -11 /* Incorrect #define toggle for feature */
#define PS_PROTOCOL_FAIL	-12 /* A protocol error occurred */
#define PS_TIMEOUT_FAIL		-13 /* A timeout occurred and MAY be an error */
#define PS_INTERRUPT_FAIL	-14 /* An interrupt occurred and MAY be an error */
#define PS_PENDING			-15 /* In process. Not necessarily an error */
#define PS_EAGAIN			-16 /* Try again later. Not necessarily an error */

#define	PS_TRUE		1
#define	PS_FALSE 	0

/******************************************************************************/
/* Public structures */
/******************************************************************************/
/*
psBuf_t
Empty buffer:
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
|.|.|.|.|.|.|.|.|.|.|.|.|.|.|.|.|
 ^
 \end
 \start
 \buf
 size = 16
 len = (end - start) = 0

Buffer with data:

 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
|.|.|a|b|c|d|e|f|g|h|i|j|.|.|.|.|
 ^   ^                   ^
 |   |                   \end
 |   \start
 \buf
size = 16
len = (end - start) = 10

Read from start pointer
Write to end pointer
Free from buf pointer
*/
typedef struct {
unsigned char	*buf;	/* Pointer to the start of the buffer */
unsigned char	*start;	/* Pointer to start of valid data */
unsigned char	*end;	/* Pointer to first byte of invalid data */
int32			size;	/* Size of buffer in bytes */
} psBuf_t;

/******************************************************************************/

#ifdef USE_FILESYSTEM
#define FILESYSTEM_CONFIG_STR "Y"
#else
#define FILESYSTEM_CONFIG_STR "N"
#endif

#define PSMALLOC_CONFIG_STR "N"

#ifdef USE_MULTITHREADING
#define MULTITHREAD_CONFIG_STR "Y"
#else
#define MULTITHREAD_CONFIG_STR "N"
#endif

#define PSCORE_CONFIG \
"Y" \
FILESYSTEM_CONFIG_STR \
PSMALLOC_CONFIG_STR \
MULTITHREAD_CONFIG_STR

/******************************************************************************/
/* Public APIs */
/******************************************************************************/

PSPUBLIC int32		psCoreOpen(char *config);
PSPUBLIC void		psCoreClose(void);
PSPUBLIC void		psBurnStack(uint32 len);
PSPUBLIC int32		memcmpct(const void *s1, const void *s2, size_t len);


/******************************************************************************/
/*
Public interface to OS-dependant core functionality

OS/osdep.c must implement the below functions
*/
PSPUBLIC int32		psGetEntropy(unsigned char *bytes, uint32 size,
					void *userPtr);

PSPUBLIC int32		psGetTime(psTime_t *t, void *userPtr);
PSPUBLIC int32		psDiffMsecs(psTime_t then, psTime_t now, void *userPtr);

/* psCompareTime is no longer used */
PSPUBLIC int32		psCompareTime(psTime_t a, psTime_t b, void *userPtr);

#ifdef MATRIX_USE_FILE_SYSTEM
PSPUBLIC int32		psGetFileBuf(psPool_t *pool, const char *fileName,
							 unsigned char **buf, int32 *bufLen);
#endif /* MATRIX_USE_FILE_SYSTEM */

#ifdef USE_MULTITHREADING
PSPUBLIC int32		psCreateMutex(psMutex_t *mutex);
PSPUBLIC int32		psLockMutex(psMutex_t *mutex);
PSPUBLIC int32		psUnlockMutex(psMutex_t *mutex);
PSPUBLIC void		psDestroyMutex(psMutex_t *mutex);
#endif /* USE_MULTITHREADING */

/******************************************************************************/
/*
Internal list helpers
*/
extern int32 psParseList(psPool_t *pool, char *list, const char separator,
			psList_t **items);
extern void psFreeList(psList_t *list, psPool_t *pool);


/******************************************************************************/
//
//
//
//
/******************************************************************************/
/* Configurable features */
/******************************************************************************/
/*
Enable psTraceCrypto family of APIs for debugging the crypto module
*/
#define USE_CRYPTO_TRACE

/******************************************************************************/
/*
Public-Key Algorithms and performance settings
*/
#define USE_RSA /* Enable/Disable RSA */
#define USE_NATIVE_RSA /* Default built-in software support */
#define USE_ECC 	/* Enable/Disable ECC */
#define USE_DH	/* Enable Diffie-Hellman */
#define USE_DSA /* Enable Digital Signature Algorithm */

/*
Optimize public/private kay operations speed or smaller ram usage.
Only one may be defined.
The speed gain for optimizing for speed is around 5%
The memory savings for optimizing for ram is around 50%
By default below, these will be enabled on an optimized build that is
	not optimized for size. Eg. for -O[1-3,fast], but not for -Os
*/
#if defined(__OPTIMIZE__)
#if defined(__OPTIMIZE_SIZE__)
#define PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM
#else
#define PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED
#endif /* OPTIMIZE_SIZE */
#endif /* OPTIMIZE */

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
/******************************************************************************/
/*
Symmetric bock ciphers (including CBC mode) and performance settings
*/
#define USE_AES /* Enable/Disable AES */
#define USE_AES_CTR /* Counter Mode.  USE_AES must be enabled */
/* #define USE_AES_GCM */ /* Galois Counter Mode.  USE_AES must be enabled */
/* #define USE_AES_XTS */ /* XEX-based tweaked-code_book mode.  USE_AES must be enabled */

/* This is defined if the -maes compiler flag us used on Intel platforms */
#ifdef __AES__
#define USE_AES_CBC_EXTERNAL
#define USE_AES_CTR_EXTERNAL
#define USE_AES_GCM_EXTERNAL
#define USE_AES_XTS_EXTERNAL
#define USE_AESNI_CRYPTO
#endif

#define USE_3DES
#define USE_DES
/* #define USE_SEED */
/* #define USE_IDEA */

/*
Improve block cipher performance, but produce larger code.
Platforms vary, but ciphers will generally see a 5%-10% performance
	boost at the cost of 10-20 kilobytes (per algorithm).
By default below, these will be enabled on an optimized build that is
	not optimized for size. Eg. for -O[1-3,fast], but not for -Os
*/
#if defined(__OPTIMIZE__) && !defined(__OPTIMIZE_SIZE__)
#define PS_AES_IMPROVE_PERF_INCREASE_CODESIZE
#define PS_3DES_IMPROVE_PERF_INCREASE_CODESIZE
#endif /* OPTIMIZE */

/******************************************************************************/
/*
Symmetric stream ciphers
@security These are generally deemed insecure and not enabled by default.
*/
/* #define USE_ARC4 */
/* #define USE_RC2 */ /* Only PKCS#12 parse should ever want this algorithm */

/******************************************************************************/
/*
Digest algorithms
@note SHA256 and above are used with TLS 1.2, and also used for
certificate signatures on some certificates regardless of TLS version.
@security MD5 is deprecated, but still required in combination with SHA-1
for TLS handshakes before TLS 1.2, meaning that the strength is at least
that of SHA-1 in this usage. The only other usage of MD5 by TLS is for
certificate signatures and MD5 based cipher suites. Both of which are
disabled at compile time by default.
*/
#define USE_SHA1
#define USE_SM3
#define USE_MD5				/* Required for < TLS 1.2 Handshake */
#define USE_SHA224			/* Must enable SHA256 to use */
#define USE_SHA256			/* Required for >= TLS 1.2 */
#define USE_SHA384			/* Must enable SHA512 to use */
#define USE_SHA512
/* #define USE_MD2 */		/* @security INSECURE */
/* #define USE_MD4 */ 		/* @security INSECURE */

#define USE_HMAC /* Requires USE_MD5 and/or USE_SHA1 */
#define USE_CMAC /* Requires USE_AES */
#define USE_CBCMAC /* Requires USE_AES, USE_DES and/or USE_3DES */

/*
Improve hashing performance, but produce larger code.
Platforms vary, but digests will generally see a 5%-10% performance
	boost at the cost of 1-10 kilobytes (per algorithm).
By default below, these will be enabled on an optimized build that is
	not optimized for size. Eg. for -O[1-3,fast], but not for -Os
*/
#if defined(__OPTIMIZE__) && !defined(__OPTIMIZE_SIZE__)
#define PS_MD5_IMPROVE_PERF_INCREASE_CODESIZE
#define PS_SHA1_IMPROVE_PERF_INCREASE_CODESIZE
#endif /* OPTIMIZE */

/******************************************************************************/
/*
X.509 Certificate and DH Params
*/
#define USE_X509
/* #define ENABLE_MD5_SIGNED_CERTS */ /* Accept MD5 signed certs if enabled */
#define USE_CERT_PARSE /* Usually required.  USE_X509 must be enabled */
#define USE_FULL_CERT_PARSE /* USE_CERT_PARSE must be enabled */
/* #define USE_CRL */ /* Must define USE_FULL_CERT_PARSE */
#define USE_BASE64_DECODE

/******************************************************************************/
/*
Minimum supported key sizes in bits.
@security Weaker keys will be rejected.
*/
#define MIN_RSA_BITS	1024
#define MIN_ECC_BITS	192
#define MIN_DH_BITS		1024

/******************************************************************************/
/*
PKCS support
*/
#define USE_PRIVATE_KEY_PARSING
#define USE_PKCS5		/* v2.0 PBKDF encrypted priv keys, reqs USE_3DES */
#define USE_PKCS8		/* Alternative private key storage format */
#define USE_PKCS12	/* Requires USE_PKCS8 */

/******************************************************************************/
/*
PRNG Algorithms
@security By default the OS PRNG will be used directly.
*/
#define USE_YARROW

/******************************************************************************/
/*
All below here are configurable tweaks (do not need to touch, in general)
*/
/*
USE_1024_KEY_SPEED_OPTIMIZATIONS
USE_2048_KEY_SPEED_OPTIMIZATIONS
Optimizations for 1024/2048 bit key size multiplication and squaring math.
The library size can increase significantly if enabled
By default below, these will be enabled on an optimized build that is
	not optimized for size. Eg. for -O[1-3,fast], but not for -Os
*/
#if defined(__OPTIMIZE__) && !defined(__OPTIMIZE_SIZE__)
#define USE_1024_KEY_SPEED_OPTIMIZATIONS
#define USE_2048_KEY_SPEED_OPTIMIZATIONS
#endif /* OPTIMIZE */

/* @security Zero the stack of functions operating on secret data */
/* #define USE_BURN_STACK */


#ifdef USE_PKCS11
#include "cryptoki.h" /* #include "pkcs11.h" */
#endif
#ifdef USE_AESNI_CRYPTO
#include "hardware/aesni.h"
#endif

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

#ifdef USE_AES_CTR_EXTERNAL
	unsigned int	UsedBlockNumber;
	unsigned char	EncryptedCount[16];
#endif
} psAesCipher_t;

#endif /* USE_AES */

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


#ifndef DISABLE_PSTM

/* Define this here to avoid including circular limits.h on some platforms */
#ifndef CHAR_BIT
#define CHAR_BIT	8
#endif

/******************************************************************************/
/*
	If native 64 bit integers are not supported, we do not support 32x32->64
	in hardware, so we must set the 16 bit flag to produce 16x16->32 products.
*/
#ifndef HAVE_NATIVE_INT64
	#define PSTM_16BIT
#endif /* ! HAVE_NATIVE_INT64 */

/******************************************************************************/
/*
	Some default configurations.

	pstm_word should be the largest value the processor can hold as the product
		of a multiplication. Most platforms support a 32x32->64 MAC instruction,
		so 64bits is the default pstm_word size.
	pstm_digit should be half the size of pstm_word
 */
#ifdef PSTM_8BIT
/*	8-bit digits, 16-bit word products */
	typedef unsigned char		pstm_digit;
	typedef unsigned short		pstm_word;
	#define DIGIT_BIT			8

#elif defined(PSTM_16BIT)
/*	16-bit digits, 32-bit word products */
	typedef unsigned short		pstm_digit;
	typedef unsigned long		pstm_word;
	#define	DIGIT_BIT			16

#elif defined(PSTM_64BIT)
/*	64-bit digits, 128-bit word products */
	#ifndef __GNUC__
	#error "64bit digits requires GCC"
	#endif
	typedef unsigned long		pstm_digit;
	typedef unsigned long		pstm_word __attribute__ ((mode(TI)));
	#define DIGIT_BIT			64

#else
/*	This is the default case, 32-bit digits, 64-bit word products */
	typedef uint32			pstm_digit;
	typedef uint64			pstm_word;
	#define DIGIT_BIT		32
	#define PSTM_32BIT
#endif /* digit and word size */

#define PSTM_MASK			(pstm_digit)(-1)
#define PSTM_DIGIT_MAX		PSTM_MASK

/******************************************************************************/
/*
	equalities
 */
#define PSTM_LT			-1		/* less than */
#define PSTM_EQ			0		/* equal to */
#define PSTM_GT			1		/* greater than */

#define PSTM_ZPOS		0		/* positive integer */
#define PSTM_NEG		1		/* negative */

#define PSTM_OKAY		PS_SUCCESS
#define PSTM_MEM		PS_MEM_FAIL

/******************************************************************************/
/*
	Various build options
 */
#define PSTM_DEFAULT_INIT 64		/* default (64) digits of allocation */
#define PSTM_MAX_SIZE	4096

typedef struct  {
	int16	used, alloc, sign;
	pstm_digit	*dp;
	psPool_t	*pool;
} pstm_int;

/******************************************************************************/
/*
	Operations on large integers
 */
#define pstm_iszero(a) (((a)->used == 0) ? PS_TRUE : PS_FALSE)
#define pstm_iseven(a) (((a)->used > 0 && (((a)->dp[0] & 1) == 0)) ? PS_TRUE : PS_FALSE)
#define pstm_isodd(a)  (((a)->used > 0 && (((a)->dp[0] & 1) == 1)) ? PS_TRUE : PS_FALSE)
#define pstm_abs(a, b)  { pstm_copy(a, b); (b)->sign  = 0; }

extern void pstm_set(pstm_int *a, pstm_digit b);

extern void pstm_zero(pstm_int * a);

extern int32 pstm_init(psPool_t *pool, pstm_int * a);

extern int32 pstm_init_size(psPool_t *pool, pstm_int * a, uint32 size);

extern int32 pstm_init_copy(psPool_t *pool, pstm_int * a, pstm_int * b,
				int16 toSqr);

extern int16 pstm_count_bits (pstm_int * a);

extern int32 pstm_init_for_read_unsigned_bin(psPool_t *pool, pstm_int *a,
				uint32 len);

extern int32 pstm_read_unsigned_bin(pstm_int *a, unsigned char *b, int32 c);

extern int32 pstm_unsigned_bin_size(pstm_int *a);

extern int32 pstm_copy(pstm_int * a, pstm_int * b);

extern void pstm_exch(pstm_int * a, pstm_int * b);

extern void pstm_clear(pstm_int * a);

extern void pstm_clear_multi(pstm_int *mp0, pstm_int *mp1, pstm_int *mp2,
				pstm_int *mp3, pstm_int *mp4, pstm_int *mp5, pstm_int *mp6,
				pstm_int *mp7);

extern int32 pstm_grow(pstm_int * a, int16 size);

extern void pstm_clamp(pstm_int * a);

extern int32 pstm_cmp(pstm_int * a, pstm_int * b);

extern int32 pstm_cmp_mag(pstm_int * a, pstm_int * b);

extern void pstm_rshd(pstm_int *a, int16 x);

extern int32 pstm_lshd(pstm_int * a, int16 b);

extern int32 pstm_div(psPool_t *pool, pstm_int *a, pstm_int *b, pstm_int *c,
				pstm_int *d);

extern int32 pstm_div_2d(psPool_t *pool, pstm_int *a, int16 b, pstm_int *c,
				pstm_int *d);

extern int32 pstm_div_2(pstm_int * a, pstm_int * b);

extern int32 s_pstm_sub(pstm_int *a, pstm_int *b, pstm_int *c);

extern int32 pstm_sub(pstm_int *a, pstm_int *b, pstm_int *c);

extern int32 pstm_sub_d(psPool_t *pool, pstm_int *a, pstm_digit b, pstm_int *c);

extern int32 pstm_mul_2(pstm_int * a, pstm_int * b);

extern int32 pstm_mod(psPool_t *pool, pstm_int *a, pstm_int *b, pstm_int *c);

extern int32 pstm_mulmod(psPool_t *pool, pstm_int *a, pstm_int *b, pstm_int *c,
				pstm_int *d);

extern int32 pstm_exptmod(psPool_t *pool, pstm_int *G, pstm_int *X, pstm_int *P,
				pstm_int *Y);

extern int32 pstm_2expt(pstm_int *a, int16 b);

extern int32 pstm_add(pstm_int *a, pstm_int *b, pstm_int *c);

extern int32 pstm_to_unsigned_bin(psPool_t *pool, pstm_int *a,
				unsigned char *b);

extern int32 pstm_to_unsigned_bin_nr(psPool_t *pool, pstm_int *a,
				unsigned char *b);

extern int32 pstm_montgomery_setup(pstm_int *a, pstm_digit *rho);

extern int32 pstm_montgomery_reduce(psPool_t *pool, pstm_int *a, pstm_int *m,
				pstm_digit mp, pstm_digit *paD, uint32 paDlen);

extern int32 pstm_mul_comba(psPool_t *pool, pstm_int *A, pstm_int *B,
				pstm_int *C, pstm_digit *paD, uint32 paDlen);

extern int32 pstm_sqr_comba(psPool_t *pool, pstm_int *A, pstm_int *B,
				pstm_digit *paD, uint32 paDlen);

extern int32 pstm_cmp_d(pstm_int *a, pstm_digit b);

extern int32 pstm_montgomery_calc_normalization(pstm_int *a, pstm_int *b);

extern int32 pstm_mul_d(pstm_int *a, pstm_digit b, pstm_int *c);

extern int32 pstm_invmod(psPool_t *pool, pstm_int * a, pstm_int * b,
				pstm_int * c);

extern int32 pstm_copy_unsigned_bin(pstm_int *a, unsigned char *b, int32 c);

#else /* DISABLE_PSTM */
	typedef int32 pstm_int;
#endif /* !DISABLE_PSTM */

/******************************************************************************/
/*
	Configuration checks
*/
#ifdef USE_CERT_PARSE
	#ifndef USE_X509
	#error "Must enable USE_X509 if USE_CERT_PARSE is enabled"
	#endif
	#if !defined(USE_MD5) || !defined(USE_SHA1)
	#error "Both USE_MD5 and USE_SHA1 must be enabled when enabling USE_X509"
	#endif
#endif

#ifdef USE_HMAC
	#if !defined(USE_SHA1) && !defined(USE_SHA256) && !defined(USE_SHA384)
	#error "Must enable a SHA based hash in cryptoConfig.h for HMAC support"
	#endif
#endif

#ifdef USE_PKCS5
	#ifndef USE_MD5
	#error "Enable USE_MD5 in cryptoConfig.h for PKCS5 support"
	#endif
	#ifndef USE_3DES
	#error "Enable USE_3DES in cryptoConfig.h for PKCS5 support"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for PKCS5 support"
	#endif
#endif

#ifdef USE_PKCS8
	#ifndef USE_HMAC
	#error "Enable USE_HMAC in cryptoConfig.h for PKCS8 support"
	#endif
#endif

#ifdef USE_PKCS11
	#ifdef USE_RSA
	#error "Currently no RSA support for PKCS#11 builds.  Disable USE_RSA"
	#endif
	#define USE_UNIFIED_PKCS11 /* TLS integration is mandatory right now */
	#define USE_PKCS11_ECC
	#define USE_PKCS11_AES
	#define USE_PKCS11_HASH
#else
	#define USE_NATIVE_ECC
	#define USE_NATIVE_AES
	#define USE_NATIVE_HASH
#endif

#ifdef USE_PKCS12
	#ifndef USE_PKCS8
	#error "Enable USE_PKCS8 in cryptoConfig.h for PKCS12 support"
	#endif
#endif

/******************************************************************************/

#define SHA1_HASH_SIZE 20
#ifdef USE_SHA1
struct sha1_state {
#ifdef HAVE_NATIVE_INT64
	uint64		length;
#else
	uint32		lengthHi;
	uint32		lengthLo;
#endif /* HAVE_NATIVE_INT64 */
	uint32		state[5], curlen;
	unsigned char	buf[64];
};
#endif /* USE_SHA1 */

#define SHA256_HASH_SIZE 32
#ifdef USE_SHA256
struct sha256_state {
#ifdef HAVE_NATIVE_INT64
	uint64		length;
#else
	uint32		lengthHi;
	uint32		lengthLo;
#endif /* HAVE_NATIVE_INT64 */
	uint32		state[8], curlen;
	unsigned char buf[64];
};
#endif /* USE_SHA256 */

#define SM3_HASH_SIZE 32
#ifdef USE_SM3
struct sm3_state {
	unsigned int total[2];     /* data length counted by bytes */
	unsigned int iter_V[8];    /* the iterated intermediate value of the compression function */
	unsigned char buffer[64];  /* data block being processed */
};
#endif /* USE_SM3 */

#define MD5_HASH_SIZE 16
#ifdef USE_MD5
struct md5_state {
#ifdef HAVE_NATIVE_INT64
	uint64 length;
#else
	uint32 lengthHi;
	uint32 lengthLo;
#endif /* HAVE_NATIVE_INT64 */
	uint32 state[4], curlen;
	unsigned char buf[64];
};
#endif /* USE_MD5 */

#ifdef USE_MD4
struct md4_state {
#ifdef HAVE_NATIVE_INT64
	uint64 length;
#else
	uint32 lengthHi;
	uint32 lengthLo;
#endif /* HAVE_NATIVE_INT64 */
	uint32 state[4], curlen;
	unsigned char buf[64];
};
#endif /* USE_MD4 */

#ifdef USE_MD2
struct md2_state {
	unsigned char	chksum[16], X[48], buf[16];
	uint32			curlen;
};
#endif /* USE_MD2 */

#define SHA224_HASH_SIZE 28
#ifdef USE_SHA224
#ifndef USE_SHA256
#error "Must enable USE_SHA256 in cryptoConig.h if USE_SHA224 is enabled"
#endif
#endif /* USE_SHA224 */

#define SHA512_HASH_SIZE 64
#ifdef USE_SHA512
#ifndef HAVE_NATIVE_INT64
#error "Must enable HAVE_NATIVE_INT64 in coreConig.h if USE_SHA512 is enabled"
#endif
struct sha512_state {
	uint64  length, state[8];
	unsigned long curlen;
	unsigned char buf[128];
};
#endif

#define SHA384_HASH_SIZE 48
#ifdef USE_SHA384
#ifndef USE_SHA512
#error "Must enable USE_SHA512 in cryptoConig.h if USE_SHA384 is enabled"
#endif
#endif /* USE_SHA384 */


#ifdef USE_SHA512
	#define MAX_HASH_SIZE SHA512_HASH_SIZE /* SHA384 depends on SHA512 */
#else
	#ifdef USE_SHA256
		#define MAX_HASH_SIZE SHA256_HASH_SIZE
	#else
		#define MAX_HASH_SIZE SHA1_HASH_SIZE
	#endif
#endif

/******************************************************************************/
typedef union {
#ifndef USE_PKCS11_HASH
#ifdef USE_SHA1
	struct sha1_state	sha1;
#endif /* USE_SHA1 */

#ifdef USE_SM3
	struct sm3_state	sm3;
#endif

#ifdef USE_MD5
	struct md5_state	md5;
#endif /* USE_MD5 */

#ifdef USE_MD2
	struct md2_state	md2;
#endif /* USE_MD2 */

#ifdef USE_MD4
	struct md4_state	md4;
#endif /* USE_MD4 */

#ifdef USE_SHA256 /* SHA224 uses */
	struct sha256_state sha256;
#endif

#ifdef USE_SHA512 /* SHA384 uses */
	struct sha512_state sha512;
#endif

#else /* USE_PKCS11_HASH  */
	CK_SESSION_HANDLE   sess;
#ifdef USE_MD5
	struct md5_state	md5; /* X.509 helper functionality */
#endif /* USE_MD5 */
#endif /* USE_PKCS11_HASH */

} psDigestContext_t;


extern void sha1_compress(psDigestContext_t *md);
extern void sha256_compress(psDigestContext_t *md, unsigned char *buf);
extern void sha512_compress(psDigestContext_t * md, unsigned char *buf);

/******************************************************************************/
#ifdef USE_HMAC
/******************************************************************************/
typedef struct {
#ifdef USE_SHA384
	unsigned char	pad[128];
#else
	unsigned char	pad[64];
#endif
	union {
		psDigestContext_t	md5;
		psDigestContext_t	sha1;
		psDigestContext_t	sha256;
		psDigestContext_t	sha512;
	} u;
} psHmacContext_t;
#endif /* USE_HMAC */

/******************************************************************************/
#ifdef USE_CMAC
/******************************************************************************/
typedef struct {
	int32         last_len;
	unsigned char last[16];

	/* Keys k1 and k2 */
	unsigned char k1[16];
	unsigned char k2[16];


	union {
		psCipherContext_t	aes;
	} u;
} psCmacContext_t;
#endif /* USE_HMAC */

/******************************************************************************/
#ifdef USE_CBCMAC
/******************************************************************************/
typedef struct {
	int32         last_len;
	unsigned char last[16];

	union {
		psCipherContext_t	aes;
		psCipherContext_t	des;
		psCipherContext_t	des3;
	} u;
} psCbcmacContext_t;
#endif /* USE_CMAC */

#define PUBKEY_TYPE		0x01
#define PRIVKEY_TYPE	0x02

/* Public Key types for psPubKey_t */
#define PS_RSA	1
#define	PS_ECC	2
#define PS_DH	3

/* Sig types */
#define	RSA_TYPE_SIG			5
#define	DSA_TYPE_SIG			6
#define RSAPSS_TYPE_SIG			7

/*
	Pub key speed or size optimization handling
*/
#if defined(PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED) &&	defined(PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM)
#error "May only enable either PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED or PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM"
#endif

#if !defined(PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED) && !defined(PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM)
#define PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM
#endif

#ifdef PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM
#define PS_EXPTMOD_WINSIZE		3
#endif

#ifdef PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED
#define PS_EXPTMOD_WINSIZE		5
#endif

/******************************************************************************/
#ifdef USE_RSA
/******************************************************************************/
/*
	Primary RSA Key struct.  Define here for crypto
*/
typedef struct {
	pstm_int    e, d, N, qP, dP, dQ, p, q;
	uint32      size;   /* Size of the key in bytes */
	int32       optimized; /* 1 for optimized */
	psPool_t *pool;
} psRsaKey_t;


#endif /* USE_RSA */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_ECC
/******************************************************************************/
#define ECC_MAXSIZE	132 /* max private key size */


#define IS_SECP192R1	0x00000001
#define IS_SECP224R1	0x00000002
#define IS_SECP256R1	0x00000004
#define IS_SECP384R1	0x00000008
#define IS_SECP521R1	0x00000010
/* WARNING: Public points on Brainpool curves are not validated */
#define IS_BRAIN224R1	0x00100000
#define IS_BRAIN256R1	0x00200000
#define IS_BRAIN384R1	0x00400000
#define IS_BRAIN512R1	0x00800000


typedef struct {
	int32 size; /* The size of the curve in octets */
	int32 curveId; /* IANA named curve id for TLS use */
	int32 OIDsum; /* Matrix OID */
#ifdef USE_PKCS11_ECC
	CK_BYTE oid[10]; /* OID bytes */
	int		oidLen; /* OID bytes */
#else
	int32 isOptimized; /* 1 if this is an optimized curve with field parameter
							A=-3, zero otherwise. */
#endif
	char *name;  /* name of curve */
	char *prime; /* prime defining the field the curve is in (encoded in hex) */
	char *A; /* The fields A param (hex) */
	char *B; /* The fields B param (hex) */
	char *order; /* The order of the curve (hex) */
	char *Gx; /* The x co-ordinate of the base point on the curve (hex) */
	char *Gy; /* The y co-ordinate of the base point on the curve (hex) */
} psEccSet_t;

/*	A point on a ECC curve, stored in Jacbobian format such that
	 (x,y,z) => (x/z^2, y/z^3, 1) when interpretted as affine
 */
typedef struct {
	psPool_t *pool;
	pstm_int x; /* The x co-ordinate */
	pstm_int y; /* The y co-ordinate */
	pstm_int z;  /* The z co-ordinate */
} psEccPoint_t;

#ifdef USE_NATIVE_ECC
typedef struct {
	psPool_t			*pool;
	int32				type;	/* Type of key, PK_PRIVATE or PK_PUBLIC */
	psEccSet_t			*dp;	/* pointer to domain parameters; */
	psEccPoint_t		pubkey;	/* The public key */
	pstm_int			k;		/* The private key */
} psEccKey_t;

#endif
#ifdef USE_PKCS11_ECC
typedef struct {
	unsigned char		*value;
	int32				valueLen;
} pkcs11EcKey_t;

typedef struct {
	psPool_t			*pool;
	int32				type;	/* Type of key, PK_PRIVATE or PK_PUBLIC */
	psEccSet_t			*dp;	/* pointer to domain parameters; */
	pkcs11EcKey_t		pubkey;
	pkcs11EcKey_t		k;  /* private key */
#ifdef USE_UNIFIED_PKCS11
	CK_SESSION_HANDLE	sess; /* keys stay internal to module */
	CK_OBJECT_HANDLE	obj;
	int32				external; /* Did we create the object? */
#endif
} psEccKey_t;
#endif

extern void	psGetEccCurveIdList(char *curveList, uint32 *len);
extern void userSuppliedEccList(char *curveList, uint32 *len, int32 curves);
extern int32 compiledInEcFlags(void);
extern int32 getEcPubKey(psPool_t *pool, unsigned char **pp, int32 len,
				psEccKey_t *pubKey);

extern int32 getEccParamById(int32 curveId, psEccSet_t **set);
extern int32 getEccParamByName(char *curveName, psEccSet_t **set);
extern int32 getEccParamByOid(int32 oid, psEccSet_t **set);
extern int32 getEccParamBySize(int32 size, psEccSet_t **set);


#endif /* USE_ECC */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_DH
/******************************************************************************/
typedef struct {
	int32	type;
	uint32	size;
	pstm_int	priv, pub;
} psDhKey_t;

typedef struct {
	psPool_t	*pool;
	uint32		size;
	pstm_int	p, g;
} psDhParams_t;

#endif /* USE_DH */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_DSA
/******************************************************************************/
typedef struct {
	int32	type;
	pstm_int	priv, pub;
} psDsaKey_t;

typedef struct {
	psPool_t	*pool;
	pstm_int	p, q, g;
} psDsaParams_t;

typedef struct {
	pstm_int	r, s;
} psDsaSign_t;

#endif /* USE_DSA */
/******************************************************************************/

/******************************************************************************/
/*
	Univeral public key type

	The pubKey name comes from the generic public-key crypto terminology and
	does not mean these key are restricted to the public side only. These
	may be private keys.
*/
/******************************************************************************/

typedef union {
#ifdef USE_RSA
	psRsaKey_t	rsa;
#else
	short		notEmpty; /* Prevents from being empty */
#endif /* USE_RSA */
#ifdef USE_ECC
	psEccKey_t	ecc;
#endif /* USE_ECC */
} pubKeyUnion_t;

typedef struct {
	pubKeyUnion_t	*key;
	uint32			keysize; /* in bytes */
	int32			type; /* PS_RSA, PS_ECC, PS_DH */
	psPool_t		*pool;
} psPubKey_t;


/******************************************************************************/
/*
	Internal helpers
*/
extern int32 pkcs1Pad(unsigned char *in, uint32 inlen, unsigned char *out,
				uint32 outlen, int32 cryptType, void *userPtr);
extern int32 pkcs1Unpad(unsigned char *in, uint32 inlen, unsigned char *out,
				uint32 outlen, int32 decryptType);

#ifdef USE_RSA
extern void psRsaFreeKey(psRsaKey_t *key);
#endif /* USE_RSA */
/******************************************************************************/

/******************************************************************************/
/******************************************************************************/
/*
	8 bit bit masks for ASN.1 tag field
*/
#define ASN_PRIMITIVE			0x0
#define ASN_CONSTRUCTED			0x20

#define ASN_UNIVERSAL			0x0
#define ASN_APPLICATION			0x40
#define ASN_CONTEXT_SPECIFIC	0x80
#define ASN_PRIVATE				0xC0

/*
	ASN.1 primitive data types
*/
enum {
	ASN_BOOLEAN = 1,
	ASN_INTEGER,
	ASN_BIT_STRING,
	ASN_OCTET_STRING,
	ASN_NULL,
	ASN_OID,
	ASN_UTF8STRING = 12,
	ASN_SEQUENCE = 16,
	ASN_SET,
	ASN_PRINTABLESTRING = 19,
	ASN_T61STRING,
	ASN_IA5STRING = 22,
	ASN_UTCTIME,
	ASN_GENERALIZEDTIME,
	ASN_GENERAL_STRING = 27,
	ASN_BMPSTRING = 30
};

#define ASN_UNKNOWN_LEN	16777215

extern int32 getAsnLength(unsigned char **p, uint32 size, uint32 *valLen);
extern int32 getAsnBig(psPool_t *pool, unsigned char **pp, uint32 len,
				pstm_int *big);
extern int32 getAsnSequence(unsigned char **pp, uint32 len, uint32 *seqlen);
extern int32 getAsnSequenceNoLenCheck(unsigned char **pp, uint32 len,
				uint32 *seqlen);
extern int32 getAsnSet(unsigned char **pp, uint32 len, uint32 *setlen);
extern int32 getAsnInteger(unsigned char **pp, uint32 len, int32 *val);

extern int32 getAsnAlgorithmIdentifier(unsigned char **pp, uint32 len,
				int32 *oi, int32 *paramLen);
extern int32 getStreamingAsnAlgorithmIdentifier(unsigned char **pp, uint32 len,
				int32 *oi, int32 *paramLen);
extern int32 getAsnOID(unsigned char **pp, uint32 len, int32 *oi,
				int32 checkForParams, int32 *paramLen);
extern int32 getAsnConstructedOctetString(psPool_t *pool, unsigned char **pp,
				uint32 len, unsigned char **outString, int32 *outStringLen);
#ifdef USE_RSA
extern int32 getAsnRsaPubKey(psPool_t *pool, unsigned char **pp, uint32 len,
				psRsaKey_t *pubKey);
#endif /* USE_RSA */
/******************************************************************************/


/******************************************************************************/
#ifdef USE_X509
/******************************************************************************/

/* ClientCertificateType */
enum {
	RSA_SIGN = 1,
	DSS_SIGN,
	RSA_FIXED_DH,
	DSS_FIXED_DH,
	ECDSA_SIGN = 64,
	RSA_FIXED_ECDH,
	ECDSA_FIXED_ECDH
};

/* Parsing flags */
#define	CERT_STORE_UNPARSED_BUFFER	0x1
#define	CERT_STORE_DN_BUFFER		0x2

#ifdef USE_CERT_PARSE

/* Per specification, any critical extension in an X.509 cert should cause
	the connection to fail. SECURITY - Uncomment at your own risk */
/* #define ALLOW_UNKNOWN_CRITICAL_EXTENSIONS */

/*
	DN attributes are used outside the X509 area for cert requests,
	which have been included in the RSA portions of the code
*/
typedef struct {
	char	*country;
	char	*state;
	char	*locality;
	char	*organization;
	char	*orgUnit;
	char	*commonName;
	char	hash[SHA1_HASH_SIZE];
	char	*dnenc; /* CERT_STORE_DN_BUFFER */
	uint32	dnencLen;
	short	countryType;
	short	countryLen;
	short	stateType;
	short	stateLen;
	short	localityType;
	short	localityLen;
	short	organizationType;
	short	organizationLen;
	short	orgUnitType;
	short	orgUnitLen;
	short	commonNameType;
	short	commonNameLen;
} x509DNattributes_t;

typedef struct {
	int32	cA;
	int32	pathLenConstraint;
} x509extBasicConstraints_t;

typedef struct psGeneralNameEntry {
	psPool_t						*pool;
	enum {
		GN_OTHER = 0,	// OtherName
		GN_EMAIL,		// IA5String
		GN_DNS,			// IA5String
		GN_X400,		// ORAddress
		GN_DIR,			// Name
		GN_EDI,			// EDIPartyName
		GN_URI,			// IA5String
		GN_IP,			// OCTET STRING
		GN_REGID		// OBJECT IDENTIFIER
	}								id;
	unsigned char					name[16];
	unsigned char					oid[32]; /* SubjectAltName OtherName */
	uint32							oidLen;
	unsigned char					*data;
	uint32							dataLen;
	struct psGeneralNameEntry		*next;
} x509GeneralName_t;

typedef struct {
	uint32			len;
	unsigned char	*id;
} x509extSubjectKeyId_t;

typedef struct {
	uint32				keyLen;
	unsigned char		*keyId;
	x509DNattributes_t	attribs;
	uint32				serialNumLen;
	unsigned char		*serialNum;
} x509extAuthKeyId_t;

#ifdef USE_FULL_CERT_PARSE
typedef struct {
	x509GeneralName_t	*permitted;
	x509GeneralName_t	*excluded;
} x509nameConstraints_t;
#endif /* USE_FULL_CERT_PARSE */

/* x509 extension types. Flag logic only works through enum of 31 */
enum {
	EXT_BASIC_CONSTRAINTS = 1,
	EXT_KEY_USAGE,
	EXT_SUBJ_KEY_ID,
	EXT_AUTH_KEY_ID,
	EXT_ALT_SUBJECT_NAME,
	EXT_CRL_DIST_PTS,
	EXT_AUTH_INFO_ACC,
	EXT_NAME_CONSTRAINTS,
	EXT_EXTND_KEY_USAGE
};

/* Make the flag value, given the enum above */
#define EXT_CRIT_FLAG(A) (unsigned int)(1 << (A))

/* Flags for known keyUsage (first byte) */
#define KEY_USAGE_DIGITAL_SIGNATURE		0x0080
#define KEY_USAGE_NON_REPUDIATION		0x0040
#define KEY_USAGE_KEY_ENCIPHERMENT		0x0020
#define KEY_USAGE_DATA_ENCIPHERMENT		0x0010
#define KEY_USAGE_KEY_AGREEMENT			0x0008
#define KEY_USAGE_KEY_CERT_SIGN			0x0004
#define KEY_USAGE_CRL_SIGN				0x0002
#define KEY_USAGE_ENCIPHER_ONLY			0x0001
/* Flags for known keyUsage (second, optional byte) */
#define KEY_USAGE_DECIPHER_ONLY			0x8000

/* Flags for known extendedKeyUsage */
#define EXT_KEY_USAGE_TLS_SERVER_AUTH	(1 << 1)
#define EXT_KEY_USAGE_TLS_CLIENT_AUTH	(1 << 2)
#define EXT_KEY_USAGE_CODE_SIGNING		(1 << 3)
#define EXT_KEY_USAGE_EMAIL_PROTECTION	(1 << 4)
#define EXT_KEY_USAGE_TIME_STAMPING		(1 << 8)
#define EXT_KEY_USAGE_OCSP_SIGNING		(1 << 9)

/* Holds the known extensions we support */
typedef struct {
	psPool_t					*pool;
	x509extBasicConstraints_t	bc;
	x509GeneralName_t			*san;
	uint32						critFlags;		/* EXT_CRIT_FLAG(EXT_KEY_USE) */
	uint32						keyUsageFlags;	/* KEY_USAGE_ */
	uint32						ekuFlags;		/* EXT_KEY_USAGE_ */
	x509extSubjectKeyId_t		sk;
	x509extAuthKeyId_t			ak;
	uint32                      counter;
	unsigned char               tvmName[256];
	uint16                      tvmNameLen;
	unsigned char               uuid[256];
	uint16                      uuidLen;
#ifdef USE_FULL_CERT_PARSE
	x509nameConstraints_t		nameConstraints;
#endif /* USE_FULL_CERT_PARSE */
#ifdef USE_CRL
	x509GeneralName_t			*crlDist;
#endif
} x509v3extensions_t;

#endif /* USE_CERT_PARSE */

#ifdef USE_CRL
typedef struct x509revoked {
	psPool_t			*pool;
	unsigned char		*serial;
	uint32				serialLen;
	struct x509revoked	*next;
} x509revoked_t;
#endif

typedef struct psCert {
	psPool_t			*pool;
#ifdef USE_CERT_PARSE
	int32				version;
	unsigned char		*serialNumber;
	uint32				serialNumberLen;
	x509DNattributes_t	issuer;
	x509DNattributes_t	subject;
	int32				notBeforeTimeType;
	int32				notAfterTimeType;
	char				*notBefore;
	char				*notAfter;
	psPubKey_t			publicKey;
	int32				pubKeyAlgorithm; /* public key algorithm OID */
	int32				certAlgorithm; /* signature algorithm OID */
	int32				sigAlgorithm; /* signature algorithm OID */
#ifdef USE_PKCS1_PSS
	int32				pssHash; /* RSAPSS sig hash OID */
	int32				maskGen; /* RSAPSS maskgen OID */
	int32				maskHash; /* hash OID for MGF1 */
	int32				saltLen; /* RSAPSS salt len param */
#endif
	unsigned char		*signature;
	uint32				signatureLen;
	unsigned char		*uniqueIssuerId;
	uint32				uniqueIssuerIdLen;
	unsigned char		*uniqueSubjectId;
	uint32				uniqueSubjectIdLen;
	x509v3extensions_t	extensions;
	int32				authStatus; /* See psX509AuthenticateCert doc */
	uint32				authFailFlags; /* Flags for extension check failures */
#ifdef USE_CRL
	x509revoked_t		*revoked;
#endif
	unsigned char		sigHash[MAX_HASH_SIZE];
#endif /* USE_CERT_PARSE */
	unsigned char		*unparsedBin; /* see psX509ParseCertFile */
	uint32				binLen;
	struct psCert		*next;
} psX509Cert_t;


#ifdef USE_CERT_PARSE
extern int32 psX509GetSignature(psPool_t *pool, unsigned char **pp, uint32 len,
					unsigned char **sig, uint32 *sigLen);
extern int32 psX509GetDNAttributes(psPool_t *pool, unsigned char **pp,
				uint32 len, x509DNattributes_t *attribs, int32 flags);
extern void psX509FreeDNStruct(x509DNattributes_t *dn, psPool_t *allocPool);
extern int32 getSerialNum(psPool_t *pool, unsigned char **pp, uint32 len,
						unsigned char **sn, uint32 *snLen);
extern int32 getExplicitExtensions(psPool_t *pool, unsigned char **pp,
					uint32 inlen, int32 expVal,	x509v3extensions_t *extensions,
					int32 known);
extern void x509FreeExtensions(x509v3extensions_t *extensions);
extern int psX509ValidateGeneralName(char *n);
#endif /* USE_CERT_PARSE */

#endif /* USE_X509 */
/******************************************************************************/


#ifdef USE_YARROW
/*
	AES SHA-1 implementation
*/
#define CTR_COUNTER_LITTLE_ENDIAN    0x0000
#define CTR_COUNTER_BIG_ENDIAN       0x1000

#define AESBLOCKSIZE 16

typedef struct {
#ifdef USE_SHA256
	unsigned char	pool[SHA256_HASH_SIZE]; /* hash of entropy */
#else
	unsigned char	pool[SHA1_HASH_SIZE]; /* hash of entropy */
#endif
	int32 mode;		/** The mode (endianess) of the CTR, 0==little, 1==big */
	int32 ctrlen;	/** counter width */
	int32 padlen;	/** The padding offset */
	int32 blocklen;	/** The AESBLOCKSIZE */
	unsigned char	ctr[AESBLOCKSIZE];	/** The counter being encrypted */
	unsigned char	pad[AESBLOCKSIZE];	/** The actual prn */
	psAesKey_t		key;				/** The scheduled key */
} psYarrow_t;
#endif /* USE_YARROW */

/*
	prng.c wrapper
*/
#define RANDOM_BYTES_BEFORE_ENTROPY	1024 /* add entropy each time # bytes read */
#define RANDOM_ENTROPY_BYTES		8	/* Bytes of entropy from source */

typedef struct {
#ifdef USE_YARROW
	psYarrow_t	yarrow;
#endif
	uint32		bytecount; /* number of bytes read from this context */
} psRandom_t;

/******************************************************************************/

/******************************************************************************/
/*
	Crypto trace
*/
#ifndef USE_CRYPTO_TRACE
#define psTraceCrypto(x)
#define psTraceStrCrypto(x, y)
#define psTraceIntCrypto(x, y)
#define psTracePtrCrypto(x, y)
#else
#define psTraceCrypto(x) _psTrace(x)
#define psTraceStrCrypto(x, y) _psTraceStr(x, y)
#define psTraceIntCrypto(x, y) _psTraceInt(x, y)
#define psTracePtrCrypto(x, y) _psTracePtr(x, y)
#endif /* USE_CRYPTO_TRACE */


/******************************************************************************/
/*
	Helpers
*/
extern int32 psBase64decode(const unsigned char *in,  uint32 len,
					unsigned char *out, uint32 *outlen);
extern void psOpenPrng(void);
extern void psClosePrng(void);
extern int32 matrixCryptoGetPrngData(unsigned char *bytes, uint32 size,
					void *userPtr);

/******************************************************************************/
/*
	RFC 3279 OID
	Matrix uses an oid summing mechanism to arrive at these defines.
	The byte values of the OID are summed to produce a "relatively unique" int

	The duplicate defines do not pose a problem as long as they don't
	exist in the same OID groupings
*/
/* Raw digest algorithms */
#define OID_SHA1_ALG			88
#define OID_SHA256_ALG			414
#define OID_SHA384_ALG			415
#define OID_SHA512_ALG			416
#define OID_MD2_ALG				646
#define OID_MD5_ALG				649

/* Signature algorithms */
#define OID_MD2_RSA_SIG			646
#define OID_MD5_RSA_SIG			648 /* 42.134.72.134.247.13.1.1.4 */
#define OID_SHA1_RSA_SIG		649 /* 42.134.72.134.247.13.1.1.5 */
#define OID_ID_MGF1				652 /* 42.134.72.134.247.13.1.1.8 */
#define OID_RSASSA_PSS			654 /* 42.134.72.134.247.13.1.1.10 */
#define OID_SHA256_RSA_SIG		655 /* 42.134.72.134.247.13.1.1.11 */
#define OID_SHA384_RSA_SIG		656 /* 42.134.72.134.247.13.1.1.12 */
#define OID_SHA512_RSA_SIG		657 /* 42.134.72.134.247.13.1.1.13 */
#define OID_SHA1_ECDSA_SIG		520	/* 42.134.72.206.61.4.1 */
#define OID_SHA224_ECDSA_SIG	523 /* 42.134.72.206.61.4.3.1 */
#define OID_SHA256_ECDSA_SIG	524 /* 42.134.72.206.61.4.3.2 */
#define OID_SHA384_ECDSA_SIG	525 /* 42.134.72.206.61.4.3.3 */
#define OID_SHA512_ECDSA_SIG	526 /* 42.134.72.206.61.4.3.4 */

/* Public key algorithms */
#define OID_RSA_KEY_ALG			645
#define OID_ECDSA_KEY_ALG		518 /* 1.2.840.10045.2.1 */

/* Encryption algorithms */
#define OID_DES_EDE3_CBC		652 /* 42.134.72.134.247.13.3.7 */
#define OID_AES_128_CBC			414	/* 2.16.840.1.101.3.4.1.2 */
#define OID_AES_128_WRAP		417 /* 2.16.840.1.101.3.4.1.5 */
#define OID_AES_128_GCM			418 /* 2.16.840.1.101.3.4.1.6 */
#define OID_AES_192_CBC			434	/* 2.16.840.1.101.3.4.1.22 */
#define OID_AES_192_WRAP		437	/* 2.16.840.1.101.3.4.1.25 */
#define OID_AES_192_GCM			438	/* 2.16.840.1.101.3.4.1.26 */
#define OID_AES_256_CBC			454 /* 2.16.840.1.101.3.4.1.42 */
#define OID_AES_256_WRAP		457 /* 2.16.840.1.101.3.4.1.45 */
#define OID_AES_256_GCM			458	/* 2.16.840.1.101.3.4.1.46 */

								/* TODO: Made this up.  Couldn't find */
#define OID_AES_CMAC			612	/* 2.16.840.1.101.3.4.1.200 */

/* TODO: These are not officially defined yet */
#define OID_AES_CBC_CMAC_128	143
#define OID_AES_CBC_CMAC_192	144
#define OID_AES_CBC_CMAC_256	145

#define OID_AUTH_ENC_256_SUM	687 /* The RFC 6476 authEnc OID */

#ifdef USE_PKCS5
#define OID_PKCS_PBKDF2			660 /* 42.134.72.134.247.13.1.5.12 */
#define OID_PKCS_PBES2			661 /* 42.134.72.134.247.13.1.5.13 */
#endif /* USE_PKCS5 */

#ifdef USE_PKCS12
#define OID_PKCS_PBESHA128RC4	657
#define OID_PKCS_PBESHA40RC4	658
#define OID_PKCS_PBESHA3DES3	659
#define OID_PKCS_PBESHA3DES2	660 /* warning: collision with pkcs5 */
#define OID_PKCS_PBESHA128RC2	661 /* warning: collision with pkcs5 */
#define OID_PKCS_PBESHA40RC2	662

#define PKCS12_BAG_TYPE_KEY			667
#define PKCS12_BAG_TYPE_SHROUD		668
#define PKCS12_BAG_TYPE_CERT		669
#define PKCS12_BAG_TYPE_CRL			670
#define PKCS12_BAG_TYPE_SECRET		671
#define PKCS12_BAG_TYPE_SAFE		672

#define PBE12						1
#define PBES2						2
#define AUTH_SAFE_3DES				1
#define AUTH_SAFE_RC2				2

#define PKCS12_KEY_ID				1
#define PKCS12_IV_ID				2
#define PKCS12_MAC_ID				3

#define PKCS9_CERT_TYPE_X509		675
#define PKCS9_CERT_TYPE_SDSI		676

#define PKCS7_DATA					651
/* signedData 1.2.840.113549.1.7.2  (2A 86 48 86 F7 0D 01 07 02) */
#define PKCS7_SIGNED_DATA			652
#define PKCS7_ENVELOPED_DATA		653
#define PKCS7_SIGNED_ENVELOPED_DATA	654
#define PKCS7_DIGESTED_DATA			655
#define PKCS7_ENCRYPTED_DATA		656
#endif /* USE_PKCS12 */

#if defined(USE_PKCS1_OAEP) || defined(USE_PKCS1_PSS)
#define PKCS1_SHA1_ID	0
#define PKCS1_MD5_ID	1
#define PKCS1_SHA256_ID	2
#define PKCS1_SHA384_ID 3
#define PKCS1_SHA512_ID 4
#endif

/******************************************************************************/
/* These values are all mutually exlusive bits to define Cipher flags */
#define CRYPTO_FLAGS_AES	0x01
#define CRYPTO_FLAGS_AES256	0x02
#define CRYPTO_FLAGS_3DES	0x04
#define CRYPTO_FLAGS_ARC4	0x08
#define CRYPTO_FLAGS_SEED	0x10

#define CRYPTO_FLAGS_SHA1	0x20
#define CRYPTO_FLAGS_SHA2	0x40
#define CRYPTO_FLAGS_MD5	0x80

#define CRYPTO_FLAGS_TLS		0x100
#define CRYPTO_FLAGS_TLS_1_1	0x200
#define CRYPTO_FLAGS_TLS_1_2	0x400

#define CRYPTO_FLAGS_INBOUND	0x800
#define CRYPTO_FLAGS_ARC4INITE	0x1000 /* Encrypt init */
#define CRYPTO_FLAGS_ARC4INITD	0x2000 /* Decrypt init */
#define CRYPTO_FLAGS_BLOCKING	0x4000

#define CRYPTO_FLAGS_DISABLED	0x8000
#define CRYPTO_FLAGS_GCM		0x10000

#define CRYPTO_FLAGS_SHA3		0x20000 /* SHA-384 */

/******************************************************************************/

#define	CRYPT_INVALID_KEYSIZE	-21
#define	CRYPT_INVALID_ROUNDS	-22

/******************************************************************************/
/* 32-bit Rotates */
/******************************************************************************/
#if defined(_MSC_VER)
/******************************************************************************/

/* instrinsic rotate */
#include <stdlib.h>
#pragma intrinsic(_lrotr,_lrotl)
#define ROR(x,n) _lrotr(x,n)
#define ROL(x,n) _lrotl(x,n)

/******************************************************************************/
#elif defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__)) && \
		!defined(INTEL_CC) && !defined(PS_NO_ASM)

static inline unsigned ROL(unsigned word, int i)
{
   asm ("roll %%cl,%0"
	  :"=r" (word)
	  :"0" (word),"c" (i));
   return word;
}

static inline unsigned ROR(unsigned word, int i)
{
   asm ("rorl %%cl,%0"
	  :"=r" (word)
	  :"0" (word),"c" (i));
   return word;
}

/******************************************************************************/
#else

/* rotates the hard way */
#define ROL(x, y) \
	( (((unsigned long)(x)<<(unsigned long)((y)&31)) | \
	(((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)(32-((y)&31)))) & \
	0xFFFFFFFFUL)
#define ROR(x, y) \
	( ((((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)((y)&31)) | \
	((unsigned long)(x)<<(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)

#endif /* 32-bit Rotates */
/******************************************************************************/

#ifdef HAVE_NATIVE_INT64
#ifdef _MSC_VER
	#define CONST64(n) n ## ui64
#else
	#define CONST64(n) n ## ULL
#endif
#endif

/******************************************************************************/
/*
	Endian helper macros
 */
#if defined (ENDIAN_NEUTRAL)
#define STORE32L(x, y) { \
(y)[3] = (unsigned char)(((x)>>24)&255); \
(y)[2] = (unsigned char)(((x)>>16)&255);  \
(y)[1] = (unsigned char)(((x)>>8)&255); \
(y)[0] = (unsigned char)((x)&255); \
}

#define LOAD32L(x, y) { \
x = ((unsigned long)((y)[3] & 255)<<24) | \
((unsigned long)((y)[2] & 255)<<16) | \
((unsigned long)((y)[1] & 255)<<8)  | \
((unsigned long)((y)[0] & 255)); \
}

#define STORE64L(x, y) { \
(y)[7] = (unsigned char)(((x)>>56)&255); \
(y)[6] = (unsigned char)(((x)>>48)&255); \
(y)[5] = (unsigned char)(((x)>>40)&255); \
(y)[4] = (unsigned char)(((x)>>32)&255); \
(y)[3] = (unsigned char)(((x)>>24)&255); \
(y)[2] = (unsigned char)(((x)>>16)&255); \
(y)[1] = (unsigned char)(((x)>>8)&255); \
(y)[0] = (unsigned char)((x)&255); \
}

#define LOAD64L(x, y) { \
x = (((uint64)((y)[7] & 255))<<56)|(((uint64)((y)[6] & 255))<<48)| \
(((uint64)((y)[5] & 255))<<40)|(((uint64)((y)[4] & 255))<<32)| \
(((uint64)((y)[3] & 255))<<24)|(((uint64)((y)[2] & 255))<<16)| \
(((uint64)((y)[1] & 255))<<8)|(((uint64)((y)[0] & 255))); \
}

#define STORE32H(x, y) { \
(y)[0] = (unsigned char)(((x)>>24)&255); \
(y)[1] = (unsigned char)(((x)>>16)&255); \
(y)[2] = (unsigned char)(((x)>>8)&255); \
(y)[3] = (unsigned char)((x)&255); \
}

#define LOAD32H(x, y) { \
x = ((unsigned long)((y)[0] & 255)<<24) | \
((unsigned long)((y)[1] & 255)<<16) | \
((unsigned long)((y)[2] & 255)<<8)  | \
((unsigned long)((y)[3] & 255)); \
}

#define STORE64H(x, y) { \
(y)[0] = (unsigned char)(((x)>>56)&255); \
(y)[1] = (unsigned char)(((x)>>48)&255); \
(y)[2] = (unsigned char)(((x)>>40)&255); \
(y)[3] = (unsigned char)(((x)>>32)&255); \
(y)[4] = (unsigned char)(((x)>>24)&255); \
(y)[5] = (unsigned char)(((x)>>16)&255); \
(y)[6] = (unsigned char)(((x)>>8)&255); \
(y)[7] = (unsigned char)((x)&255); \
}

#define LOAD64H(x, y) { \
x = (((uint64)((y)[0] & 255))<<56)|(((uint64)((y)[1] & 255))<<48) | \
(((uint64)((y)[2] & 255))<<40)|(((uint64)((y)[3] & 255))<<32) | \
(((uint64)((y)[4] & 255))<<24)|(((uint64)((y)[5] & 255))<<16) | \
(((uint64)((y)[6] & 255))<<8)|(((uint64)((y)[7] & 255))); \
}

#endif /* ENDIAN_NEUTRAL */

#ifdef ENDIAN_LITTLE
#define STORE32H(x, y) { \
(y)[0] = (unsigned char)(((x)>>24)&255); \
(y)[1] = (unsigned char)(((x)>>16)&255); \
(y)[2] = (unsigned char)(((x)>>8)&255); \
(y)[3] = (unsigned char)((x)&255); \
}

#define LOAD32H(x, y) { \
x = ((unsigned long)((y)[0] & 255)<<24) | \
((unsigned long)((y)[1] & 255)<<16) | \
((unsigned long)((y)[2] & 255)<<8)  | \
((unsigned long)((y)[3] & 255)); \
}

#define STORE64H(x, y) { \
(y)[0] = (unsigned char)(((x)>>56)&255); \
(y)[1] = (unsigned char)(((x)>>48)&255); \
(y)[2] = (unsigned char)(((x)>>40)&255); \
(y)[3] = (unsigned char)(((x)>>32)&255); \
(y)[4] = (unsigned char)(((x)>>24)&255); \
(y)[5] = (unsigned char)(((x)>>16)&255); \
(y)[6] = (unsigned char)(((x)>>8)&255); \
(y)[7] = (unsigned char)((x)&255); \
}

#define LOAD64H(x, y) { \
x = (((uint64)((y)[0] & 255))<<56)|(((uint64)((y)[1] & 255))<<48) | \
(((uint64)((y)[2] & 255))<<40)|(((uint64)((y)[3] & 255))<<32) | \
(((uint64)((y)[4] & 255))<<24)|(((uint64)((y)[5] & 255))<<16) | \
(((uint64)((y)[6] & 255))<<8)|(((uint64)((y)[7] & 255))); }

#ifdef ENDIAN_32BITWORD
#define STORE32L(x, y) { \
unsigned long __t = (x); memcpy(y, &__t, 4); \
}

#define LOAD32L(x, y)  memcpy(&(x), y, 4);

#define STORE64L(x, y) { \
(y)[7] = (unsigned char)(((x)>>56)&255); \
(y)[6] = (unsigned char)(((x)>>48)&255); \
(y)[5] = (unsigned char)(((x)>>40)&255); \
(y)[4] = (unsigned char)(((x)>>32)&255); \
(y)[3] = (unsigned char)(((x)>>24)&255); \
(y)[2] = (unsigned char)(((x)>>16)&255); \
(y)[1] = (unsigned char)(((x)>>8)&255); \
(y)[0] = (unsigned char)((x)&255); \
}

#define LOAD64L(x, y) { \
x = (((uint64)((y)[7] & 255))<<56)|(((uint64)((y)[6] & 255))<<48)| \
(((uint64)((y)[5] & 255))<<40)|(((uint64)((y)[4] & 255))<<32)| \
(((uint64)((y)[3] & 255))<<24)|(((uint64)((y)[2] & 255))<<16)| \
(((uint64)((y)[1] & 255))<<8)|(((uint64)((y)[0] & 255))); \
}

#else /* 64-bit words then  */
#define STORE32L(x, y) \
{ unsigned long __t = (x); memcpy(y, &__t, 4); }

#define LOAD32L(x, y) \
{ memcpy(&(x), y, 4); x &= 0xFFFFFFFF; }

#define STORE64L(x, y) \
{ uint64 __t = (x); memcpy(y, &__t, 8); }

#define LOAD64L(x, y) \
{ memcpy(&(x), y, 8); }

#endif /* ENDIAN_64BITWORD */
#endif /* ENDIAN_LITTLE */

#ifdef ENDIAN_BIG
#define STORE32L(x, y) { \
(y)[3] = (unsigned char)(((x)>>24)&255); \
(y)[2] = (unsigned char)(((x)>>16)&255); \
(y)[1] = (unsigned char)(((x)>>8)&255); \
(y)[0] = (unsigned char)((x)&255); \
}

#define LOAD32L(x, y) { \
x = ((unsigned long)((y)[3] & 255)<<24) | \
((unsigned long)((y)[2] & 255)<<16) | \
((unsigned long)((y)[1] & 255)<<8)  | \
((unsigned long)((y)[0] & 255)); \
}

#define STORE64L(x, y) { \
(y)[7] = (unsigned char)(((x)>>56)&255); \
(y)[6] = (unsigned char)(((x)>>48)&255); \
(y)[5] = (unsigned char)(((x)>>40)&255); \
(y)[4] = (unsigned char)(((x)>>32)&255); \
(y)[3] = (unsigned char)(((x)>>24)&255); \
(y)[2] = (unsigned char)(((x)>>16)&255); \
(y)[1] = (unsigned char)(((x)>>8)&255); \
(y)[0] = (unsigned char)((x)&255); \
}

#define LOAD64L(x, y) { \
x = (((uint64)((y)[7] & 255))<<56)|(((uint64)((y)[6] & 255))<<48) | \
(((uint64)((y)[5] & 255))<<40)|(((uint64)((y)[4] & 255))<<32) | \
(((uint64)((y)[3] & 255))<<24)|(((uint64)((y)[2] & 255))<<16) | \
(((uint64)((y)[1] & 255))<<8)|(((uint64)((y)[0] & 255))); \
}

#ifdef ENDIAN_32BITWORD
#define STORE32H(x, y) \
{ unsigned int __t = (x); memcpy(y, &__t, 4); }

#define LOAD32H(x, y) memcpy(&(x), y, 4);

#define STORE64H(x, y) { \
(y)[0] = (unsigned char)(((x)>>56)&255); \
(y)[1] = (unsigned char)(((x)>>48)&255); \
(y)[2] = (unsigned char)(((x)>>40)&255); \
(y)[3] = (unsigned char)(((x)>>32)&255); \
(y)[4] = (unsigned char)(((x)>>24)&255); \
(y)[5] = (unsigned char)(((x)>>16)&255); \
(y)[6] = (unsigned char)(((x)>>8)&255); \
(y)[7] = (unsigned char)((x)&255); \
}

#define LOAD64H(x, y) { \
x = (((uint64)((y)[0] & 255))<<56)|(((uint64)((y)[1] & 255))<<48)| \
(((uint64)((y)[2] & 255))<<40)|(((uint64)((y)[3] & 255))<<32)| \
(((uint64)((y)[4] & 255))<<24)|(((uint64)((y)[5] & 255))<<16)| \
(((uint64)((y)[6] & 255))<<8)| (((uint64)((y)[7] & 255))); \
}

#else /* 64-bit words then  */

#define STORE32H(x, y) \
{ unsigned long __t = (x); memcpy(y, &__t, 4); }

#define LOAD32H(x, y) \
{ memcpy(&(x), y, 4); x &= 0xFFFFFFFF; }

#define STORE64H(x, y) \
{ uint64 __t = (x); memcpy(y, &__t, 8); }

#define LOAD64H(x, y) \
{ memcpy(&(x), y, 8); }

#endif /* ENDIAN_64BITWORD */
#endif /* ENDIAN_BIG */

#ifdef HAVE_NATIVE_INT64
#define ROL64c(x, y) \
( (((x)<<((uint64)(y)&63)) | \
(((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((uint64)64-((y)&63)))) & CONST64(0xFFFFFFFFFFFFFFFF))

#define ROR64c(x, y) \
( ((((x)&CONST64(0xFFFFFFFFFFFFFFFF))>>((uint64)(y)&CONST64(63))) | \
((x)<<((uint64)(64-((y)&CONST64(63)))))) & CONST64(0xFFFFFFFFFFFFFFFF))
#endif /* HAVE_NATIVE_INT64 */
/******************************************************************************/


/******************************************************************************/
/*
	Return the length of padding bytes required for a record of 'LEN' bytes
	The name Pwr2 indicates that calculations will work with 'BLOCKSIZE'
	that are powers of 2.
	Because of the trailing pad length byte, a length that is a multiple
	of the pad bytes
*/
#define psPadLenPwr2(LEN, BLOCKSIZE) \
	BLOCKSIZE <= 1 ? (unsigned char)0 : \
	(unsigned char)(BLOCKSIZE - ((LEN) & (BLOCKSIZE - 1)))


#ifdef USE_PKCS11

/* #define PKCS11_STATS */
#ifdef PKCS11_STATS
extern void pkcs11RegisterObj(CK_SESSION_HANDLE ses, CK_OBJECT_HANDLE obj);
extern void pkcs11ShowObjects();
#endif
extern CK_RV pkcs11Init(CK_C_INITIALIZE_ARGS *args);
extern CK_RV pkcs11Close(void);
extern CK_RV pkcs11OpenSession(CK_SESSION_HANDLE *session, int32 flags);
extern void pkcs11CloseSession(CK_SESSION_HANDLE session);
extern CK_RV pkcs11CreateObject(CK_SESSION_HANDLE session,
				CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
				CK_OBJECT_HANDLE *phObject);
extern CK_RV pkcs11DestroyObject(CK_SESSION_HANDLE session,
				CK_OBJECT_HANDLE object);
#endif

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
	CBC Mode AES
*/
PSPUBLIC int32 psCbcAesInit(psCipherContext_t *ctx, unsigned char *IV,
						unsigned char *key, uint32 keylen);
PSPUBLIC int32 psCbcAesDecrypt(psCipherContext_t *ctx, unsigned char *ct,
						unsigned char *pt, uint32 len);
PSPUBLIC int32 psCbcAesEncrypt(psCipherContext_t *ctx, unsigned char *pt,
						unsigned char *ct, uint32 len);
/*
	CTR Mode AES
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

PSPUBLIC int32 psX509ExportCertBinary(psPool_t *pool, psX509Cert_t *cert,
		psPubKey_t *privKey, unsigned char *out, uint32 outlen);

PSPUBLIC int x509_write_publickey( psPool_t *pool, unsigned char **p, unsigned char *start,
		psPubKey_t *publicKey, int32 pubKeyAlgorithm );

PSPUBLIC int x509_export_ecc_key( psPool_t *pool, unsigned char **p, unsigned char *start,
		psPubKey_t *publicKey, int32 pubKeyAlgorithm, unsigned char *x, uint32 xlen, unsigned char *y, uint32 ylen);




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
	//psCbcmacContext_t 	 ctx;
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

#ifdef __cplusplus
    }
#endif

#endif
