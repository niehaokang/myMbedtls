/**
 *	@file    osdep.c
 *	@version 33ef80f (HEAD, tag: MATRIXSSL-3-7-2-OPEN, tag: MATRIXSSL-3-7-2-COMM, origin/master, origin/HEAD, master)
 *
 *	POSIX layer.
 *		Mac OSX 10.5
 *		Linux
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

#include "../coreApi.h"
#include <contrib/lib_tvm_time/lib_tvm_time.h>
#include <contrib/libutcrypto/ut_pf_cp_hwc.h>

int osdepTimeOpen(void)
{
	return PS_SUCCESS;
}

void osdepTimeClose(void)
{
}

int32 psGetTime(psTime_t *t, void *userPtr)
{
	TIME_Time   lt_time;
	((void)userPtr);
	if (t == NULL) {
		GetSystemTime(&lt_time);
		return lt_time.seconds;
	}

	GetSystemTime(&lt_time) ;

	t->tv_sec = (__time_t)lt_time.seconds;
	t->tv_usec = (__suseconds_t)(lt_time.mills * 1000);
	return t->tv_sec;
}

int32 psDiffMsecs(psTime_t then, psTime_t now, void *userPtr)
{
	((void)userPtr);
	if (now.tv_usec < then.tv_usec) {
		now.tv_sec--;
		now.tv_usec += 1000000; /* borrow 1 second worth of usec */
	}
	return (int32)((now.tv_sec - then.tv_sec) * 1000) +
		((now.tv_usec - then.tv_usec)/ 1000);
}

/******************************************************************************/


/******************************************************************************/
/* MUTEX */

#ifdef USE_MULTITHREADING

int osdepMutexOpen(void)
{
	return PS_SUCCESS;
}

int osdepMutexClose(void)
{
	return PS_SUCCESS;
}

/* PScore Public API implementations */
int32 psCreateMutex(psMutex_t *mutex)
{
	sem_init(mutex, 0, 1);
	return PS_SUCCESS;
}

int32 psLockMutex(psMutex_t *mutex)
{
	sem_wait(mutex);
	return PS_SUCCESS;
}

int32 psUnlockMutex(psMutex_t *mutex)
{
	sem_post(mutex);
	return PS_SUCCESS;
}

void psDestroyMutex(psMutex_t *mutex)
{
	sem_destroy(mutex);
}
#endif /* USE_MULTITHREADING */

/******************************************************************************/
/* ENTROPY */

//static HCRYPTPROV		hProv;	/* Crypto context for random bytes */

int osdepEntropyOpen(void)
{
	return PS_SUCCESS;
}

void osdepEntropyClose(void)
{
}

#if 0
static void hexify( unsigned char *obuf, const unsigned char *ibuf, int len ) {
    unsigned char l, h;

    while( len != 0 )
    {
        h = *ibuf / 16;
        l = *ibuf % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}

static void printlog(char *name, unsigned char *hex, int hexlen )
{
	int i = 0, n = 0, m = 0;
	unsigned char *p = hex;
	unsigned char out[128] = {0};

	n = hexlen / 32; m = hexlen % 32;
	for ( i = 0; i < n; i++) {
		memset( out, 0, sizeof(out));
		hexify( out, p, 32 );
		printf( "%s:%s\n", name, out);
		p += 32;
	}

	if ( m > 0 ) {
		memset( out, 0, sizeof(out));
		hexify( out, p, m );
		printf( "%s:%s\n", name, out);
	}
}
#endif

int32 psGetEntropy(unsigned char *bytes, uint32 size, void *userPtr)
{
	((void)userPtr);

	static int use_hwc_flg = 1;

	if ( use_hwc_flg )
	{
		ut_int32_t r = -1;
		ut_pf_cp_context_h *ctx = NULL;

		unsigned int x = 946080000;

		r = ut_pf_cp_hwc_open(&ctx,
					UT_PF_CP_CLS_RD,
					UT_PF_CP_ACT_RD_GENVEC);
		if ( r < 0 ) {
			goto soft_random;
		}

		r = ut_pf_cp_hwc_rd_random(ctx,
					(ut_uint8_t *)bytes, size);
		if ( r < 0 ) {
			ut_pf_cp_hwc_close(ctx);
			goto soft_random;
		}

		r = ut_pf_cp_hwc_close(ctx);
		if ( r < 0 ) {
			goto soft_random;
		}

		//printlog("psGetEntropy(H)", bytes, size);
		return size;

soft_random:
		printf("Use Soft-Random Algorithm !!! \n");

		use_hwc_flg = 0;
		srandom( x );
	}

	int  i, n, l;
	int *d = bytes;

	n = size / sizeof(int);
	l = size % sizeof(int);

	for (i = 0; i < n; i++)	*d++ = rand();
	if  (l > 0) { n = rand(); memcpy(d, &n, l); }

	//printlog("psGetEntropy(S)", bytes, size);
	return size;
}

/******************************************************************************/
/* TRACE */

int osdepTraceOpen(void)
{
	return PS_SUCCESS;
}

void osdepTraceClose(void)
{
}

void _psTrace(char *msg)
{
	printf(msg);
}

/* Message should contain one %s, unless value is NULL */
void _psTraceStr(char *message, char *value)
{
	if (value) {
		printf(message, value);
	} else {
		printf(message);
	}
}

/* message should contain one %d */
void _psTraceInt(char *message, int32 value)
{
	printf(message, value);
}

/* message should contain one %p */
void _psTracePtr( char *message, void *value)
{
	printf(message, value);
}

/******************************************************************************/
/* DEBUGGING */

#ifdef HALT_ON_PS_ERROR
void osdepBreak(void)
{
	/* System halt on psError (and assert) */
	 DebugBreak();
}
#endif /* HALT_ON_PS_ERROR */

/******************************************************************************/
/* FILE SYSTEM */

#ifdef MATRIX_USE_FILE_SYSTEM
/*
	Memory info:
	Caller must free 'buf' parameter on success
	Callers do not need to free buf on function failure
*/
int32 psGetFileBuf(psPool_t *pool, const char *fileName, unsigned char **buf,
				int32 *bufLen)
{
	FILE	*fp;
	struct	stat	fstat;
	size_t	tmp = 0;

	*bufLen = 0;
	*buf = NULL;

	if (fileName == NULL) {
		return PS_ARG_FAIL;
	}
	if ((stat(fileName, &fstat) != 0) || (fp = fopen(fileName, "r")) == NULL) {
		psTraceStrCore("Unable to open %s\n", (char*)fileName);
		return PS_PLATFORM_FAIL;
	}

	*buf = psMalloc(pool, (size_t)(fstat.st_size + 1));
	if (*buf == NULL) {
		return PS_MEM_FAIL;
	}
	memset(*buf, 0x0, (size_t)fstat.st_size + 1);

	while (((tmp = fread(*buf + *bufLen, sizeof(char), 512, fp)) > 0) &&
			(*bufLen < fstat.st_size)) {
		*bufLen += (int32)tmp;
	}
	fclose(fp);
	return PS_SUCCESS;
}
#endif /* MATRIX_USE_FILE_SYSTEM */

