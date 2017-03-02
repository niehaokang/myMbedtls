PKGDIR	?= .
L4DIR	?= $(PKGDIR)/../..
#CRT2           := $(shell  rm -rf mbedtls-2.3.0 && tar zxvf src/libs/mbedtls-2.3.0-apache.tgz &&  patch -p0 <src/libs/bean.patch  && cp -f src/crypto/ut_pf_cp.h include/ut_pf_cp.h)
include $(L4DIR)/mk/subdir.mk
