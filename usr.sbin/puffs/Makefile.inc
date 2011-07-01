WARNS?=	2

MOUNT=  /usr/src/sbin/mount
.PATH:  ${MOUNT}
CFLAGS+= -I${MOUNT}

SRCROOT=${.CURDIR}/../../..
DEBUG_FLAGS=-g -O0 -I${SRCROOT}/lib/libpuffs -I${SRCROOT}/sys
LDFLAGS+=-L${SRCROOT}/lib/libpuffs
