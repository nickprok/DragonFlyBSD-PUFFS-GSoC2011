#	$NetBSD: Makefile,v 1.24 2010/12/06 14:50:34 pooka Exp $
#

.include <bsd.own.mk>

USE_FORT?= yes	# data-driven bugs?

WARNS=		2

LIB=		puffs

SRCS=		puffs.c callcontext.c creds.c dispatcher.c flush.c	\
		framebuf.c null.c opdump.c paths.c pnode.c requests.c	\
		subr.c suspend.c
MAN=		puffs.3 puffs_cc.3 puffs_cred.3 puffs_flush.3		\
		puffs_framebuf.3 puffs_node.3 puffs_ops.3 puffs_path.3
INCS=		puffs.h puffsdump.h
INCSDIR=	/usr/include
LINTFLAGS+=-S -w
CFLAGS+=	-I${.CURDIR}/../../sys -I/usr/src/sbin/mount
DEBUG_FLAGS=	-O0 -g

.include <bsd.lib.mk>
