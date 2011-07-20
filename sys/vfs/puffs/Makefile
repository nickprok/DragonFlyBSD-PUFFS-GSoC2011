
KMOD=	puffs
SRCS=	puffs_msgif.c puffs_msgif.h puffs_node.c puffs_subr.c		\
	puffs_sys.h puffs_vfsops.c puffs_vnops.c 

DEBUG_FLAGS= -g -I${.CURDIR}/../.. -DPUFFSDEBUG -DINVARIANTS
# -DDEBUG_LOCKS

.include <bsd.kmod.mk>
