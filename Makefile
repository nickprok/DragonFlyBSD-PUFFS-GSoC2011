SUBDIR= sys/dev/misc/putter sys/vfs/puffs
SUBDIR+= lib/libpuffs
SUBDIR+= lib/librefuse
SUBDIR+= usr.sbin/puffs/mount_psshfs
SUBDIR+= share/examples/puffs/pnullfs

.include <bsd.subdir.mk>
