/*	$NetBSD: puffs_vnops.c,v 1.154 2011/07/04 08:07:30 manu Exp $	*/

/*
 * Copyright (c) 2005, 2006, 2007  Antti Kantee.  All Rights Reserved.
 *
 * Development of this software was supported by the
 * Google Summer of Code program and the Ulla Tuominen Foundation.
 * The Google SoC project was mentored by Bill Studenmund.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/buf.h>
#include <sys/lockf.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/proc.h>

#include <vfs/puffs/puffs_msgif.h>
#include <vfs/puffs/puffs_sys.h>

#define RWARGS(cont, iofl, move, offset, creds)				\
	(cont)->pvnr_ioflag = (iofl);					\
	(cont)->pvnr_resid = (move);					\
	(cont)->pvnr_offset = (offset);					\
	puffs_credcvt(&(cont)->pvnr_cred, creds)

int
puffs_directread(struct vnode *vp, struct uio *uio, int ioflag,
    struct ucred *cred)
{
	PUFFS_MSG_VARS(vn, read);
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);
	size_t tomove, argsize;
	int error;

	KKASSERT(vp->v_type == VREG);

	if (uio->uio_offset < 0)
		return EINVAL;
	if (uio->uio_resid == 0)
		return 0;

	read_msg = NULL;
	error = 0;

	/* std sanity */
	if (uio->uio_resid == 0)
		return 0;
	if (uio->uio_offset < 0)
		return EINVAL;

	/*
	 * in case it's not a regular file or we're operating
	 * uncached, do read in the old-fashioned style,
	 * i.e. explicit read operations
	 */

	tomove = PUFFS_TOMOVE(uio->uio_resid, pmp);
	argsize = sizeof(struct puffs_vnmsg_read);
	puffs_msgmem_alloc(argsize + tomove, &park_read,
	    (void *)&read_msg, 1);

	error = 0;
	while (uio->uio_resid > 0) {
		tomove = PUFFS_TOMOVE(uio->uio_resid, pmp);
		memset(read_msg, 0, argsize); /* XXX: touser KASSERT */
		RWARGS(read_msg, ioflag, tomove,
		    uio->uio_offset, cred);
		puffs_msg_setinfo(park_read, PUFFSOP_VN,
		    PUFFS_VN_READ, VPTOPNC(vp));
		puffs_msg_setdelta(park_read, tomove);

		PUFFS_MSG_ENQUEUEWAIT2(pmp, park_read, vp->v_data,
		    NULL, error);
		error = checkerr(pmp, error, __func__);
		if (error)
			break;

		if (read_msg->pvnr_resid > tomove) {
			puffs_senderr(pmp, PUFFS_ERR_READ,
			    E2BIG, "resid grew", VPTOPNC(vp));
			error = EPROTO;
			break;
		}

		error = uiomove(read_msg->pvnr_data,
		    tomove - read_msg->pvnr_resid, uio);

		/*
		 * in case the file is out of juice, resid from
		 * userspace is != 0.  and the error-case is
		 * quite obvious
		 */
		if (error || read_msg->pvnr_resid)
			break;
	}

	puffs_msgmem_release(park_read);

	return error;
}

int
puffs_directwrite(struct vnode *vp, struct uio *uio, int ioflag,
    struct ucred *cred)
{
	PUFFS_MSG_VARS(vn, write);
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);
	size_t tomove, argsize;
	int error, uflags;

	KKASSERT(vp->v_type == VREG);

	if (uio->uio_offset < 0)
		return EINVAL;
	if (uio->uio_resid == 0)
		return 0;

	error = uflags = 0;
	write_msg = NULL;

	/* tomove is non-increasing */
	tomove = PUFFS_TOMOVE(uio->uio_resid, pmp);
	argsize = sizeof(struct puffs_vnmsg_write) + tomove;
	puffs_msgmem_alloc(argsize, &park_write, (void *)&write_msg,1);

	while (uio->uio_resid > 0) {
		/* move data to buffer */
		tomove = PUFFS_TOMOVE(uio->uio_resid, pmp);
		memset(write_msg, 0, argsize); /* XXX: touser KASSERT */
		RWARGS(write_msg, ioflag, tomove,
		    uio->uio_offset, cred);
		error = uiomove(write_msg->pvnr_data, tomove, uio);
		if (error)
			break;

		/* move buffer to userspace */
		puffs_msg_setinfo(park_write, PUFFSOP_VN,
		    PUFFS_VN_WRITE, VPTOPNC(vp));
		PUFFS_MSG_ENQUEUEWAIT2(pmp, park_write, vp->v_data,
		    NULL, error);
		error = checkerr(pmp, error, __func__);
		if (error)
			break;

		if (write_msg->pvnr_resid > tomove) {
			puffs_senderr(pmp, PUFFS_ERR_WRITE,
			    E2BIG, "resid grew", VPTOPNC(vp));
			error = EPROTO;
			break;
		}

		/* adjust file size */
		if (vp->v_filesize < uio->uio_offset)
			vnode_pager_setsize(vp, uio->uio_offset);

		/* didn't move everything?  bad userspace.  bail */
		if (write_msg->pvnr_resid != 0) {
			error = EIO;
			break;
		}
	}
	puffs_msgmem_release(park_write);

	return error;
}

int
puffs_bioread(struct vnode *vp, struct uio *uio, int ioflag,
    struct ucred *cred)
{
	return ENOTSUP;
}

int
puffs_biowrite(struct vnode *vp, struct uio *uio, int ioflag,
    struct ucred *cred)
{
	return ENOTSUP;
}
