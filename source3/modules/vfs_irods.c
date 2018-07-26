/* 
 * Skeleton VFS module.  Implements dummy versions of all VFS
 * functions.
 *
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002
 * Copyright (C) Stefan (metze) Metzmacher, 2003
 * Copyright (C) Jeremy Allison 2009
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "lib/util/tevent_ntstatus.h"

#include <dlfcn.h>
#include "libirods_smb.h"
//#include <irods/rodsClient.h>

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

/* PLEASE,PLEASE READ THE VFS MODULES CHAPTER OF THE 
   SAMBA DEVELOPERS GUIDE!!!!!!
 */

/* If you take this file as template for your module
 * you must re-implement every function.
 */

static void* libirods_smb_handle;

static int load_lib()
{
        libirods_smb_handle = dlopen("/usr/lib/libirods_smb.so", RTLD_LAZY | RTLD_GLOBAL);

        if (!libirods_smb_handle)
        {
            const char* err = dlerror();
            DEBUG(0, ("irods_connect - dlopen error: %s", err));
            errno = ENOSYS;
            return 0;
        }

        (void) dlerror();

        return 1;
}

// An implicit dlclose() of all libraries is performed on process termination.
// Probably don't need to call this.
static void unload_lib()
{
        dlclose(libirods_smb_handle);
}

static int irods_connect(vfs_handle_struct *handle, const char *service,
			const char *user)
{
        DEBUG(0, ("irods_connect - START\n"));

        static int lib_loaded = 0;

        if (!lib_loaded)
        {
            lib_loaded = load_lib();

            if (!lib_loaded)
            {
                DEBUG(0, ("irods_connect - failed to load libirods_smb."));
                errno = ENOSYS;
                return -1;
            }
        }

        DEBUG(0, ("irods_connect - allocating memory for irods_context ...\n"));

        irods_context* ctx = talloc_zero(handle->conn, irods_context);

        if (!ctx)
        {
            DEBUG(0, ("irods_connect - failed to allocate memory.\n"));
            errno = ENOMEM;
            return -1;
        }
        
        DEBUG(0, ("irods_connect - calling ismb_connect() ...\n"));

        error_code ec = ismb_connect(ctx);

        DEBUG(0, ("irods_connect - ismb_connect error code = %d\n", ec));

        if (ec != 0)
        {
            DEBUG(0, ("irods_connect - failed to connect.\n"));
            errno = ENOSYS;
            return -1;
        }

        DEBUG(0, ("irods_connect - associating irods_context with handle ...\n"));

        SMB_VFS_HANDLE_SET_DATA(handle, ctx, NULL, irods_context, return -1);

        DEBUG(0, ("irods_connect - END\n"));

        return 0;
}

static void irods_disconnect(vfs_handle_struct *handle)
{
        DEBUG(0, ("irods_disconnect - START\n"));
        DEBUG(0, ("irods_disconnect - retreiving irods_context ...\n"));

        irods_context* ctx;
        SMB_VFS_HANDLE_GET_DATA(handle, ctx, irods_context, return);

        DEBUG(0, ("irods_disconnect - calling ismb_disconnect ...\n"));

        error_code ec = ismb_disconnect(ctx);

        DEBUG(0, ("irods_disconnect - ismb_disconnect error code = %d\n", ec));

        if (ec != 0)
            DEBUG(0, ("ismb_disconnect - failed to disconnect.\n"));

        unload_lib();

        DEBUG(0, ("irods_disconnect - END\n"));
}

static uint64_t irods_disk_free(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	*bsize = 0;
	*dfree = 0;
	*dsize = 0;
	return 0;
}

static int irods_get_quota(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
				SMB_DISK_QUOTA *dq)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_set_quota(vfs_handle_struct *handle, enum SMB_QUOTA_TYPE qtype,
			  unid_t id, SMB_DISK_QUOTA *dq)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_get_shadow_copy_data(vfs_handle_struct *handle,
				     files_struct *fsp,
				     struct shadow_copy_data *shadow_copy_data,
				     bool labels)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_statvfs(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				struct vfs_statvfs_struct *statbuf)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static uint32_t irods_fs_capabilities(struct vfs_handle_struct *handle,
				     enum timestamp_set_resolution *p_ts_res)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return 0;
}

static NTSTATUS irods_get_dfs_referrals(struct vfs_handle_struct *handle,
				       struct dfs_GetDFSReferral *r)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static DIR *irods_opendir(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *mask,
			uint32_t attr)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NULL;
}

static NTSTATUS irods_snap_check_path(struct vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     const char *service_path,
				     char **base_volume)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS irods_snap_create(struct vfs_handle_struct *handle,
				 TALLOC_CTX *mem_ctx,
				 const char *base_volume,
				 time_t *tstamp,
				 bool rw,
				 char **base_path,
				 char **snap_path)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS irods_snap_delete(struct vfs_handle_struct *handle,
				 TALLOC_CTX *mem_ctx,
				 char *base_path,
				 char *snap_path)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_SUPPORTED;
}

static DIR *irods_fdopendir(vfs_handle_struct *handle, files_struct *fsp,
			   const char *mask, uint32_t attr)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NULL;
}

static struct dirent *irods_readdir(vfs_handle_struct *handle,
				   DIR *dirp, SMB_STRUCT_STAT *sbuf)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NULL;
}

static void irods_seekdir(vfs_handle_struct *handle, DIR *dirp, long offset)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	;
}

static long irods_telldir(vfs_handle_struct *handle, DIR *dirp)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return (long)-1;
}

static void irods_rewind_dir(vfs_handle_struct *handle, DIR *dirp)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	;
}

static int irods_mkdir(vfs_handle_struct *handle,
		const struct smb_filename *smb_fname,
		mode_t mode)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_rmdir(vfs_handle_struct *handle,
		const struct smb_filename *smb_fname)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_closedir(vfs_handle_struct *handle, DIR *dir)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_open(vfs_handle_struct *handle, struct smb_filename *smb_fname,
		     files_struct *fsp, int flags, mode_t mode)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static NTSTATUS irods_create_file(struct vfs_handle_struct *handle,
				 struct smb_request *req,
				 uint16_t root_dir_fid,
				 struct smb_filename *smb_fname,
				 uint32_t access_mask,
				 uint32_t share_access,
				 uint32_t create_disposition,
				 uint32_t create_options,
				 uint32_t file_attributes,
				 uint32_t oplock_request,
				 struct smb2_lease *lease,
				 uint64_t allocation_size,
				 uint32_t private_flags,
				 struct security_descriptor *sd,
				 struct ea_list *ea_list,
				 files_struct **result, int *pinfo,
				 const struct smb2_create_blobs *in_context_blobs,
				 struct smb2_create_blobs *out_context_blobs)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static int irods_close_fn(vfs_handle_struct *handle, files_struct *fsp)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static ssize_t irods_pread(vfs_handle_struct *handle, files_struct *fsp,
			  void *data, size_t n, off_t offset)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static struct tevent_req *irods_pread_send(struct vfs_handle_struct *handle,
					  TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct files_struct *fsp,
					  void *data, size_t n, off_t offset)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NULL;
}

static ssize_t irods_pread_recv(struct tevent_req *req,
			       struct vfs_aio_state *vfs_aio_state)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	vfs_aio_state->error = ENOSYS;
	return -1;
}

static ssize_t irods_pwrite(vfs_handle_struct *handle, files_struct *fsp,
			   const void *data, size_t n, off_t offset)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static struct tevent_req *irods_pwrite_send(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct files_struct *fsp,
					   const void *data,
					   size_t n, off_t offset)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NULL;
}

static ssize_t irods_pwrite_recv(struct tevent_req *req,
				struct vfs_aio_state *vfs_aio_state)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	vfs_aio_state->error = ENOSYS;
	return -1;
}

static off_t irods_lseek(vfs_handle_struct *handle, files_struct *fsp,
			off_t offset, int whence)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return (off_t) - 1;
}

static ssize_t irods_sendfile(vfs_handle_struct *handle, int tofd,
			     files_struct *fromfsp, const DATA_BLOB *hdr,
			     off_t offset, size_t n)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static ssize_t irods_recvfile(vfs_handle_struct *handle, int fromfd,
			     files_struct *tofsp, off_t offset, size_t n)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_rename(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname_src,
		       const struct smb_filename *smb_fname_dst)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static struct tevent_req *irods_fsync_send(struct vfs_handle_struct *handle,
					  TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct files_struct *fsp)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NULL;
}

static int irods_fsync_recv(struct tevent_req *req,
			   struct vfs_aio_state *vfs_aio_state)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	vfs_aio_state->error = ENOSYS;
	return -1;
}

static int irods_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));

        irods_context* ctx;
        SMB_VFS_HANDLE_GET_DATA(handle, ctx, irods_context, errno = ENOSYS; return -1);

        error_code ec = ismb_stat_path(ctx, "/tempZone/home/rods");
        DEBUG(0, (">>\tismb_stat_path ec = %d\n", ec));

        if (smb_fname->stream_name)
        {
            errno = ENOENT;
            return -1;
        }

        SMB_STRUCT_STAT* st = &smb_fname->st;

        st->st_ex_dev = 17;
        st->st_ex_rdev = 17;
        st->st_ex_nlink = 1;
        st->st_ex_uid = 1000;
        st->st_ex_gid = 1000;
        st->st_ex_size = 0;
        st->st_ex_mode = S_IFDIR | 0777;

	//errno = ENOSYS;
	//return -1;
        return 0;
}

static int irods_fstat(vfs_handle_struct *handle, files_struct *fsp,
		      SMB_STRUCT_STAT *sbuf)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_lstat(vfs_handle_struct *handle,
		      struct smb_filename *smb_fname)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static uint64_t irods_get_alloc_size(struct vfs_handle_struct *handle,
				    struct files_struct *fsp,
				    const SMB_STRUCT_STAT *sbuf)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_unlink(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_chmod(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_fchmod(vfs_handle_struct *handle, files_struct *fsp,
		       mode_t mode)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_chown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_fchown(vfs_handle_struct *handle, files_struct *fsp,
		       uid_t uid, gid_t gid)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_lchown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_chdir(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static struct smb_filename *irods_getwd(vfs_handle_struct *handle,
				TALLOC_CTX *ctx)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return NULL;
}

static int irods_ntimes(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname,
		       struct smb_file_time *ft)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_ftruncate(vfs_handle_struct *handle, files_struct *fsp,
			  off_t offset)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_fallocate(vfs_handle_struct *handle, files_struct *fsp,
			  uint32_t mode, off_t offset, off_t len)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static bool irods_lock(vfs_handle_struct *handle, files_struct *fsp, int op,
		      off_t offset, off_t count, int type)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return false;
}

static int irods_kernel_flock(struct vfs_handle_struct *handle,
			     struct files_struct *fsp,
			     uint32_t share_mode, uint32_t access_mask)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_linux_setlease(struct vfs_handle_struct *handle,
			       struct files_struct *fsp, int leasetype)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static bool irods_getlock(vfs_handle_struct *handle, files_struct *fsp,
			 off_t *poffset, off_t *pcount, int *ptype,
			 pid_t *ppid)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return false;
}

static int irods_symlink(vfs_handle_struct *handle,
			const char *link_contents,
			const struct smb_filename *new_smb_fname)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_vfs_readlink(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			char *buf,
			size_t bufsiz)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_link(vfs_handle_struct *handle,
			const struct smb_filename *old_smb_fname,
			const struct smb_filename *new_smb_fname)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_mknod(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode,
			SMB_DEV_T dev)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static struct smb_filename *irods_realpath(vfs_handle_struct *handle,
			TALLOC_CTX *ctx,
			const struct smb_filename *smb_fname)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
        DEBUG(0, (">> \tbase_name = %s\n", smb_fname->base_name));
        DEBUG(0, (">> \tstream_name = %s\n", smb_fname->stream_name));
        DEBUG(0, (">> \toriginal_lcomp = %s\n", smb_fname->original_lcomp));
        DEBUG(0, (">> \tflags = %u\n", smb_fname->flags));
        //DEBUG(0, (">> %s: base_name = %s\n", __FUNCTION__, smb_fname->st));

        //struct smb_filename* smb_fn = talloc_zero(handle->conn, struct smb_filename);
        //smb_fn->base_name = smb_fname->base_name;

        return synthetic_smb_fname(ctx, smb_fname->base_name, NULL, NULL, 0);
	//errno = ENOSYS;
	//return NULL;
}

static int irods_chflags(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uint flags)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static struct file_id irods_file_id_create(vfs_handle_struct *handle,
					  const SMB_STRUCT_STAT *sbuf)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	struct file_id id;
	ZERO_STRUCT(id);
	errno = ENOSYS;
	return id;
}

struct irods_offload_read_state {
	bool dummy;
};

static struct tevent_req *irods_offload_read_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct vfs_handle_struct *handle,
	struct files_struct *fsp,
	uint32_t fsctl,
	uint32_t ttl,
	off_t offset,
	size_t to_copy)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	struct tevent_req *req = NULL;
	struct irods_offload_read_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct irods_offload_read_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
	return tevent_req_post(req, ev);
}

static NTSTATUS irods_offload_read_recv(struct tevent_req *req,
				       struct vfs_handle_struct *handle,
				       TALLOC_CTX *mem_ctx,
				       DATA_BLOB *_token_blob)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}
	tevent_req_received(req);

	return NT_STATUS_OK;
}

struct irods_cc_state {
	uint64_t unused;
};
static struct tevent_req *irods_offload_write_send(struct vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       uint32_t fsctl,
					       DATA_BLOB *token,
					       off_t transfer_offset,
					       struct files_struct *dest_fsp,
					       off_t dest_off,
					       off_t num)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	struct tevent_req *req;
	struct irods_cc_state *cc_state;

	req = tevent_req_create(mem_ctx, &cc_state, struct irods_cc_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
	return tevent_req_post(req, ev);
}

static NTSTATUS irods_offload_write_recv(struct vfs_handle_struct *handle,
				     struct tevent_req *req,
				     off_t *copied)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}
	tevent_req_received(req);

	return NT_STATUS_OK;
}

static NTSTATUS irods_get_compression(struct vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct files_struct *fsp,
				     struct smb_filename *smb_fname,
				     uint16_t *_compression_fmt)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS irods_set_compression(struct vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct files_struct *fsp,
				     uint16_t compression_fmt)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS irods_streaminfo(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				const struct smb_filename *smb_fname,
				TALLOC_CTX *mem_ctx,
				unsigned int *num_streams,
				struct stream_struct **streams)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static int irods_get_real_filename(struct vfs_handle_struct *handle,
				  const char *path,
				  const char *name,
				  TALLOC_CTX *mem_ctx, char **found_name)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static const char *irods_connectpath(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return NULL;
}

static NTSTATUS irods_brl_lock_windows(struct vfs_handle_struct *handle,
				      struct byte_range_lock *br_lck,
				      struct lock_struct *plock,
				      bool blocking_lock)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static bool irods_brl_unlock_windows(struct vfs_handle_struct *handle,
				    struct messaging_context *msg_ctx,
				    struct byte_range_lock *br_lck,
				    const struct lock_struct *plock)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return false;
}

static bool irods_brl_cancel_windows(struct vfs_handle_struct *handle,
				    struct byte_range_lock *br_lck,
				    struct lock_struct *plock)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return false;
}

static bool irods_strict_lock_check(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   struct lock_struct *plock)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return false;
}

static NTSTATUS irods_translate_name(struct vfs_handle_struct *handle,
				    const char *mapped_name,
				    enum vfs_translate_direction direction,
				    TALLOC_CTX *mem_ctx, char **pmapped_name)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS irods_fsctl(struct vfs_handle_struct *handle,
			   struct files_struct *fsp,
			   TALLOC_CTX *ctx,
			   uint32_t function,
			   uint16_t req_flags,	/* Needed for UNICODE ... */
			   const uint8_t *_in_data,
			   uint32_t in_len,
			   uint8_t **_out_data,
			   uint32_t max_out_len, uint32_t *out_len)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS irods_readdir_attr(struct vfs_handle_struct *handle,
				  const struct smb_filename *fname,
				  TALLOC_CTX *mem_ctx,
				  struct readdir_attr_data **pattr_data)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS irods_get_dos_attributes(struct vfs_handle_struct *handle,
				struct smb_filename *smb_fname,
				uint32_t *dosmode)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS irods_fget_dos_attributes(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				uint32_t *dosmode)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS irods_set_dos_attributes(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint32_t dosmode)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS irods_fset_dos_attributes(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				uint32_t dosmode)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS irods_fget_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
				 uint32_t security_info,
				 TALLOC_CTX *mem_ctx,
				 struct security_descriptor **ppdesc)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS irods_get_nt_acl(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint32_t security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS irods_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
				 uint32_t security_info_sent,
				 const struct security_descriptor *psd)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static SMB_ACL_T irods_sys_acl_get_file(vfs_handle_struct *handle,
				       const struct smb_filename *smb_fname,
				       SMB_ACL_TYPE_T type,
				       TALLOC_CTX *mem_ctx)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return (SMB_ACL_T) NULL;
}

static SMB_ACL_T irods_sys_acl_get_fd(vfs_handle_struct *handle,
				     files_struct *fsp, TALLOC_CTX *mem_ctx)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return (SMB_ACL_T) NULL;
}

static int irods_sys_acl_blob_get_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				TALLOC_CTX *mem_ctx,
				char **blob_description,
				DATA_BLOB *blob)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_sys_acl_blob_get_fd(vfs_handle_struct *handle,
				    files_struct *fsp, TALLOC_CTX *mem_ctx,
				    char **blob_description, DATA_BLOB *blob)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_sys_acl_set_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				SMB_ACL_TYPE_T acltype,
				SMB_ACL_T theacl)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
			       SMB_ACL_T theacl)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_sys_acl_delete_def_file(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static ssize_t irods_getxattr(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				void *value,
				size_t size)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static ssize_t irods_fgetxattr(vfs_handle_struct *handle,
			      struct files_struct *fsp, const char *name,
			      void *value, size_t size)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static ssize_t irods_listxattr(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				char *list,
				size_t size)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static ssize_t irods_flistxattr(vfs_handle_struct *handle,
			       struct files_struct *fsp, char *list,
			       size_t size)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_removexattr(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *name)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_fremovexattr(vfs_handle_struct *handle,
			     struct files_struct *fsp, const char *name)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
	return SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, name);
}

static int irods_setxattr(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *name,
			const void *value,
			size_t size,
			int flags)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static int irods_fsetxattr(vfs_handle_struct *handle, struct files_struct *fsp,
			  const char *name, const void *value, size_t size,
			  int flags)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return -1;
}

static bool irods_aio_force(struct vfs_handle_struct *handle,
			   struct files_struct *fsp)
{
        DEBUG(0, (">> FUNCTION: %s\n", __FUNCTION__));
	errno = ENOSYS;
	return false;
}

/* VFS operations structure */

struct vfs_fn_pointers irods_fns = {
	/* Disk operations */

	.connect_fn = irods_connect,
	.disconnect_fn = irods_disconnect,
	.disk_free_fn = irods_disk_free,
	.get_quota_fn = irods_get_quota,
	.set_quota_fn = irods_set_quota,
	.get_shadow_copy_data_fn = irods_get_shadow_copy_data,
	.statvfs_fn = irods_statvfs,
	.fs_capabilities_fn = irods_fs_capabilities,
	.get_dfs_referrals_fn = irods_get_dfs_referrals,
	.snap_check_path_fn = irods_snap_check_path,
	.snap_create_fn = irods_snap_create,
	.snap_delete_fn = irods_snap_delete,

	/* Directory operations */

	.opendir_fn = irods_opendir,
	.fdopendir_fn = irods_fdopendir,
	.readdir_fn = irods_readdir,
	.seekdir_fn = irods_seekdir,
	.telldir_fn = irods_telldir,
	.rewind_dir_fn = irods_rewind_dir,
	.mkdir_fn = irods_mkdir,
	.rmdir_fn = irods_rmdir,
	.closedir_fn = irods_closedir,

	/* File operations */

	.open_fn = irods_open,
	.create_file_fn = irods_create_file,
	.close_fn = irods_close_fn,
	.pread_fn = irods_pread,
	.pread_send_fn = irods_pread_send,
	.pread_recv_fn = irods_pread_recv,
	.pwrite_fn = irods_pwrite,
	.pwrite_send_fn = irods_pwrite_send,
	.pwrite_recv_fn = irods_pwrite_recv,
	.lseek_fn = irods_lseek,
	.sendfile_fn = irods_sendfile,
	.recvfile_fn = irods_recvfile,
	.rename_fn = irods_rename,
	.fsync_send_fn = irods_fsync_send,
	.fsync_recv_fn = irods_fsync_recv,
	.stat_fn = irods_stat,
	.fstat_fn = irods_fstat,
	.lstat_fn = irods_lstat,
	.get_alloc_size_fn = irods_get_alloc_size,
	.unlink_fn = irods_unlink,
	.chmod_fn = irods_chmod,
	.fchmod_fn = irods_fchmod,
	.chown_fn = irods_chown,
	.fchown_fn = irods_fchown,
	.lchown_fn = irods_lchown,
	.chdir_fn = irods_chdir,
	.getwd_fn = irods_getwd,
	.ntimes_fn = irods_ntimes,
	.ftruncate_fn = irods_ftruncate,
	.fallocate_fn = irods_fallocate,
	.lock_fn = irods_lock,
	.kernel_flock_fn = irods_kernel_flock,
	.linux_setlease_fn = irods_linux_setlease,
	.getlock_fn = irods_getlock,
	.symlink_fn = irods_symlink,
	.readlink_fn = irods_vfs_readlink,
	.link_fn = irods_link,
	.mknod_fn = irods_mknod,
	.realpath_fn = irods_realpath,
	.chflags_fn = irods_chflags,
	.file_id_create_fn = irods_file_id_create,
	.offload_read_send_fn = irods_offload_read_send,
	.offload_read_recv_fn = irods_offload_read_recv,
	.offload_write_send_fn = irods_offload_write_send,
	.offload_write_recv_fn = irods_offload_write_recv,
	.get_compression_fn = irods_get_compression,
	.set_compression_fn = irods_set_compression,

	.streaminfo_fn = irods_streaminfo,
	.get_real_filename_fn = irods_get_real_filename,
	.connectpath_fn = irods_connectpath,
	.brl_lock_windows_fn = irods_brl_lock_windows,
	.brl_unlock_windows_fn = irods_brl_unlock_windows,
	.brl_cancel_windows_fn = irods_brl_cancel_windows,
	.strict_lock_check_fn = irods_strict_lock_check,
	.translate_name_fn = irods_translate_name,
	.fsctl_fn = irods_fsctl,
	.readdir_attr_fn = irods_readdir_attr,

	/* DOS attributes. */
	.get_dos_attributes_fn = irods_get_dos_attributes,
	.fget_dos_attributes_fn = irods_fget_dos_attributes,
	.set_dos_attributes_fn = irods_set_dos_attributes,
	.fset_dos_attributes_fn = irods_fset_dos_attributes,

	/* NT ACL operations. */

	.fget_nt_acl_fn = irods_fget_nt_acl,
	.get_nt_acl_fn = irods_get_nt_acl,
	.fset_nt_acl_fn = irods_fset_nt_acl,

	/* POSIX ACL operations. */

	.sys_acl_get_file_fn = irods_sys_acl_get_file,
	.sys_acl_get_fd_fn = irods_sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = irods_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = irods_sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = irods_sys_acl_set_file,
	.sys_acl_set_fd_fn = irods_sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = irods_sys_acl_delete_def_file,

	/* EA operations. */
	.getxattr_fn = irods_getxattr,
	.fgetxattr_fn = irods_fgetxattr,
	.listxattr_fn = irods_listxattr,
	.flistxattr_fn = irods_flistxattr,
	.removexattr_fn = irods_removexattr,
	.fremovexattr_fn = irods_fremovexattr,
	.setxattr_fn = irods_setxattr,
	.fsetxattr_fn = irods_fsetxattr,

	/* aio operations */
	.aio_force_fn = irods_aio_force,
};

static_decl_vfs;
NTSTATUS vfs_irods_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "irods", &irods_fns);
}
