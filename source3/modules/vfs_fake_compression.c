#include "includes.h"
#include "librpc/gen_ndr/ioctl.h"

//#undef DBGC_CLASS
//#define DBGC_CLASS DBGC_VFS

static uint32_t fake_fs_capabilities(struct vfs_handle_struct* _handle,
                                     enum timestamp_set_resolution* _ts_res)
{
    uint32_t fs_capabilities;
    enum timestamp_set_resolution ts_res;

    fs_capabilities = SMB_VFS_NEXT_FS_CAPABILITIES(_handle, &ts_res);
    fs_capabilities |= FILE_FILE_COMPRESSION;
    *_ts_res = ts_res;

    return fs_capabilities;
}

static NTSTATUS fake_get_compression(struct vfs_handle_struct* _handle,
                                     TALLOC_CTX* _mem_ctx,
                                     struct files_struct* _fsp,
                                     struct smb_filename* _smb_fname,
                                     uint16_t* _compression_fmt)
{
    *_compression_fmt = COMPRESSION_FORMAT_NONE;
    return NT_STATUS_OK;
}

static NTSTATUS fake_set_compression(struct vfs_handle_struct* _handle,
                                     TALLOC_CTX* _mem_ctx,
                                     struct files_struct* _fsp,
                                     uint16_t _compression_fmt)
{
    NTSTATUS status;

    if ((_fsp == NULL) || (_fsp->fh->fd == -1))
    {
        status = NT_STATUS_INVALID_PARAMETER;
        goto err_out;
    }

    status = NT_STATUS_OK;

err_out:
    return status;
}

static struct vfs_fn_pointers fake_compression_fns = {
    .fs_capabilities_fn = fake_fs_capabilities,
    .get_compression_fn = fake_get_compression,
    .set_compression_fn = fake_set_compression
};

static_decl_vfs;
NTSTATUS vfs_fake_compression_init(TALLOC_CTX* _ctx)
{
    return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
                            "fake_compression",
                            &fake_compression_fns);
}
