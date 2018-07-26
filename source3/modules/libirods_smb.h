#ifndef LIB_IRODS_SMB_HPP
#define LIB_IRODS_SMB_HPP

#include <irods/rodsClient.h>

typedef int error_code;

typedef struct _irods_context
{
    rodsEnv env;
    rcComm_t* conn;
} irods_context;

typedef struct _irods_stat_info
{
    int inode;
    int dev_id;
    int rdev_id;
    long mode;
} irods_stat_info;

#ifdef __cplusplus
extern "C" {
#endif

error_code ismb_test(void);

error_code ismb_connect(irods_context* _ctx);

error_code ismb_disconnect(irods_context* _ctx);

error_code ismb_stat_path(irods_context* _ctx, const char* _path);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // LIB_IRODS_SMB_HPP

