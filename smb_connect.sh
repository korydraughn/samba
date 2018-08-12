#! /bin/bash

# This command assumes the user has the following share
# defined in their samba server config file.
#
# The [path] option points to a location that does not exist
# in the file system.  It's just needed for the server to boot.
#
# etc/smb.conf
# ~~~~~~~~~~~~
# [irods_smb]
#     comment = iRODS SMB/VFS Test
#     path = /irods
#     browseable = yes
#     read only = yes
#     vfs objects = irods
#     public = yes
#     only guest = yes

clear && ./smbclient -U kory //localhost/irods_smb
