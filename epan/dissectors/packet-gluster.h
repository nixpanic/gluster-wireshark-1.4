/* packet-gluster.h
 *
 * Copyright (c) 2011 Niels de Vos <ndevos@redhat.com>, Red Hat UK, Ltd.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_GLUSTER_H__
#define __PACKET_GLUSTER_H__

#include <glib.h>

#define GLUSTER_PORT		24007

/* this comes from rpc/rpc-lib/src/protocol-common.h
 * TODO: use libglusterfs-devel
 *
 * #include <gluster/rpc-lib/protocol-common.h>>
 */

enum gf_mgmt_procnum_ {
        GD_MGMT_NULL,    /* 0 */
        GD_MGMT_PROBE_QUERY,
        GD_MGMT_FRIEND_ADD,
        GD_MGMT_CLUSTER_LOCK,
        GD_MGMT_CLUSTER_UNLOCK,
        GD_MGMT_STAGE_OP,
        GD_MGMT_COMMIT_OP,
        GD_MGMT_FRIEND_REMOVE,
        GD_MGMT_FRIEND_UPDATE,
        GD_MGMT_CLI_PROBE,
        GD_MGMT_CLI_DEPROBE,
        GD_MGMT_CLI_LIST_FRIENDS,
        GD_MGMT_CLI_CREATE_VOLUME,
        GD_MGMT_CLI_GET_VOLUME,
        GD_MGMT_CLI_DELETE_VOLUME,
        GD_MGMT_CLI_START_VOLUME,
        GD_MGMT_CLI_STOP_VOLUME,
        GD_MGMT_CLI_RENAME_VOLUME,
        GD_MGMT_CLI_DEFRAG_VOLUME,
        GD_MGMT_CLI_SET_VOLUME,
        GD_MGMT_CLI_ADD_BRICK,
        GD_MGMT_CLI_REMOVE_BRICK,
        GD_MGMT_CLI_REPLACE_BRICK,
        GD_MGMT_CLI_LOG_FILENAME,
        GD_MGMT_CLI_LOG_LOCATE,
        GD_MGMT_CLI_LOG_ROTATE,
        GD_MGMT_CLI_SYNC_VOLUME,
        GD_MGMT_CLI_RESET_VOLUME,
        GD_MGMT_CLI_FSM_LOG,
        GD_MGMT_CLI_GSYNC_SET,
        GD_MGMT_CLI_PROFILE_VOLUME,
        GD_MGMT_BRICK_OP,
        GD_MGMT_CLI_LOG_LEVEL,
        GD_MGMT_CLI_STATUS_VOLUME,
        GD_MGMT_MAXVALUE,
};
typedef enum gf_mgmt_procnum_ gf_mgmt_procnum;


enum gluster_cli_procnum {
        GLUSTER_CLI_NULL,    /* 0 */
        GLUSTER_CLI_PROBE,
        GLUSTER_CLI_DEPROBE,
        GLUSTER_CLI_LIST_FRIENDS,
        GLUSTER_CLI_CREATE_VOLUME,
        GLUSTER_CLI_GET_VOLUME,
        GLUSTER_CLI_GET_NEXT_VOLUME,
        GLUSTER_CLI_DELETE_VOLUME,
        GLUSTER_CLI_START_VOLUME,
        GLUSTER_CLI_STOP_VOLUME,
        GLUSTER_CLI_RENAME_VOLUME,
        GLUSTER_CLI_DEFRAG_VOLUME,
        GLUSTER_CLI_SET_VOLUME,
        GLUSTER_CLI_ADD_BRICK,
        GLUSTER_CLI_REMOVE_BRICK,
        GLUSTER_CLI_REPLACE_BRICK,
        GLUSTER_CLI_LOG_FILENAME,
        GLUSTER_CLI_LOG_LOCATE,
        GLUSTER_CLI_LOG_ROTATE,
        GLUSTER_CLI_GETSPEC,
        GLUSTER_CLI_PMAP_PORTBYBRICK,
        GLUSTER_CLI_SYNC_VOLUME,
        GLUSTER_CLI_RESET_VOLUME,
        GLUSTER_CLI_FSM_LOG,
        GLUSTER_CLI_GSYNC_SET,
        GLUSTER_CLI_PROFILE_VOLUME,
        GLUSTER_CLI_QUOTA,
        GLUSTER_CLI_TOP_VOLUME,
        GLUSTER_CLI_GETWD,
        GLUSTER_CLI_LOG_LEVEL,
        GLUSTER_CLI_STATUS_VOLUME,
        GLUSTER_CLI_MOUNT,
        GLUSTER_CLI_UMOUNT,
        GLUSTER_CLI_HEAL_VOLUME,
        GLUSTER_CLI_STATEDUMP_VOLUME,
        GLUSTER_CLI_MAXVALUE,
};

/* numbers are spread over a load of files */
enum gluster_prognums {
	GD_MGMT_PROGRAM        = 1238433,
	GLUSTER3_1_FOP_PROGRAM = 1298437,
	GLUSTER_CBK_PROGRAM    = 52743234,
	GLUSTER_CLI_PROGRAM    = 1238463,
	GLUSTERD1_MGMT_PROGRAM = 1298433,
	GLUSTER_DUMP_PROGRAM   = 123451501,
	GLUSTERFS_PROGRAM      = 4867634,
	GLUSTER_HNDSK_PROGRAM  = 14398633,
	GLUSTER_PMAP_PROGRAM   = 34123456,
};

/* rpc/rpc-lib/src/xdr-common.h:gf_dump_procnum
 * gf_dump_procnum does not contain a 0-value */
enum gluster_prog_dump_procs {
	GF_DUMP_NULL /* = 0 */,
	GF_DUMP_DUMP,
	GF_DUMP_MAXVALUE,
};

enum glusterd_mgmt_procnum {
	GLUSTERD_MGMT_NULL,    /* 0 */ 
	GLUSTERD_MGMT_PROBE_QUERY,
	GLUSTERD_MGMT_FRIEND_ADD,
	GLUSTERD_MGMT_CLUSTER_LOCK,
	GLUSTERD_MGMT_CLUSTER_UNLOCK,
	GLUSTERD_MGMT_STAGE_OP,
	GLUSTERD_MGMT_COMMIT_OP,
	GLUSTERD_MGMT_FRIEND_REMOVE,
	GLUSTERD_MGMT_FRIEND_UPDATE,
	GLUSTERD_MGMT_MAXVALUE,
};

/* rpc/rpc-lib/src/protocol-common.h */
enum gf_brick_procnum {
	GF_BRICK_NULL = 0,
	GF_BRICK_TERMINATE = 1,
	GF_BRICK_XLATOR_INFO = 2,
	GF_BRICK_XLATOR_HEAL = 3,
	GF_BRICK_MAXVALUE
};

enum gluster_prog_hndsk_procs {
	GF_HNDSK_NULL,
	GF_HNDSK_SETVOLUME,
	GF_HNDSK_GETSPEC,
	GF_HNDSK_PING,
	GF_HNDSK_MAXVALUE,
};

/* rpc/rpc-lib/src/protocol-common.h */
enum gf_pmap_procnum {
	GF_PMAP_NULL = 0,
	GF_PMAP_PORTBYBRICK,
	GF_PMAP_BRICKBYPORT,
	GF_PMAP_SIGNUP,
	GF_PMAP_SIGNIN,
	GF_PMAP_SIGNOUT,
	GF_PMAP_MAXVALUE,
};

#endif /* __PACKET_GLUSTER_H__ */
