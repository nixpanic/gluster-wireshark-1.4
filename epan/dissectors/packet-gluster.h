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
#include <rpc/xdr.h>

#define GLUSTER_PORT		24007
#define MIN_PACKET_SIZE		28	/* smallest packet */

/* from rpc/rpc-lib/src/rpcsvc.h */
#define RPCSVC_NAME_MAX		32
#define RPCSVC_MAX_AUTH_BYTES	400

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


/* from cli-rpc-ops.c

struct rpc_clnt_procedure gluster_cli_actors[GLUSTER_CLI_MAXVALUE] = {
        [GLUSTER_CLI_NULL]             = {"NULL", NULL },
        [GLUSTER_CLI_PROBE]            = {"PROBE_QUERY", gf_cli3_1_probe},
        [GLUSTER_CLI_DEPROBE]          = {"DEPROBE_QUERY", gf_cli3_1_deprobe},
        [GLUSTER_CLI_LIST_FRIENDS]     = {"LIST_FRIENDS", gf_cli3_1_list_friends},
        [GLUSTER_CLI_CREATE_VOLUME]    = {"CREATE_VOLUME", gf_cli3_1_create_volume},
        [GLUSTER_CLI_DELETE_VOLUME]    = {"DELETE_VOLUME", gf_cli3_1_delete_volume},
        [GLUSTER_CLI_START_VOLUME]     = {"START_VOLUME", gf_cli3_1_start_volume},
        [GLUSTER_CLI_STOP_VOLUME]      = {"STOP_VOLUME", gf_cli3_1_stop_volume},
        [GLUSTER_CLI_RENAME_VOLUME]    = {"RENAME_VOLUME", gf_cli3_1_rename_volume},
        [GLUSTER_CLI_DEFRAG_VOLUME]    = {"DEFRAG_VOLUME", gf_cli3_1_defrag_volume},
        [GLUSTER_CLI_GET_VOLUME]       = {"GET_VOLUME", gf_cli3_1_get_volume},
        [GLUSTER_CLI_GET_NEXT_VOLUME]  = {"GET_NEXT_VOLUME", gf_cli3_1_get_next_volume},
        [GLUSTER_CLI_SET_VOLUME]       = {"SET_VOLUME", gf_cli3_1_set_volume},
        [GLUSTER_CLI_ADD_BRICK]        = {"ADD_BRICK", gf_cli3_1_add_brick},
        [GLUSTER_CLI_REMOVE_BRICK]     = {"REMOVE_BRICK", gf_cli3_1_remove_brick},
        [GLUSTER_CLI_REPLACE_BRICK]    = {"REPLACE_BRICK", gf_cli3_1_replace_brick},
        [GLUSTER_CLI_LOG_FILENAME]     = {"LOG FILENAME", gf_cli3_1_log_filename},
        [GLUSTER_CLI_LOG_LOCATE]       = {"LOG LOCATE", gf_cli3_1_log_locate},
        [GLUSTER_CLI_LOG_ROTATE]       = {"LOG ROTATE", gf_cli3_1_log_rotate},
        [GLUSTER_CLI_GETSPEC]          = {"GETSPEC", gf_cli3_1_getspec},
        [GLUSTER_CLI_PMAP_PORTBYBRICK] = {"PMAP PORTBYBRICK", gf_cli3_1_pmap_b2p},
        [GLUSTER_CLI_SYNC_VOLUME]      = {"SYNC_VOLUME", gf_cli3_1_sync_volume},
        [GLUSTER_CLI_RESET_VOLUME]     = {"RESET_VOLUME", gf_cli3_1_reset_volume},
        [GLUSTER_CLI_FSM_LOG]          = {"FSM_LOG", gf_cli3_1_fsm_log},
        [GLUSTER_CLI_GSYNC_SET]        = {"GSYNC_SET", gf_cli3_1_gsync_set},
        [GLUSTER_CLI_PROFILE_VOLUME]   = {"PROFILE_VOLUME", gf_cli3_1_profile_volume},
        [GLUSTER_CLI_QUOTA]            = {"QUOTA", gf_cli3_1_quota},
        [GLUSTER_CLI_TOP_VOLUME]       = {"TOP_VOLUME", gf_cli3_1_top_volume},
        [GLUSTER_CLI_LOG_LEVEL]        = {"VOLUME_LOGLEVEL", gf_cli3_1_log_level},
        [GLUSTER_CLI_GETWD]            = {"GETWD", gf_cli3_1_getwd},
        [GLUSTER_CLI_STATUS_VOLUME]    = {"STATUS_VOLUME", gf_cli3_1_status_volume},
        [GLUSTER_CLI_MOUNT]            = {"MOUNT", gf_cli3_1_mount},
        [GLUSTER_CLI_UMOUNT]           = {"UMOUNT", gf_cli3_1_umount},
        [GLUSTER_CLI_HEAL_VOLUME]      = {"HEAL_VOLUME", gf_cli3_1_heal_volume},
        [GLUSTER_CLI_STATEDUMP_VOLUME] = {"STATEDUMP_VOLUME", gf_cli3_1_statedump_volume},
};
*/


enum gluster_msg_direction {
	CALL = 0,
	REPLY = 1,
	UNIVERSAL_ANSWER = 42,
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
	MOUNT_PROGRAM          = 100005,
	NFS_PROGRAM            = 100003,
};

/* if searching for a prognum/progversion, this matches any version */
#define GLUSTER_PROG_VERSION_ANY	-1

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


struct gluster_pkt_hdr {
	guint32 size;				/* size of the packet */
	gboolean last;				/* marker for the last packet */
	guint32 xid;				/* session id */
	enum gluster_msg_direction direction;
};
typedef struct gluster_pkt_hdr gluster_pkt_hdr_t;

struct gluster_rpc_hdr {
	guint32 rpcver;
	guint32 prognum;
	guint32 progver;
	guint32 procnum;
};
typedef struct gluster_rpc_hdr gluster_rpc_hdr_t;

struct gluster_proc {
	const gchar* procname;           /* user readable description */
	guint32 procnum;               /* procedure number */

	gboolean (*xdr_call)(XDR *xdr, gluster_pkt_hdr_t *hdr);	/* xdr decoding of a call */
	gboolean (*xdr_reply)(XDR *xdr, gluster_pkt_hdr_t *hdr);	/* xdr decoding of a reply */
};
typedef struct gluster_proc gluster_proc_t;

struct gluster_prog {
	const gchar progname[RPCSVC_NAME_MAX];  /* user readable description */
	guint32 prognum;                      /* program numner */
	guint32 progver;                      /* program version */

	gluster_proc_t *procs;            /* procedures of a program */
	unsigned int nr_procs;                 /* number of elements in *procs */
};
typedef struct gluster_prog gluster_prog_t;

#endif /* __PACKET_GLUSTER_H__ */
