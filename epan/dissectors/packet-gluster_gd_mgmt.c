/* packet-gluster_gd_mgmt.c
 * Routines for Gluster Daemon Management dissection
 * Copyright 2012, Niels de Vos <ndevos@redhat.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 *
 *
 * References to source files point in general to the glusterfs sources.
 * There is currently no RFC or other document where the protocol is
 * completely described. The glusterfs sources can be found at:
 * - http://git.gluster.com/?p=glusterfs.git
 * - https://github.com/gluster/glusterfs
 *
 * The coding-style is roughly the same as the one use in the Linux kernel,
 * see http://www.kernel.org/doc/Documentation/CodingStyle.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/tfs.h>

#include "packet-rpc.h"
#include "packet-gluster.h"

/* Initialize the protocol and registered fields */
static gint proto_gd_mgmt = -1;

/* programs and procedures */
static gint hf_gd_mgmt_proc = -1;
static gint hf_gd_mgmt_2_proc = -1;

/* fields used by multiple programs/procedures */
static gint hf_gluster_op_errstr = -1;
static gint hf_gluster_uuid = -1;
static gint hf_gluster_hostname = -1;
static gint hf_gluster_port = -1;
static gint hf_gluster_vols = -1;
static gint hf_gluster_buf = -1;
static gint hf_gluster_op_errno = -1;

/* Initialize the subtree pointers */
static gint ett_gd_mgmt = -1;

static int
gluster_gd_mgmt_probe_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *hostname = NULL;

	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset, &hostname);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);

	return offset;
}

static int
gluster_gd_mgmt_probe_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *hostname = NULL;

	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset, &hostname);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);

	return offset;
}

static int
gluster_gd_mgmt_friend_add_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *hostname = NULL;

	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset, &hostname);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);

	return offset;
}

static int
gluster_gd_mgmt_friend_add_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *hostname = NULL;

	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset, &hostname);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_vols, offset);

	return offset;
}

/* gluster_gd_mgmt_cluster_lock_reply is used for LOCK and UNLOCK */
static int
gluster_gd_mgmt_cluster_lock_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);

	return offset;
}

/* gluster_gd_mgmt_cluster_lock_call is used for LOCK and UNLOCK */
static int
gluster_gd_mgmt_cluster_lock_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);

	return offset;
}

static int
gluster_gd_mgmt_stage_op_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *errstr = NULL;

	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_op_errstr, offset, &errstr);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);
	return offset;
}

static int
gluster_gd_mgmt_stage_op_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);

	return offset;
}

static int
gluster_gd_mgmt_commit_op_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *errstr = NULL;

	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_buf, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_op_errstr, offset, &errstr);
	return offset;
}

static int
gluster_gd_mgmt_commit_op_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_buf, offset);

	return offset;
}

static int
gluster_gd_mgmt_friend_update_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);

	return offset;
}

static int
gluster_gd_mgmt_friend_update_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_vols, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);

	return offset;
}

/* Below procedure is used for version 2 */
static int
glusterd_mgmt_2_cluster_lock_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);

	return offset;
}

/* glusterd__mgmt_2_cluster_lock_call is used for LOCK and UNLOCK */
static int
glusterd_mgmt_2_cluster_lock_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);

	return offset;
}

static int
glusterd_mgmt_2_stage_op_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *errstr = NULL;

	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_op_errstr, offset, &errstr);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);

	return offset;
}

static int
glusterd_mgmt_2_stage_op_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);

	return offset;
}

static int
glusterd_mgmt_2_commit_op_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *errstr = NULL;

	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_buf, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_op_errstr, offset, &errstr);

	return offset;
}

static int
glusterd_mgmt_2_commit_op_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_buf, offset);

	return offset;
}


/*
 * GD_MGMT_PROGRAM
 * - xlators/mgmt/glusterd/src/glusterd-handler.c: "GlusterD svc mgmt"
 * - xlators/mgmt/glusterd/src/glusterd-rpc-ops.c: "glusterd clnt mgmt"
 */
static const vsff gd_mgmt_proc[] = {
	{ GD_MGMT_NULL, "NULL", NULL, NULL},
	{
		GD_MGMT_PROBE_QUERY, "GD_MGMT_PROBE_QUERY",
		gluster_gd_mgmt_probe_call, gluster_gd_mgmt_probe_reply
	},
	{
		GD_MGMT_FRIEND_ADD, "GD_MGMT_FRIEND_ADD",
		gluster_gd_mgmt_friend_add_call, gluster_gd_mgmt_friend_add_reply
	},
	{
		GD_MGMT_CLUSTER_LOCK, "GD_MGMT_CLUSTER_LOCK",
		gluster_gd_mgmt_cluster_lock_call, gluster_gd_mgmt_cluster_lock_reply
	},
	{
		GD_MGMT_CLUSTER_UNLOCK, "GD_MGMT_CLUSTER_UNLOCK",
		/* UNLOCK seems to be the same a LOCK, re-use the function */
		gluster_gd_mgmt_cluster_lock_call, gluster_gd_mgmt_cluster_lock_reply
	},
	{
		GD_MGMT_STAGE_OP, "GD_MGMT_STAGE_OP",
		gluster_gd_mgmt_stage_op_call, gluster_gd_mgmt_stage_op_reply
	},
	{
		GD_MGMT_COMMIT_OP, "GD_MGMT_COMMIT_OP",
		gluster_gd_mgmt_commit_op_call, gluster_gd_mgmt_commit_op_reply
	},
	{ GD_MGMT_FRIEND_REMOVE, "GD_MGMT_FRIEND_REMOVE", NULL, NULL},
	{
		GD_MGMT_FRIEND_UPDATE, "GD_MGMT_FRIEND_UPDATE",
		gluster_gd_mgmt_friend_update_call, gluster_gd_mgmt_friend_update_reply
	},
	{ GD_MGMT_CLI_PROBE, "GD_MGMT_CLI_PROBE", NULL, NULL},
	{ GD_MGMT_CLI_DEPROBE, "GD_MGMT_CLI_DEPROBE", NULL, NULL},
	{ GD_MGMT_CLI_LIST_FRIENDS, "GD_MGMT_CLI_LIST_FRIENDS", NULL, NULL},
	{ GD_MGMT_CLI_CREATE_VOLUME, "GD_MGMT_CLI_CREATE_VOLUME", NULL, NULL},
	{ GD_MGMT_CLI_GET_VOLUME, "GD_MGMT_CLI_GET_VOLUME", NULL, NULL},
	{ GD_MGMT_CLI_DELETE_VOLUME, "GD_MGMT_CLI_DELETE_VOLUME", NULL, NULL},
	{ GD_MGMT_CLI_START_VOLUME, "GD_MGMT_CLI_START_VOLUME", NULL, NULL},
	{ GD_MGMT_CLI_STOP_VOLUME, "GD_MGMT_CLI_STOP_VOLUME", NULL, NULL},
	{ GD_MGMT_CLI_RENAME_VOLUME, "GD_MGMT_CLI_RENAME_VOLUME", NULL, NULL},
	{ GD_MGMT_CLI_DEFRAG_VOLUME, "GD_MGMT_CLI_DEFRAG_VOLUME", NULL, NULL},
	{ GD_MGMT_CLI_SET_VOLUME, "GD_MGMT_CLI_DEFRAG_VOLUME", NULL, NULL},
	{ GD_MGMT_CLI_ADD_BRICK, "GD_MGMT_CLI_ADD_BRICK", NULL, NULL},
	{ GD_MGMT_CLI_REMOVE_BRICK, "GD_MGMT_CLI_REMOVE_BRICK", NULL, NULL},
	{ GD_MGMT_CLI_REPLACE_BRICK, "GD_MGMT_CLI_REPLACE_BRICK", NULL, NULL},
	{ GD_MGMT_CLI_LOG_FILENAME, "GD_MGMT_CLI_LOG_FILENAME", NULL, NULL},
	{ GD_MGMT_CLI_LOG_LOCATE, "GD_MGMT_CLI_LOG_LOCATE", NULL, NULL},
	{ GD_MGMT_CLI_LOG_ROTATE, "GD_MGMT_CLI_LOG_ROTATE", NULL, NULL},
	{ GD_MGMT_CLI_SYNC_VOLUME, "GD_MGMT_CLI_SYNC_VOLUME", NULL, NULL},
	{ GD_MGMT_CLI_RESET_VOLUME, "GD_MGMT_CLI_RESET_VOLUME", NULL, NULL},
	{ GD_MGMT_CLI_FSM_LOG, "GD_MGMT_CLI_FSM_LOG", NULL, NULL},
	{ GD_MGMT_CLI_GSYNC_SET, "GD_MGMT_CLI_GSYNC_SET", NULL, NULL},
	{ GD_MGMT_CLI_PROFILE_VOLUME, "GD_MGMT_CLI_PROFILE_VOLUME", NULL, NULL},
	{ GD_MGMT_BRICK_OP, "BRICK_OP", NULL, NULL},
	{ GD_MGMT_CLI_LOG_LEVEL, "GD_MGMT_CLI_LOG_LEVEL", NULL, NULL},
	{ GD_MGMT_CLI_STATUS_VOLUME, "GD_MGMT_CLI_STATUS_VOLUME", NULL, NULL},
	{ GD_MGMT_MAXVALUE, "GD_MGMT_MAXVALUE", NULL, NULL},
	{ 0, NULL, NULL, NULL}
};

static const vsff gd_mgmt_2_proc[] = {
	{ GLUSTERD_MGMT_2_NULL, "NULL", NULL, NULL},
	{
		GLUSTERD_MGMT_2_CLUSTER_LOCK, "GD_MGMT_CLUSTER_LOCK",
		glusterd_mgmt_2_cluster_lock_call, glusterd_mgmt_2_cluster_lock_reply
	},
	{
		GLUSTERD_MGMT_2_CLUSTER_UNLOCK, "GD_MGMT_CLUSTER_UNLOCK",
		/* UNLOCK seems to be the same a LOCK, re-use the function */
		glusterd_mgmt_2_cluster_lock_call, glusterd_mgmt_2_cluster_lock_reply
	},
	{
		GLUSTERD_MGMT_2_STAGE_OP, "GD_MGMT_STAGE_OP",
		gluster_gd_mgmt_stage_op_call, gluster_gd_mgmt_stage_op_reply
	},
	{
		GLUSTERD_MGMT_2_COMMIT_OP, "GD_MGMT_COMMIT_OP",
		gluster_gd_mgmt_commit_op_call, gluster_gd_mgmt_commit_op_reply
	},
	{ GLUSTERD_MGMT_2_MAXVALUE, "GD_MGMT_MAXVALUE", NULL, NULL},
	{ 0, NULL, NULL, NULL}
};

static const value_string gd_mgmt_proc_vals[] = {
	{ GD_MGMT_NULL, "NULL" },
	{ GD_MGMT_PROBE_QUERY, "GD_MGMT_PROBE_QUERY" },
	{ GD_MGMT_FRIEND_ADD, "GD_MGMT_FRIEND_ADD" },
	{ GD_MGMT_CLUSTER_LOCK, "GD_MGMT_CLUSTER_LOCK" },
	{ GD_MGMT_CLUSTER_UNLOCK, "GD_MGMT_CLUSTER_UNLOCK" },
	{ GD_MGMT_STAGE_OP, "GD_MGMT_STAGE_OP" },
	{ GD_MGMT_COMMIT_OP, "GD_MGMT_COMMIT_OP" },
	{ GD_MGMT_FRIEND_REMOVE, "GD_MGMT_FRIEND_REMOVE" },
	{ GD_MGMT_FRIEND_UPDATE, "GD_MGMT_FRIEND_UPDATE" },
	{ GD_MGMT_CLI_PROBE, "GD_MGMT_CLI_PROBE" },
	{ GD_MGMT_CLI_DEPROBE, "GD_MGMT_CLI_DEPROBE" },
	{ GD_MGMT_CLI_LIST_FRIENDS, "GD_MGMT_CLI_LIST_FRIENDS" },
	{ GD_MGMT_CLI_CREATE_VOLUME, "GD_MGMT_CLI_CREATE_VOLUME" },
	{ GD_MGMT_CLI_GET_VOLUME, "GD_MGMT_CLI_GET_VOLUME" },
	{ GD_MGMT_CLI_DELETE_VOLUME, "GD_MGMT_CLI_DELETE_VOLUME" },
	{ GD_MGMT_CLI_START_VOLUME, "GD_MGMT_CLI_START_VOLUME" },
	{ GD_MGMT_CLI_STOP_VOLUME, "GD_MGMT_CLI_STOP_VOLUME" },
	{ GD_MGMT_CLI_RENAME_VOLUME, "GD_MGMT_CLI_RENAME_VOLUME" },
	{ GD_MGMT_CLI_DEFRAG_VOLUME, "GD_MGMT_CLI_DEFRAG_VOLUME" },
	{ GD_MGMT_CLI_SET_VOLUME, "GD_MGMT_CLI_DEFRAG_VOLUME" },
	{ GD_MGMT_CLI_ADD_BRICK, "GD_MGMT_CLI_ADD_BRICK" },
	{ GD_MGMT_CLI_REMOVE_BRICK, "GD_MGMT_CLI_REMOVE_BRICK" },
	{ GD_MGMT_CLI_REPLACE_BRICK, "GD_MGMT_CLI_REPLACE_BRICK" },
	{ GD_MGMT_CLI_LOG_FILENAME, "GD_MGMT_CLI_LOG_FILENAME" },
	{ GD_MGMT_CLI_LOG_LOCATE, "GD_MGMT_CLI_LOG_LOCATE" },
	{ GD_MGMT_CLI_LOG_ROTATE, "GD_MGMT_CLI_LOG_ROTATE" },
	{ GD_MGMT_CLI_SYNC_VOLUME, "GD_MGMT_CLI_SYNC_VOLUME" },
	{ GD_MGMT_CLI_RESET_VOLUME, "GD_MGMT_CLI_RESET_VOLUME" },
	{ GD_MGMT_CLI_FSM_LOG, "GD_MGMT_CLI_FSM_LOG" },
	{ GD_MGMT_CLI_GSYNC_SET, "GD_MGMT_CLI_GSYNC_SET" },
	{ GD_MGMT_CLI_PROFILE_VOLUME, "GD_MGMT_CLI_PROFILE_VOLUME" },
	{ GD_MGMT_BRICK_OP, "BRICK_OP" },
	{ GD_MGMT_CLI_LOG_LEVEL, "GD_MGMT_CLI_LOG_LEVEL" },
	{ GD_MGMT_CLI_STATUS_VOLUME, "GD_MGMT_CLI_STATUS_VOLUME" },
	{ GD_MGMT_MAXVALUE, "GD_MGMT_MAXVALUE" },
	{ 0, NULL }
};

static const value_string gd_mgmt_2_proc_vals[] = {
	{ GLUSTERD_MGMT_2_NULL , "GLUSTERD_MGMT_NULL" },
	{ GLUSTERD_MGMT_2_CLUSTER_LOCK, "GLUSTERD_MGMT_CLUSTER_LOCK" },
	{ GLUSTERD_MGMT_2_CLUSTER_UNLOCK, "GLUSTERD_MGMT_CLUSTER_UNLOCK" },
	{ GLUSTERD_MGMT_2_STAGE_OP, "GLUSTERD_MGMT_STAGE_OP"},
	{ GLUSTERD_MGMT_2_COMMIT_OP, " GLUSTERD_MGMT_COMMIT_OP"},
	{ GLUSTERD_MGMT_2_MAXVALUE, "GLUSTERD_MGMT_MAXVALUE" },
	{ 0, NULL }
};

void
proto_register_gluster_gd_mgmt(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		/* programs */
		{ &hf_gd_mgmt_proc,
			{ "Gluster Daemon Management", "glusterd.mgmt",
				FT_UINT32, BASE_DEC, VALS(gd_mgmt_proc_vals),
				0, NULL, HFILL }
		},
		{ &hf_gd_mgmt_2_proc,
			{ "Gluster Daemon Management", "glusterd.mgmt",
				FT_UINT32, BASE_DEC, VALS(gd_mgmt_2_proc_vals),
				0, NULL, HFILL }
		},
		{ &hf_gluster_op_errstr,
			{ "Error String", "gluster.op_errstr", FT_STRING,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_uuid,
			{ "UUID", "gluster.uuid", FT_BYTES,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_hostname,
			{ "Hostname", "gluster.hostname", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_port,
			{ "Port", "gluster.port", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_vols,
			{ "Volumes", "gluster.vols", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_buf,
			{ "Buffer", "gluster.buffer", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_op_errno,
			{ "Errno", "gluster.op_errno", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_gd_mgmt
	};

	/* Register the protocol name and description */
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_gluster, hf, array_length(hf));

	proto_gd_mgmt = proto_register_protocol("Gluster Daemon Management",
					"GlusterD Management", "gd-mgmt");
}

void
proto_reg_handoff_gluster_gd_mgmt(void)
{
	rpc_init_prog(proto_gd_mgmt, GD_MGMT_PROGRAM, ett_gd_mgmt);
	rpc_init_proc_table(GD_MGMT_PROGRAM, 1, gd_mgmt_proc, hf_gd_mgmt_proc);
	rpc_init_proc_table(GD_MGMT_PROGRAM, 2, gd_mgmt_2_proc, hf_gd_mgmt_2_proc);

}

