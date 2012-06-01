/* packet-gluster_glusterd.c
 * Routines for Gluster Daemon Management dissection
 * Copyright 2012, Niels de Vos <ndevos@redhat.com>
 * With contributions from:
 *    Shreedhara LG <shreedharlg@gmail.com>
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
static gint proto_glusterd = -1;
static gint proto_gd_mgmt = -1;
static gint proto_gd_brick = -1;
static gint proto_gd_friend = -1;

/* programs and procedures */
static gint hf_gd_mgmt_proc = -1;
static gint hf_gd_mgmt_2_proc = -1;
static gint hf_gd_mgmt_brick_2_proc = -1;
static gint hf_glusterd_friend_proc = -1;

/* fields used by multiple programs/procedures */
static gint hf_gluster_dict = -1;
static gint hf_gluster_op = -1;
static gint hf_gluster_op_errstr = -1;
static gint hf_gluster_uuid = -1;
static gint hf_gluster_hostname = -1;
static gint hf_gluster_port = -1;
static gint hf_gluster_vols = -1;
static gint hf_gluster_buf = -1;
static gint hf_gluster_name = -1;

/* Initialize the subtree pointers */
static gint ett_gd_mgmt = -1;
static gint ett_gd_brick = -1;
static gint ett_gd_friend = -1;
/* the UUID is the same as a GlusterFS GFID, except its encoded per byte */
static int
gluster_gd_mgmt_dissect_uuid(tvbuff_t *tvb, proto_tree *tree, int hfindex, int offset)
{
	if (tree) {
		proto_item *gfid_item;
		header_field_info *hfinfo = proto_registrar_get_nth(hfindex);
		gfid_item = proto_tree_add_text(tree, tvb, offset, 16 * 4, "%s: ", hfinfo->name);

		/* 4 bytes */
		proto_item_append_text(gfid_item, "%.2x", tvb_get_ntohl(tvb, offset));
		offset += 4;
		proto_item_append_text(gfid_item, "%.2x", tvb_get_ntohl(tvb, offset));
		offset += 4;
		proto_item_append_text(gfid_item, "%.2x", tvb_get_ntohl(tvb, offset));
		offset += 4;
		proto_item_append_text(gfid_item, "%.2x", tvb_get_ntohl(tvb, offset));
		offset += 4;
		/* 2 bytes */
		proto_item_append_text(gfid_item, "-%.2x", tvb_get_ntohl(tvb, offset));
		offset += 4;
		proto_item_append_text(gfid_item, "%.2x", tvb_get_ntohl(tvb, offset));
		offset += 4;
		/* 2 bytes */
		proto_item_append_text(gfid_item, "-%.2x", tvb_get_ntohl(tvb, offset));
		offset += 4;
		proto_item_append_text(gfid_item, "%.2x", tvb_get_ntohl(tvb, offset));
		offset += 4;
		/* 2 bytes */
		proto_item_append_text(gfid_item, "-%.2x", tvb_get_ntohl(tvb, offset));
		offset += 4;
		proto_item_append_text(gfid_item, "%.2x", tvb_get_ntohl(tvb, offset));
		offset += 4;
		/* 6 bytes */
		proto_item_append_text(gfid_item, "-%.2x", tvb_get_ntohl(tvb, offset));
		offset += 4;
		proto_item_append_text(gfid_item, "%.2x", tvb_get_ntohl(tvb, offset));
		offset += 4;
		proto_item_append_text(gfid_item, "%.2x", tvb_get_ntohl(tvb, offset));
		offset += 4;
		proto_item_append_text(gfid_item, "%.2x", tvb_get_ntohl(tvb, offset));
		offset += 4;
		proto_item_append_text(gfid_item, "%.2x", tvb_get_ntohl(tvb, offset));
		offset += 4;
		proto_item_append_text(gfid_item, "%.2x", tvb_get_ntohl(tvb, offset));
		offset += 4;
	} else
		offset += 16 * 4;

	return offset;
}

static int
gluster_gd_mgmt_probe_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	gchar *hostname = NULL;

	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset, &hostname);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);

	return offset;
}

static int
gluster_gd_mgmt_probe_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *hostname = NULL;

	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset, &hostname);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);

	return offset;
}

static int
gluster_gd_mgmt_friend_add_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	gchar *hostname = NULL;

	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset, &hostname);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);

	return offset;
}

static int
gluster_gd_mgmt_friend_add_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *hostname = NULL;

	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset, &hostname);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_vols, offset);

	return offset;
}

/* gluster_gd_mgmt_cluster_lock_reply is used for LOCK and UNLOCK */
static int
gluster_gd_mgmt_cluster_lock_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);

	return offset;
}

/* gluster_gd_mgmt_cluster_lock_call is used for LOCK and UNLOCK */
static int
gluster_gd_mgmt_cluster_lock_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);

	return offset;
}

static int
gluster_gd_mgmt_stage_op_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	gchar *errstr = NULL;

	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_op_errstr, offset, &errstr);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);
	return offset;
}

static int
gluster_gd_mgmt_stage_op_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);

	return offset;
}

static int
gluster_gd_mgmt_commit_op_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	gchar *errstr = NULL;

	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_buf, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_op_errstr, offset, &errstr);
	return offset;
}

static int
gluster_gd_mgmt_commit_op_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_buf, offset);

	return offset;
}

static int
gluster_gd_mgmt_friend_update_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);

	return offset;
}

static int
gluster_gd_mgmt_friend_update_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_vols, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);

	return offset;
}

/* Below procedure is used for version 2 */
static int
glusterd_mgmt_2_cluster_lock_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);

	return offset;
}

/* glusterd__mgmt_2_cluster_lock_call is used for LOCK and UNLOCK */
static int
glusterd_mgmt_2_cluster_lock_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);

	return offset;
}

static int
glusterd_mgmt_2_stage_op_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	gchar *errstr = NULL;

	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_op_errstr, offset, &errstr);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);

	return offset;
}

static int
glusterd_mgmt_2_stage_op_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);

	return offset;
}

static int
glusterd_mgmt_2_commit_op_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	gchar *errstr = NULL;

	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_buf, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_op_errstr, offset, &errstr);

	return offset;
}

static int
glusterd_mgmt_2_commit_op_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = gluster_gd_mgmt_dissect_uuid(tvb, tree, hf_gluster_uuid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_buf, offset);

	return offset;
}

/* Brick management common function */

static int
glusterd_brick_2_common_reply(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	gchar *errstr = NULL;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_op_errstr, offset, &errstr);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);

	return offset;
}

static int
glusterd_brick_2_common_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *name = NULL;

	offset = dissect_rpc_string(tvb, tree, hf_gluster_name, offset, &name);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);

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
		glusterd_mgmt_2_stage_op_call, glusterd_mgmt_2_stage_op_reply
	},
	{
		GLUSTERD_MGMT_2_COMMIT_OP, "GD_MGMT_COMMIT_OP",
		glusterd_mgmt_2_commit_op_call, glusterd_mgmt_2_commit_op_reply
	},
	{ GLUSTERD_MGMT_2_MAXVALUE, "GD_MGMT_MAXVALUE", NULL, NULL},
	{ 0, NULL, NULL, NULL}
};

static const vsff gd_mgmt_brick_2_proc[] = {
	{ GLUSTERD_2_BRICK_NULL, "GLUSTERD_2_BRICK_NULL", NULL , NULL },    /* 0 */
	{
		GLUSTERD_2_BRICK_TERMINATE, "GLUSTERD_2_BRICK_TERMINATE",
		glusterd_brick_2_common_call, glusterd_brick_2_common_reply
	},
        {
		GLUSTERD_2_BRICK_XLATOR_INFO, "GLUSTERD_2_BRICK_XLATOR_INFO",
 		glusterd_brick_2_common_call, glusterd_brick_2_common_reply
	},
        {
		GLUSTERD_2_BRICK_XLATOR_OP, "GLUSTERD_2_BRICK_XLATOR_OP" ,
		glusterd_brick_2_common_call, glusterd_brick_2_common_reply
	},
        {
		GLUSTERD_2_BRICK_STATUS, "GLUSTERD_2_BRICK_STATUS",
		glusterd_brick_2_common_call, glusterd_brick_2_common_reply
	},
        {
		GLUSTERD_2_BRICK_OP, "GLUSTERD_2_BRICK_OP",
		glusterd_brick_2_common_call, glusterd_brick_2_common_reply
	},
        {
		GLUSTERD_2_BRICK_XLATOR_DEFRAG, "GLUSTERD_2_BRICK_XLATOR_DEFRAG",
		glusterd_brick_2_common_call, glusterd_brick_2_common_reply
	},
        {
		GLUSTERD_2_NODE_PROFILE, "GLUSTERD_2_NODE_PROFILE",
		glusterd_brick_2_common_call, glusterd_brick_2_common_reply
	},
        {
		GLUSTERD_2_NODE_STATUS, "GLUSTERD_2_NODE_PROFILE",
		glusterd_brick_2_common_call, glusterd_brick_2_common_reply
	},
        { GLUSTERD_2_BRICK_MAXVALUE, "GLUSTERD_2_BRICK_MAXVALUE", NULL, NULL },
        { 0, NULL, NULL, NULL }
};

static const vsff glusterd_friend_proc[] = {
	{ GLUSTERD_FRIEND_NULL,"NULL" , NULL,NULL },
	{ GLUSTERD_PROBE_QUERY, "GLUSTERD_PROBE_QUERY" , NULL , NULL },
	{ GLUSTERD_FRIEND_ADD, "GLUSTERD_FRIEND_ADD" , NULL , NULL },
	{ GLUSTERD_FRIEND_REMOVE,"GLUSTERD_FRIEND_REMOVE", NULL , NULL },
	{ GLUSTERD_FRIEND_UPDATE,"GLUSTERD_FRIEND_UPDATE" , NULL , NULL },
	{ GLUSTERD_FRIEND_MAXVALUE,"GLUSTERD_FRIEND_MAXVALUE", NULL , NULL },
	{ 0, NULL, NULL, NULL }
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

static const value_string gd_mgmt_brick_2_proc_vals[] = {
	{ GLUSTERD_2_BRICK_NULL,"GLUSTERD_2_BRICK_NULL" },    /* 0 */
	{ GLUSTERD_2_BRICK_TERMINATE, "GLUSTERD_2_BRICK_TERMINATE" },
	{ GLUSTERD_2_BRICK_XLATOR_INFO, "GLUSTERD_2_BRICK_XLATOR_INFO" },
	{ GLUSTERD_2_BRICK_XLATOR_OP, "GLUSTERD_2_BRICK_XLATOR_OP" },
	{ GLUSTERD_2_BRICK_STATUS, "GLUSTERD_2_BRICK_STATUS" },
	{ GLUSTERD_2_BRICK_OP, "GLUSTERD_2_BRICK_OP" },
	{ GLUSTERD_2_BRICK_XLATOR_DEFRAG, "GLUSTERD_2_BRICK_XLATOR_DEFRAG" },
	{ GLUSTERD_2_NODE_PROFILE, "GLUSTERD_2_NODE_PROFILE" },
	{ GLUSTERD_2_NODE_STATUS, "GLUSTERD_2_NODE_PROFILE" },
	{ GLUSTERD_2_BRICK_MAXVALUE, "GLUSTERD_2_BRICK_MAXVALUE" },
	{ 0, NULL }
};

static const value_string glusterd_op_vals[] = {
	{ GD_OP_NONE, "NONE" },
	{ GD_OP_CREATE_VOLUME, "CREATE_VOLUME" },
	{ GD_OP_START_BRICK, "START_BRICK" },
	{ GD_OP_STOP_BRICK, "STOP_BRICK" },
	{ GD_OP_DELETE_VOLUME, "DELETE_VOLUME" },
	{ GD_OP_START_VOLUME, "START_VOLUME" },
	{ GD_OP_STOP_VOLUME, "STOP_VOLUME" },
	{ GD_OP_DEFRAG_VOLUME, "DEFRAG_VOLUME" },
	{ GD_OP_ADD_BRICK, "ADD_BRICK" },
	{ GD_OP_REMOVE_BRICK, "REMOVE_BRICK" },
	{ GD_OP_REPLACE_BRICK, "REPLACE_BRICK" },
	{ GD_OP_SET_VOLUME, "SET_VOLUME" },
	{ GD_OP_RESET_VOLUME, "RESET_VOLUME" },
	{ GD_OP_SYNC_VOLUME, "SYNC_VOLUME" },
	{ GD_OP_LOG_ROTATE, "LOG_ROTATE" },
	{ GD_OP_GSYNC_SET, "GSYNC_SET" },
	{ GD_OP_PROFILE_VOLUME, "PROFILE_VOLUME" },
	{ GD_OP_QUOTA, "QUOTA" },
	{ GD_OP_STATUS_VOLUME, "STATUS_VOLUME" },
	{ GD_OP_REBALANCE, "REBALANCE" },
	{ GD_OP_HEAL_VOLUME, "HEAL_VOLUME" },
	{ GD_OP_STATEDUMP_VOLUME, "STATEDUMP_VOLUME" },
	{ GD_OP_LIST_VOLUME, "LIST_VOLUME" },
	{ GD_OP_CLEARLOCKS_VOLUME, "CLEARLOCKS_VOLUME" },
	{ GD_OP_DEFRAG_BRICK_VOLUME, "DEFRAG_BRICK_VOLUME" },
	{ 0, NULL }
};

static const vsff glusterd_friend_proc_vals[] = {
	{ GLUSTERD_FRIEND_NULL,"NULL"},
	{ GLUSTERD_PROBE_QUERY, "GLUSTERD_PROBE_QUERY" },
	{ GLUSTERD_FRIEND_ADD, "GLUSTERD_FRIEND_ADD" },
	{ GLUSTERD_FRIEND_REMOVE,"GLUSTERD_FRIEND_REMOVE" },
	{ GLUSTERD_FRIEND_UPDATE,"GLUSTERD_FRIEND_UPDATE" },
	{ GLUSTERD_FRIEND_MAXVALUE,"GLUSTERD_FRIEND_UMAXVALUE" },
	{ 0, NULL, NULL, NULL }
};

void
proto_register_gluster_gd_mgmt(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		/* programs */
		{ &hf_gd_mgmt_proc,
			{ "Gluster Daemon Management", "glusterd.mgmt.proc",
				FT_UINT32, BASE_DEC, VALS(gd_mgmt_proc_vals),
				0, NULL, HFILL }
		},
		{ &hf_gd_mgmt_2_proc,
			{ "Gluster Daemon Management", "glusterd.mgmt.proc",
				FT_UINT32, BASE_DEC, VALS(gd_mgmt_2_proc_vals),
				0, NULL, HFILL }
		},
		{ &hf_gd_mgmt_brick_2_proc,
                        { "Gluster Daemon Brick Operations", "glusterd.brick.proc",
                                FT_UINT32, BASE_DEC, VALS(gd_mgmt_brick_2_proc_vals),
                                0, NULL, HFILL }
                },
		{ &hf_glusterd_friend_proc ,
			{ "Gluster Daemon Friend Operations", "glusterd.friend.proc",
				FT_UINT32, BASE_DEC, VALS(glusterd_friend_proc_vals),
				0, NULL, HFILL }
		},
		{ &hf_gluster_dict,
			{ "Dict", "gluster.dict", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_op,
			{ "Operation", "gluster.op", FT_UINT32, BASE_DEC,
				VALS(glusterd_op_vals), 0, NULL, HFILL }
		},
		{ &hf_gluster_op_errstr,
			{ "Error", "gluster.op_errstr", FT_STRING,
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
		{ &hf_gluster_name,
			{ "Name", "gluster.name", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_gd_mgmt,
		&ett_gd_brick,
		&ett_gd_friend
	};

	/* Register the protocol name and description */
	proto_glusterd = proto_register_protocol("Gluster Daemon", "GlusterD",
								"glusterd");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_glusterd, hf, array_length(hf));

	proto_gd_mgmt = proto_register_protocol("Gluster Daemon Management",
					"GlusterD Management", "gd-mgmt");
	proto_gd_brick = proto_register_protocol("Gluster Daemon Brick Operations",
					"GlusterD Brick", "gd-brick");
	proto_gd_friend = proto_register_protocol("Gluster Daemon Friend Operations",
					"GlusterD Friend", "gd-friend");
}

void
proto_reg_handoff_gluster_gd_mgmt(void)
{
	rpc_init_prog(proto_gd_mgmt, GD_MGMT_PROGRAM, ett_gd_mgmt);
	rpc_init_proc_table(GD_MGMT_PROGRAM, 1, gd_mgmt_proc, hf_gd_mgmt_proc);
	rpc_init_proc_table(GD_MGMT_PROGRAM, 2, gd_mgmt_2_proc, hf_gd_mgmt_2_proc);

	rpc_init_prog(proto_gd_brick, GD_BRICK_PROGRAM, ett_gd_brick);
	rpc_init_proc_table(GD_BRICK_PROGRAM, 2, gd_mgmt_brick_2_proc, hf_gd_mgmt_brick_2_proc);
	rpc_init_prog(proto_gd_friend,GD_FRIEND_PROGRAM, ett_gd_friend);
	rpc_init_proc_table(GD_FRIEND_PROGRAM, 2,glusterd_friend_proc, hf_glusterd_friend_proc);

}

