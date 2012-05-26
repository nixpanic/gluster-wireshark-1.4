/* packet-gluster_cli.c
 * Routines for Gluster CLI dissection
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
static gint proto_gluster_cli = -1;

/* programs and procedures */
static gint hf_gluster_op_errno = -1;
static gint hf_gluster_cli_proc = -1;
static gint hf_gluster_cli_2_proc = -1;
static gint hf_gluster_dict = -1;
static gint hf_gluster_path = -1;
static gint hf_gluster_lazy = -1;
static gint hf_gluster_label = -1;
static gint hf_gluster_unused = -1;
static gint hf_gluster_wd= -1;
static gint hf_gluster_op_errstr= -1;
static gint hf_gluster_name= -1;
static gint hf_gluster_hostname = -1;
static gint hf_gluster_port = -1;
static gint hf_gluster_flags = -1;

/* Initialize the subtree pointers */
static gint ett_gluster_cli = -1;

/* CLI Operations */

static int
gluster_cli_2_common_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);

	return offset;
}

static int
gluster_cli_2_common_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* errstr= NULL;

	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_op_errstr, offset, &errstr);

	return offset;
}

static int
gluster_cli_2_probe_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{

	gchar* hostname = NULL;

	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset, &hostname);

	return offset;
}

static int
gluster_cli_2_probe_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{

	gchar* hostname = NULL;
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset, &hostname);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);

	return offset;
}

static int
gluster_cli_2_deprobe_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{

	gchar* hostname = NULL;

	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset, &hostname);

	return offset;
}

static int
gluster_cli_2_deprobe_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{

	gchar* hostname = NULL;

	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset, &hostname);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_flags, offset);

	return offset;
}

static int
gluster_cli_2_fsm_log_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* name = NULL;

	offset = dissect_rpc_string(tvb, tree, hf_gluster_wd, offset, &name);

	return offset;
}

static int
gluster_cli_2_getwd_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* wd = NULL;

	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_wd, offset, &wd);

	return offset;
}

static int
gluster_cli_2_getwd_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_unused, offset);

	return offset;
}

static int
gluster_cli_2_mount_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* label = NULL;

	offset = dissect_rpc_string(tvb, tree, hf_gluster_label, offset, &label);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);

	return offset;
}

static int
gluster_cli_2_mount_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* path = NULL;

	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_path, offset, &path);

	return offset;
}

static int
gluster_cli_2_umount_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
        gchar* path = NULL;

	offset = dissect_rpc_uint32(tvb, tree,hf_gluster_lazy, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_path, offset, &path);

	return offset;
}

static int
gluster_cli_2_umount_reply(tvbuff_t *tvb, int offset,
                                packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);

	return offset;
}

/* procedures for GLUSTER_CLI_PROGRAM */
static const vsff gluster_cli_proc[] = {
	{ GLUSTER_CLI_NULL, "GLUSTER_CLI_NULL", NULL, NULL },
	{ GLUSTER_CLI_PROBE, "GLUSTER_CLI_PROBE", NULL, NULL },
	{ GLUSTER_CLI_DEPROBE, "GLUSTER_CLI_DEPROBE", NULL, NULL },
	{ GLUSTER_CLI_LIST_FRIENDS, "GLUSTER_CLI_LIST_FRIENDS", NULL, NULL },
	{ GLUSTER_CLI_CREATE_VOLUME, "GLUSTER_CLI_CREATE_VOLUME", NULL, NULL },
	{ GLUSTER_CLI_GET_VOLUME, "GLUSTER_CLI_GET_VOLUME", NULL, NULL },
	{
		GLUSTER_CLI_GET_NEXT_VOLUME, "GLUSTER_CLI_GET_NEXT_VOLUME",
		NULL, NULL
	},
	{ GLUSTER_CLI_DELETE_VOLUME, "GLUSTER_CLI_DELETE_VOLUME", NULL, NULL },
	{ GLUSTER_CLI_START_VOLUME, "GLUSTER_CLI_START_VOLUME", NULL, NULL },
	{ GLUSTER_CLI_STOP_VOLUME, "GLUSTER_CLI_STOP_VOLUME", NULL, NULL },
	{ GLUSTER_CLI_RENAME_VOLUME, "GLUSTER_CLI_RENAME_VOLUME", NULL, NULL },
	{ GLUSTER_CLI_DEFRAG_VOLUME, "GLUSTER_CLI_DEFRAG_VOLUME", NULL, NULL },
	{ GLUSTER_CLI_SET_VOLUME, "GLUSTER_CLI_SET_VOLUME", NULL, NULL },
	{ GLUSTER_CLI_ADD_BRICK, "GLUSTER_CLI_ADD_BRICK", NULL, NULL },
	{ GLUSTER_CLI_REMOVE_BRICK, "GLUSTER_CLI_REMOVE_BRICK", NULL, NULL },
	{ GLUSTER_CLI_REPLACE_BRICK, "GLUSTER_CLI_REPLACE_BRICK", NULL, NULL },
	{ GLUSTER_CLI_LOG_FILENAME, "GLUSTER_CLI_LOG_FILENAME", NULL, NULL },
	{ GLUSTER_CLI_LOG_LOCATE, "GLUSTER_CLI_LOG_LOCATE", NULL, NULL },
	{ GLUSTER_CLI_LOG_ROTATE, "GLUSTER_CLI_LOG_ROTATE", NULL, NULL },
	{ GLUSTER_CLI_GETSPEC, "GLUSTER_CLI_GETSPEC", NULL, NULL },
	{
		GLUSTER_CLI_PMAP_PORTBYBRICK, "GLUSTER_CLI_PMAP_PORTBYBRICK",
		NULL , NULL
	},
	{ GLUSTER_CLI_SYNC_VOLUME, "GLUSTER_CLI_SYNC_VOLUME", NULL, NULL },
	{ GLUSTER_CLI_RESET_VOLUME, "GLUSTER_CLI_RESET_VOLUME", NULL, NULL },
	{ GLUSTER_CLI_FSM_LOG, "GLUSTER_CLI_FSM_LOG", NULL, NULL },
	{ GLUSTER_CLI_GSYNC_SET, "GLUSTER_CLI_GSYNC_SET", NULL, NULL },
	{
		GLUSTER_CLI_PROFILE_VOLUME, "GLUSTER_CLI_PROFILE_VOLUME",
		NULL, NULL
	},
	{ GLUSTER_CLI_QUOTA, "GLUSTER_CLI_QUOTA", NULL, NULL },
	{ GLUSTER_CLI_TOP_VOLUME, "GLUSTER_CLI_TOP_VOLUME", NULL, NULL },
	{ GLUSTER_CLI_GETWD, "GLUSTER_CLI_GETWD", NULL, NULL },
	{ GLUSTER_CLI_LOG_LEVEL, "GLUSTER_CLI_LOG_LEVEL", NULL, NULL },
	{ GLUSTER_CLI_STATUS_VOLUME, "GLUSTER_CLI_STATUS_VOLUME", NULL, NULL },
	{ GLUSTER_CLI_MOUNT, "GLUSTER_CLI_MOUNT", NULL, NULL },
	{ GLUSTER_CLI_UMOUNT, "GLUSTER_CLI_UMOUNT", NULL, NULL },
	{ GLUSTER_CLI_HEAL_VOLUME, "GLUSTER_CLI_HEAL_VOLUME", NULL, NULL },
	{
		GLUSTER_CLI_STATEDUMP_VOLUME, "GLUSTER_CLI_STATEDUMP_VOLUME",
		NULL, NULL
	},
	{ GLUSTER_CLI_MAXVALUE, "GLUSTER_CLI_MAXVALUE", NULL, NULL },
	{ 0, NULL, NULL, NULL }
};

/* procedures for GLUSTER_CLI_PROGRAM  version 2*/
static const vsff gluster_cli_2_proc[] = {
	{
		GLUSTER_CLI_2_NULL, "GLUSTER_CLI_NULL",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_PROBE, "GLUSTER_CLI_PROBE",
		gluster_cli_2_probe_call, gluster_cli_2_probe_reply
	},
	{
		GLUSTER_CLI_2_DEPROBE, "GLUSTER_CLI_DEPROBE",
		gluster_cli_2_deprobe_call, gluster_cli_2_deprobe_reply
	},
        {
		GLUSTER_CLI_2_LIST_FRIENDS, "GLUSTER_CLI_LIST_FRIENDS",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_CREATE_VOLUME, "GLUSTER_CLI_CREATE_VOLUME" ,
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
       		GLUSTER_CLI_2_GET_VOLUME, "GLUSTER_CLI_GET_VOLUME",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_GET_NEXT_VOLUME, "GLUSTER_CLI_GET_NEXT_VOLUME",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_DELETE_VOLUME, "GLUSTER_CLI_DELETE_VOLUME",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_START_VOLUME, "GLUSTER_CLI_START_VOLUME",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_STOP_VOLUME, "GLUSTER_CLI_STOP_VOLUME",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_RENAME_VOLUME, "GLUSTER_CLI_RENAME_VOLUME",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_DEFRAG_VOLUME, "GLUSTER_CLI_DEFRAG_VOLUME" ,
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_SET_VOLUME, "GLUSTER_CLI_SET_VOLUME",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_ADD_BRICK, "GLUSTER_CLI_ADD_BRICK",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_REMOVE_BRICK, "GLUSTER_CLI_REMOVE_BRICK",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_REPLACE_BRICK, "GLUSTER_CLI_REPLACE_BRICK",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_LOG_ROTATE, "GLUSTER_CLI_LOG_ROTATE",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_GETSPEC, "GLUSTER_CLI_GETSPEC",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_PMAP_PORTBYBRICK, "GLUSTER_CLI_PMAP_PORTBYBRICK",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_SYNC_VOLUME, "GLUSTER_CLI_SYNC_VOLUME",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_RESET_VOLUME, "GLUSTER_CLI_RESET_VOLUME",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_FSM_LOG, "GLUSTER_CLI_FSM_LOG",
		gluster_cli_2_fsm_log_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_GSYNC_SET, "GLUSTER_CLI_GSYNC_SET",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_PROFILE_VOLUME, "GLUSTER_CLI_PROFILE_VOLUME",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_QUOTA, "GLUSTER_CLI_QUOTA",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_TOP_VOLUME, "GLUSTER_CLI_TOP_VOLUME",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_GETWD, "GLUSTER_CLI_GETWD",
		gluster_cli_2_getwd_call, gluster_cli_2_getwd_reply
	},
	{
		GLUSTER_CLI_2_STATUS_VOLUME, "GLUSTER_CLI_STATUS_VOLUME",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_STATUS_ALL, "GLUSTER_CLI_STATUS_ALL",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_MOUNT, "GLUSTER_CLI_MOUNT",
		gluster_cli_2_mount_call, gluster_cli_2_mount_reply
	},
	{
		GLUSTER_CLI_2_UMOUNT, "GLUSTER_CLI_UMOUNT",
		gluster_cli_2_umount_call, gluster_cli_2_umount_reply
	},
	{
		GLUSTER_CLI_2_HEAL_VOLUME, "GLUSTER_CLI_HEAL_VOLUME",
		gluster_cli_2_common_call, gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_STATEDUMP_VOLUME, "GLUSTER_CLI_STATEDUMP_VOLUME",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_LIST_VOLUME, "GLUSTER_CLI_LIST_VOLUME",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_CLRLOCKS_VOLUME, " GLUSTER_CLI_CLRLOCKS_VOLUME",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{
		GLUSTER_CLI_2_MAXVALUE, "GLUSTER_CLI_MAXVALUE",
		gluster_cli_2_common_call,gluster_cli_2_common_reply
	},
	{ 0, NULL , NULL, NULL}
};


static const value_string gluster_cli_proc_vals[] = {
	{ GLUSTER_CLI_NULL, "GLUSTER_CLI_NULL" },
	{ GLUSTER_CLI_PROBE, "GLUSTER_CLI_PROBE" },
	{ GLUSTER_CLI_DEPROBE, "GLUSTER_CLI_DEPROBE" },
	{ GLUSTER_CLI_LIST_FRIENDS, "GLUSTER_CLI_LIST_FRIENDS" },
	{ GLUSTER_CLI_CREATE_VOLUME, "GLUSTER_CLI_CREATE_VOLUME" },
	{ GLUSTER_CLI_GET_VOLUME, "GLUSTER_CLI_GET_VOLUME" },
	{ GLUSTER_CLI_GET_NEXT_VOLUME, "GLUSTER_CLI_GET_NEXT_VOLUME" },
	{ GLUSTER_CLI_DELETE_VOLUME, "GLUSTER_CLI_DELETE_VOLUME" },
	{ GLUSTER_CLI_START_VOLUME, "GLUSTER_CLI_START_VOLUME" },
	{ GLUSTER_CLI_STOP_VOLUME, "GLUSTER_CLI_STOP_VOLUME" },
	{ GLUSTER_CLI_RENAME_VOLUME, "GLUSTER_CLI_RENAME_VOLUME" },
	{ GLUSTER_CLI_DEFRAG_VOLUME, "GLUSTER_CLI_DEFRAG_VOLUME" },
	{ GLUSTER_CLI_SET_VOLUME, "GLUSTER_CLI_SET_VOLUME" },
	{ GLUSTER_CLI_ADD_BRICK, "GLUSTER_CLI_ADD_BRICK" },
	{ GLUSTER_CLI_REMOVE_BRICK, "GLUSTER_CLI_REMOVE_BRICK" },
	{ GLUSTER_CLI_REPLACE_BRICK, "GLUSTER_CLI_REPLACE_BRICK" },
	{ GLUSTER_CLI_LOG_FILENAME, "GLUSTER_CLI_LOG_FILENAME" },
	{ GLUSTER_CLI_LOG_LOCATE, "GLUSTER_CLI_LOG_LOCATE" },
	{ GLUSTER_CLI_LOG_ROTATE, "GLUSTER_CLI_LOG_ROTATE" },
	{ GLUSTER_CLI_GETSPEC, "GLUSTER_CLI_GETSPEC" },
	{ GLUSTER_CLI_PMAP_PORTBYBRICK, "GLUSTER_CLI_PMAP_PORTBYBRICK" },
	{ GLUSTER_CLI_SYNC_VOLUME, "GLUSTER_CLI_SYNC_VOLUME" },
	{ GLUSTER_CLI_RESET_VOLUME, "GLUSTER_CLI_RESET_VOLUME" },
	{ GLUSTER_CLI_FSM_LOG, "GLUSTER_CLI_FSM_LOG" },
	{ GLUSTER_CLI_GSYNC_SET, "GLUSTER_CLI_GSYNC_SET" },
	{ GLUSTER_CLI_PROFILE_VOLUME, "GLUSTER_CLI_PROFILE_VOLUME" },
	{ GLUSTER_CLI_QUOTA, "GLUSTER_CLI_QUOTA" },
	{ GLUSTER_CLI_TOP_VOLUME, "GLUSTER_CLI_TOP_VOLUME" },
	{ GLUSTER_CLI_GETWD, "GLUSTER_CLI_GETWD" },
	{ GLUSTER_CLI_LOG_LEVEL, "GLUSTER_CLI_LOG_LEVEL" },
	{ GLUSTER_CLI_STATUS_VOLUME, "GLUSTER_CLI_STATUS_VOLUME" },
	{ GLUSTER_CLI_MOUNT, "GLUSTER_CLI_MOUNT" },
	{ GLUSTER_CLI_UMOUNT, "GLUSTER_CLI_UMOUNT" },
	{ GLUSTER_CLI_HEAL_VOLUME, "GLUSTER_CLI_HEAL_VOLUME" },
	{ GLUSTER_CLI_STATEDUMP_VOLUME, "GLUSTER_CLI_STATEDUMP_VOLUME" },
	{ GLUSTER_CLI_MAXVALUE, "GLUSTER_CLI_MAXVALUE" },
	{ 0, NULL }
};

static const value_string gluster_cli_2_proc_vals[] = {
	{ GLUSTER_CLI_2_NULL, "GLUSTER_CLI_NULL" },
	{ GLUSTER_CLI_2_PROBE, "GLUSTER_CLI_PROBE" },
	{ GLUSTER_CLI_2_DEPROBE, "GLUSTER_CLI_DEPROBE" },
	{ GLUSTER_CLI_2_LIST_FRIENDS, "GLUSTER_CLI_LIST_FRIENDS" },
	{ GLUSTER_CLI_2_CREATE_VOLUME, "GLUSTER_CLI_CREATE_VOLUME" },
	{ GLUSTER_CLI_2_GET_VOLUME, "GLUSTER_CLI_GET_VOLUME" },
	{ GLUSTER_CLI_2_GET_NEXT_VOLUME, "GLUSTER_CLI_GET_NEXT_VOLUME" },
	{ GLUSTER_CLI_2_DELETE_VOLUME, "GLUSTER_CLI_DELETE_VOLUME" },
	{ GLUSTER_CLI_2_START_VOLUME, "GLUSTER_CLI_START_VOLUME" },
	{ GLUSTER_CLI_2_STOP_VOLUME, "GLUSTER_CLI_STOP_VOLUME" },
	{ GLUSTER_CLI_2_RENAME_VOLUME, "GLUSTER_CLI_RENAME_VOLUME" },
	{ GLUSTER_CLI_2_DEFRAG_VOLUME, "GLUSTER_CLI_DEFRAG_VOLUME" },
	{ GLUSTER_CLI_2_SET_VOLUME, "GLUSTER_CLI_SET_VOLUME" },
	{ GLUSTER_CLI_2_ADD_BRICK, "GLUSTER_CLI_ADD_BRICK" },
	{ GLUSTER_CLI_2_REMOVE_BRICK, "GLUSTER_CLI_REMOVE_BRICK" },
	{ GLUSTER_CLI_2_REPLACE_BRICK, "GLUSTER_CLI_REPLACE_BRICK" },
	{ GLUSTER_CLI_2_LOG_ROTATE, "GLUSTER_CLI_LOG_ROTATE" },
	{ GLUSTER_CLI_2_GETSPEC, "GLUSTER_CLI_GETSPEC" },
	{ GLUSTER_CLI_2_PMAP_PORTBYBRICK, "GLUSTER_CLI_PMAP_PORTBYBRICK" },
	{ GLUSTER_CLI_2_SYNC_VOLUME, "GLUSTER_CLI_SYNC_VOLUME" },
	{ GLUSTER_CLI_2_RESET_VOLUME, "GLUSTER_CLI_RESET_VOLUME" },
	{ GLUSTER_CLI_2_FSM_LOG, "GLUSTER_CLI_FSM_LOG" },
	{ GLUSTER_CLI_2_GSYNC_SET, "GLUSTER_CLI_GSYNC_SET" },
	{ GLUSTER_CLI_2_PROFILE_VOLUME, "GLUSTER_CLI_PROFILE_VOLUME" },
	{ GLUSTER_CLI_2_QUOTA, "GLUSTER_CLI_QUOTA" },
	{ GLUSTER_CLI_2_TOP_VOLUME, "GLUSTER_CLI_TOP_VOLUME" },
	{ GLUSTER_CLI_2_GETWD, "GLUSTER_CLI_GETWD" },
	{ GLUSTER_CLI_2_STATUS_VOLUME, "GLUSTER_CLI_STATUS_VOLUME" },
	{ GLUSTER_CLI_2_STATUS_ALL, "GLUSTER_CLI_STATUS_ALL" },
 	{ GLUSTER_CLI_2_MOUNT, "GLUSTER_CLI_MOUNT" },
	{ GLUSTER_CLI_2_UMOUNT, "GLUSTER_CLI_UMOUNT" },
	{ GLUSTER_CLI_2_HEAL_VOLUME, "GLUSTER_CLI_HEAL_VOLUME" },
	{ GLUSTER_CLI_2_STATEDUMP_VOLUME, "GLUSTER_CLI_STATEDUMP_VOLUME" },
	{ GLUSTER_CLI_2_LIST_VOLUME, "GLUSTER_CLI_LIST_VOLUME"},
	{ GLUSTER_CLI_2_CLRLOCKS_VOLUME, " GLUSTER_CLI_CLRLOCKS_VOLUME" },
	{ GLUSTER_CLI_2_MAXVALUE, "GLUSTER_CLI_MAXVALUE" },
	{ 0, NULL }
};

void
proto_register_gluster_cli(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		/* programs */
		{ &hf_gluster_cli_proc,
			{ "Gluster CLI", "gluster.cli", FT_UINT32, BASE_DEC,
				VALS(gluster_cli_proc_vals), 0, NULL, HFILL }
		},
		{ &hf_gluster_cli_2_proc,
			{ "Gluster CLI", "gluster.cli", FT_UINT32, BASE_DEC,
				VALS(gluster_cli_2_proc_vals), 0, NULL, HFILL }
		},
		{ &hf_gluster_dict,
			{ "Dict", "gluster.dict", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_op_errno,
			{ "Errno", "gluster.op_errno", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_path,
			{ "Path", "gluster.path", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_lazy,
			{ "lazy", "gluster.lazy", FT_UINT32, BASE_OCT,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_label,
			{ "Label", "gluster.label", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_unused,
			{ "Unused", "gluster.unused", FT_UINT32, BASE_OCT,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_wd,
			{ "Path", "gluster.wd", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_op_errstr,
			{ "Errstr", "gluster.op_errstr", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_name,
			{ "Name", "gluster.name", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_hostname,
			{ "Hostname", "gluster.hostname", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_port,
			{ "Port", "gluster.port", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_flags,
			{ "Flags", "gluster.flag", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		}
	};


	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_gluster_cli
	};

	/* Register the protocol name and description */
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_gluster, hf, array_length(hf));

	proto_gluster_cli = proto_register_protocol("Gluster CLI",
					"Gluster CLI", "gluster-cli");
}

void
proto_reg_handoff_gluster_cli(void)
{
	rpc_init_prog(proto_gluster_cli, GLUSTER_CLI_PROGRAM, ett_gluster_cli);
	rpc_init_proc_table(GLUSTER_CLI_PROGRAM, 1, gluster_cli_proc,
							hf_gluster_cli_proc);
	rpc_init_proc_table(GLUSTER_CLI_PROGRAM, 2, gluster_cli_2_proc,
							hf_gluster_cli_2_proc);
}

