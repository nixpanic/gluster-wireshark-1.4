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
static gint hf_gluster_cli_proc = -1;

/* Initialize the subtree pointers */
static gint ett_gluster_cli = -1;

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

void
proto_register_gluster_cli(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		/* programs */
		{ &hf_gluster_cli_proc,
			{ "Gluster CLI", "gluster.cli", FT_UINT32, BASE_DEC,
				VALS(gluster_cli_proc_vals), 0, NULL, HFILL }
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
}

