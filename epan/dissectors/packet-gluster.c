/* packet-gluster.c
 * Routines for gluster dissection
 * Copyright 2012, Niels de Vos <ndevos@redhat.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/tfs.h>

#include "packet-rpc.h"
#include "packet-gluster.h"

/* Initialize the protocol and registered fields */
static gint proto_gluster = -1;
static gint proto_gluster_dump = -1;
static gint proto_gluster_mgmt = -1;
static gint proto_gd_mgmt = -1;
static gint proto_gluster_hndsk = -1;

static gint hf_gluster_dump_proc = -1;
static gint hf_gluster_dump_gfs_idx = -1;
static gchar* hf_gluster_dump_gfsid = NULL;
static gchar* hf_gluster_dump_progname = NULL;
static gint hf_gluster_dump_prognum = -1;
static gint hf_gluster_dump_progver = -1;

static gint hf_gluster_mgmt_proc = -1;
static gint hf_gd_mgmt_proc = -1;
static gint hf_gluster_hndsk_proc = -1;

/* Initialize the subtree pointers */
static gint ett_gluster_dump = -1;
static gint ett_gluster_mgmt = -1;
static gint ett_gd_mgmt = -1;
static gint ett_gluster_hndsk = -1;

static int gluster_dump_reply_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
#if 0
	/* progname */
	offset = dissect_rpc_string();
	/* prognumber */
	offset = dissect_rpc_int();
	/* progversion */
	offset = dissect_rpc_int();
#endif
	return offset;
}

static int gluster_dump_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_list(tvb, pinfo, tree, offset, gluster_dump_reply_item);

	return offset;
}

/* DUMP request */
static int gluster_dump_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
//	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_dump_gfsid, offset);
//
	return offset;
}


/* procedures for GLUSTER_DUMP_PROGRAM */
static const vsff gluster_dump_proc[] = {
	{ 0, "NULL", NULL, NULL },
	{ GF_DUMP_DUMP, "DUMP", gluster_dump_call, gluster_dump_reply },
	{ 0, "NULL", NULL, NULL }
};
static const value_string gluster_dump_proc_vals[] = {
	{ 0, "NULL" },
	{ GF_DUMP_DUMP, "DUMP" },
	{ 0, "NULL" }
};

/* xlators/mgmt/glusterd/src/glusterd-rpc-ops.c */
static const vsff gluster_mgmt_proc[] = {
	{ GLUSTERD_MGMT_NULL, "NULL", NULL, NULL },
	{ GLUSTERD_MGMT_PROBE_QUERY, "PROBE_QUERY", NULL, NULL },
	{ GLUSTERD_MGMT_FRIEND_ADD, "FRIEND_ADD", NULL, NULL },
	{ GLUSTERD_MGMT_CLUSTER_LOCK, "CLUSTER_LOCK", NULL, NULL },
	{ GLUSTERD_MGMT_CLUSTER_UNLOCK, "CLUSTER_UNLOCK", NULL, NULL },
	{ GLUSTERD_MGMT_STAGE_OP, "STAGE_OP", NULL, NULL },
	{ GLUSTERD_MGMT_COMMIT_OP, "COMMIT_OP", NULL, NULL },
	{ GLUSTERD_MGMT_FRIEND_REMOVE, "FRIEND_REMOVE", NULL, NULL },
	{ GLUSTERD_MGMT_FRIEND_UPDATE, "FRIEND_UPDATE", NULL, NULL },
	{ 0, "NULL", NULL, NULL }
};
static const value_string gluster_mgmt_proc_vals[] = {
	{ GLUSTERD_MGMT_NULL, "NULL" },
	{ GLUSTERD_MGMT_PROBE_QUERY, "PROBE_QUERY" },
	{ GLUSTERD_MGMT_FRIEND_ADD, "FRIEND_ADD" },
	{ GLUSTERD_MGMT_CLUSTER_LOCK, "CLUSTER_LOCK" },
	{ GLUSTERD_MGMT_CLUSTER_UNLOCK, "CLUSTER_UNLOCK" },
	{ GLUSTERD_MGMT_STAGE_OP, "STAGE_OP" },
	{ GLUSTERD_MGMT_COMMIT_OP, "COMMIT_OP" },
	{ GLUSTERD_MGMT_FRIEND_REMOVE, "FRIEND_REMOVE" },
	{ GLUSTERD_MGMT_FRIEND_UPDATE, "FRIEND_UPDATE" },
	{ 0, "NULL" }
};

static const vsff gd_mgmt_proc[] = {
	{ GD_MGMT_NULL, "NULL", NULL, NULL },
	{ GD_MGMT_BRICK_OP, "BRICK_OP", NULL, NULL },
	{ 0, "NULL", NULL, NULL }
};
static const value_string gd_mgmt_proc_vals[] = {
	{ GD_MGMT_NULL, "NULL" },
	{ GD_MGMT_BRICK_OP, "BRICK_OP" },
	{ 0, "NULL" }
};

/* procedures for GLUSTER_HNDSK_PROGRAM */
static const vsff gluster_hndsk_proc[] = {
	{ GF_HNDSK_NULL, "NULL", NULL, NULL },
	{ GF_HNDSK_SETVOLUME, "DUMP", NULL, NULL },
	{ GF_HNDSK_GETSPEC, "GETSPEC", NULL, NULL },
	{ GF_HNDSK_PING, "PING", NULL, NULL },
	{ 0, "NULL", NULL, NULL }
};
static const value_string gluster_hndsk_proc_vals[] = {
	{ GF_HNDSK_NULL, "NULL" },
	{ GF_HNDSK_SETVOLUME, "DUMP" },
	{ GF_HNDSK_GETSPEC, "GETSPEC" },
	{ GF_HNDSK_PING, "PING" },
	{ 0, "NULL" }
};

/* TODO: procedures for GLUSTER3_1_FOP_PROGRAM */
/* TODO: procedures for GLUSTER_CBK_PROGRAM */
/* TODO: procedures for GLUSTER_CLI_PROGRAM */
/* TODO: procedures for GLUSTERD1_MGMT_PROGRAM */
/* TODO: procedures for GLUSTER_PMAP_PROGRAM */

void
proto_register_gluster(void)
{
/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf_dump[] = {
		{ &hf_gluster_dump_gfsid,
			{ "DUMP GFS ID", "gluster.dump.gfsid", FT_UINT32, BASE_HEX,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_dump_proc,
			{ "Gluster DUMP", "gluster.dump", FT_UINT32, BASE_DEC,
			VALS(gluster_dump_proc_vals), 0, NULL, HFILL }
		},
		{ &hf_gluster_dump_progname,
			{ "DUMP Program", "gluster.dump.progname", FT_STRING, BASE_NONE,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_dump_prognum,
			{ "DUMP Program Numbver", "gluster.dump.prognum", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_dump_progver,
			{ "DUMP Program Version", "gluster.dump.progver", FT_UINT32, BASE_DEC,
			NULL, 0, NULL, HFILL }
		}
	};

	static hf_register_info hf_mgmt[] = {
		{ &hf_gluster_mgmt_proc,
			{ "Gluster Management", "gluster.mgmt", FT_UINT32, BASE_DEC,
			VALS(gluster_mgmt_proc_vals), 0, NULL, HFILL }
		}
	};

	static hf_register_info hf_gd_mgmt[] = {
		{ &hf_gd_mgmt_proc,
			{ "Gluster Daemon Management", "glusterd.mgmt", FT_UINT32, BASE_DEC,
			VALS(gd_mgmt_proc_vals), 0, NULL, HFILL }
		}
	};

	static hf_register_info hf_hndsk[] = {
		{ &hf_gluster_hndsk_proc,
			{ "Gluster Handshake", "gluster.hndsk", FT_UINT32, BASE_DEC,
			VALS(gluster_hndsk_proc_vals), 0, NULL, HFILL }
		}
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_gluster_dump,
		&ett_gluster_mgmt,
		&ett_gd_mgmt,
		&ett_gluster_hndsk
	};

/* Register the protocol name and description */
	proto_gluster = proto_register_protocol("Gluster",
	    "Gluster", "gluster");
	proto_register_subtree_array(ett, array_length(ett));

/* Register the protocol name and description */
	proto_gluster_dump = proto_register_protocol("Gluster Dump",
	    "Gluster Dump", "gluster-dump");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_gluster_dump, hf_dump, array_length(hf_dump));
//	proto_register_field_array(proto_gluster_mgmt, hf_mgmt, array_length(hf_mgmt));
//	proto_register_field_array(proto_gd_mgmt, hf_gd_mgmt, array_length(hf_gd_mgmt));
//	proto_register_field_array(proto_gluster_hndsk, hf_hndsk, array_length(hf_hndsk));
}


/* Simple form of proto_reg_handoff_PROTOABBREV which can be used if there are
   no prefs-dependent registration function calls.
 */
void
proto_reg_handoff_gluster(void)
{
	rpc_init_prog(proto_gluster_dump, GLUSTER_DUMP_PROGRAM, ett_gluster_dump);
	rpc_init_proc_table(GLUSTER_DUMP_PROGRAM, 1, gluster_dump_proc, hf_gluster_dump_proc);

	rpc_init_prog(proto_gluster_mgmt, GLUSTERD1_MGMT_PROGRAM, ett_gluster_mgmt);
	rpc_init_proc_table(GLUSTERD1_MGMT_PROGRAM, 1, gluster_mgmt_proc, hf_gluster_mgmt_proc);

	rpc_init_prog(proto_gd_mgmt, GD_MGMT_PROGRAM, ett_gd_mgmt);
	rpc_init_proc_table(GD_MGMT_PROGRAM, 1, gd_mgmt_proc, hf_gd_mgmt_proc);

	rpc_init_prog(proto_gluster_hndsk, GLUSTER_HNDSK_PROGRAM, ett_gluster_hndsk);
	rpc_init_proc_table(GLUSTER_HNDSK_PROGRAM, 1, gluster_hndsk_proc, hf_gluster_hndsk_proc);
}

