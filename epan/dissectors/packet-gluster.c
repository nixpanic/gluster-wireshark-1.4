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
gint proto_gluster = -1;
static gint proto_gluster_mgmt = -1;

/* programs and procedures */
static gint hf_gluster_mgmt_proc = -1;

/* fields used by multiple programs/procedures */
gint hf_gluster_gfid = -1;
gint hf_gluster_op = -1;
gint hf_gluster_op_ret = -1;
gint hf_gluster_dict = -1;
static gint hf_gluster_dict_key = -1;
static gint hf_gluster_dict_value = -1;

/* Initialize the subtree pointers */
static gint ett_gluster = -1;
static gint ett_gluster_mgmt = -1;
static gint ett_gluster_dict = -1;
static gint ett_gluster_dict_items = -1;

/* function for dissecting and adding a gluster dict_t to the tree */
int
gluster_rpc_dissect_dict(proto_tree *tree, tvbuff_t *tvb, int hfindex, int offset)
{
	gchar *key, *value;
	gint items, i, len, roundup, value_len, key_len;

	proto_item *subtree_item;
	proto_tree *subtree;

	proto_item *dict_item;
	proto_tree *dict_tree;

	/* create a subtree for all the items in the dict */
	if (hfindex >= 0) {
		header_field_info *hfinfo = proto_registrar_get_nth(hfindex);
		subtree_item = proto_tree_add_text(tree, tvb, offset, -1, "%s", hfinfo->name);
	} else {
		subtree_item = proto_tree_add_text(tree, tvb, offset, -1, "<NAMELESS DICT STRUCTURE>");
	}

	subtree = proto_item_add_subtree(subtree_item, ett_gluster_dict);

	len = tvb_get_ntohl(tvb, offset);
	roundup = rpc_roundup(len) - len;
	proto_tree_add_text(subtree, tvb, offset, 4, "[Size: %d (%d bytes inc. RPC-roundup)]", len, rpc_roundup(len));
	offset += 4;

	if (len == 0)
		return offset;

	items = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(subtree, tvb, offset, 4, "[Items: %d]", items);
	offset += 4;

	for (i = 0; i < items; i++) {
		/* key_len is the length of the key without the terminating '\0' */
		/* key_len = tvb_get_ntohl(tvb, offset) + 1; // will be read later */
		offset += 4;
		value_len = tvb_get_ntohl(tvb, offset);
		offset += 4;

		/* read the key, '\0' terminated */
		key = tvb_get_stringz(tvb, offset, &key_len);
		if (tree)
			dict_item = proto_tree_add_text(subtree, tvb, offset, -1, "%s: ", key);
		offset += key_len;
		g_free(key);

		/* read the value, '\0' terminated */
		value = tvb_get_string(tvb, offset, value_len);
		if (tree)
			proto_item_append_text(dict_item, "%s", value);
		offset += value_len;
		g_free(value);
	}

	if (roundup) {
		if (tree)
			proto_tree_add_text(subtree, tvb, offset, -1, "[RPC-roundup bytes: %d]", roundup);
		offset += roundup;
	}

	return offset;
}

/* GLUSTERD1_MGMT_PROGRAM from xlators/mgmt/glusterd/src/glusterd-rpc-ops.c */
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
	{ 0, NULL, NULL, NULL }
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
	{ 0, NULL }
};


void
proto_register_gluster(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		/* programs */
		{ &hf_gluster_mgmt_proc,
			{ "Gluster Management", "gluster.mgmt", FT_UINT32,
				BASE_DEC, VALS(gluster_mgmt_proc_vals), 0,
				NULL, HFILL }
		},
		/* fields used by procedures */
		{ &hf_gluster_gfid,
			{ "GFID", "gluster.gfid", FT_BYTES,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_op,
			{ "Operation (FIXME?)", "gluster.op", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_op_ret,
			{ "Return value", "gluster.op_ret", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		/* fields used by gluster_rpc_dissect_dict() */
		{ &hf_gluster_dict,
			{ "Dict", "gluster.dict", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_dict_key,
			{ "Key", "gluster.dict.key", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_dict_value,
			{ "Value", "gluster.dict.value", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_gluster,
		&ett_gluster_mgmt,
		&ett_gluster_dict,
		&ett_gluster_dict_items
	};

	/* Register the protocol name and description */
	proto_gluster = proto_register_protocol("Gluster", "Gluster",
								"gluster");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_gluster, hf, array_length(hf));

	proto_gluster_mgmt = proto_register_protocol("Gluster Management",
					"Gluster Management", "gluster-mgmt");
}


void
proto_reg_handoff_gluster(void)
{
	rpc_init_prog(proto_gluster_mgmt, GLUSTERD1_MGMT_PROGRAM,
							ett_gluster_mgmt);
	rpc_init_proc_table(GLUSTERD1_MGMT_PROGRAM, 1, gluster_mgmt_proc,
							hf_gluster_mgmt_proc);

}

