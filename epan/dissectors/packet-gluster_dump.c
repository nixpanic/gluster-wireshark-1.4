/* packet-gluster_dump.c
 * Routines for Gluster DUMP dissection
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
static gint proto_gluster_dump = -1;

/* programs and procedures */
static gint hf_gluster_dump_proc = -1;

/* fields used by multiple programs/procedures */
static gint hf_gluster_gfsid = -1;
static gint hf_gluster_progname = -1;
static gint hf_gluster_prognum = -1;
static gint hf_gluster_progver = -1;

/* Initialize the subtree pointers */
static gint ett_gluster_dump = -1;

/* from rpc/rpc-lib/src/rpc-common.c */
static int
gluster_dump_reply_item(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	gchar *progname = NULL;

	/* progname */
	offset = dissect_rpc_string(tvb, tree, hf_gluster_progname, offset,
								&progname);
	/* prognumber */
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_prognum, offset);
	/* progversion */
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_progver, offset);

	return offset;
}

static int
gluster_dump_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
							proto_tree *tree)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_gfid, offset, 8,
								FALSE, NULL);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);

	if (tree)
		proto_tree_add_text(tree, tvb, offset, -1, "FIXME: The data that follows is a xdr_pointer from xdr_gf_prog_detail()");

	return offset;
}

/* DUMP request */
static int
gluster_dump_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
							proto_tree *tree)
{
	offset = dissect_rpc_uint64(tvb, tree, hf_gluster_gfsid, offset);

	return offset;
}

/* procedures for GLUSTER_DUMP_PROGRAM */
static const vsff gluster_dump_proc[] = {
	{ 0, "NULL", NULL, NULL },
	{ GF_DUMP_DUMP, "DUMP", gluster_dump_call, gluster_dump_reply },
	{ 0, NULL, NULL, NULL }
};
static const value_string gluster_dump_proc_vals[] = {
	{ 0, "NULL" },
	{ GF_DUMP_DUMP, "DUMP" },
	{ 0, NULL }
};

void
proto_register_gluster_dump(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		/* programs */
		{ &hf_gluster_dump_proc,
			{ "Gluster DUMP", "gluster.dump", FT_UINT32, BASE_DEC,
				VALS(gluster_dump_proc_vals), 0, NULL, HFILL }
		},
		{ &hf_gluster_progname,
			{ "DUMP Program", "gluster.dump.progname", FT_STRING,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_prognum,
			{ "DUMP Program Number", "gluster.dump.prognum",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_progver,
			{ "DUMP Program Version", "gluster.dump.progver",
				FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_gfsid,
			{ "GFS ID", "gluster.gfsid", FT_UINT64,
				BASE_HEX, NULL, 0, NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_gluster_dump
	};

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_gluster, hf, array_length(hf));

	proto_gluster_dump = proto_register_protocol("Gluster Dump",
					"Gluster Dump", "gluster-dump");
}

void
proto_reg_handoff_gluster_dump(void)
{
	rpc_init_prog(proto_gluster_dump, GLUSTER_DUMP_PROGRAM,
							ett_gluster_dump);
	rpc_init_proc_table(GLUSTER_DUMP_PROGRAM, 1, gluster_dump_proc,
							hf_gluster_dump_proc);
}

