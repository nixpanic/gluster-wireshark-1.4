/* packet-gluster_pmap.c
 * Routines for Gluster Portmapper dissection
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
static gint proto_gluster_pmap = -1;

/* programs and procedures */
static gint hf_gluster_pmap_proc = -1;

/* fields used by multiple programs/procedures */
static gint hf_gluster_brick = -1;
static gint hf_gluster_brick_status = -1;
static gint hf_gluster_brick_port = -1;

/* Initialize the subtree pointers */
static gint ett_gluster_pmap = -1;

/* PMAP PORTBYBRICK */
static int
gluster_pmap_portbybrick_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_brick_status, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_brick_port, offset);

	return offset;
}

static int
gluster_pmap_portbybrick_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *brick = NULL;
	offset = dissect_rpc_string(tvb, tree, hf_gluster_brick, offset,
								&brick);
	return offset;
}

/* GLUSTER_PMAP_PROGRAM from xlators/mgmt/glusterd/src/glusterd-pmap.c */
static const vsff gluster_pmap_proc[] = {
	{ GF_PMAP_NULL, "NULL", NULL, NULL },
	{
		GF_PMAP_PORTBYBRICK, "PORTBYBRICK",
		gluster_pmap_portbybrick_call, gluster_pmap_portbybrick_reply
	},
	{ GF_PMAP_BRICKBYPORT, "BRICKBYPORT", NULL, NULL },
	{ GF_PMAP_SIGNIN, "SIGNIN", NULL, NULL },
	{ GF_PMAP_SIGNOUT, "SIGNOUT", NULL, NULL },
	{ GF_PMAP_SIGNUP, "SIGNUP", NULL, NULL },
	{ 0, NULL, NULL, NULL }
};
static const value_string gluster_pmap_proc_vals[] = {
	{ GF_PMAP_NULL, "NULL" },
	{ GF_PMAP_PORTBYBRICK, "PORTBYBRICK" },
	{ GF_PMAP_BRICKBYPORT, "BRICKBYPORT" },
	{ GF_PMAP_SIGNIN, "SIGNIN" },
	{ GF_PMAP_SIGNOUT, "SIGNOUT" },
	{ GF_PMAP_SIGNUP, "SIGNUP" },
	{ 0, NULL }
};

void
proto_register_gluster_pmap(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		/* programs */
		{ &hf_gluster_pmap_proc,
			{ "Gluster Portmap", "gluster.pmap", FT_UINT32,
				BASE_DEC, VALS(gluster_pmap_proc_vals), 0,
				NULL, HFILL }
		},
		{ &hf_gluster_brick,
			{ "Brick", "gluster.brick", FT_STRINGZ, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_brick_status,
			{ "Status", "gluster.brick.status", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_brick_port,
			{ "Port", "gluster.brick.port", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_gluster_pmap
	};

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_gluster, hf, array_length(hf));

	proto_gluster_pmap = proto_register_protocol("Gluster Portmap",
					"Gluster Portmap", "gluster-pmap");
}

void
proto_reg_handoff_gluster_pmap(void)
{
	rpc_init_prog(proto_gluster_pmap, GLUSTER_PMAP_PROGRAM,
							ett_gluster_pmap);
	rpc_init_proc_table(GLUSTER_PMAP_PROGRAM, 1, gluster_pmap_proc,
							hf_gluster_pmap_proc);
}

