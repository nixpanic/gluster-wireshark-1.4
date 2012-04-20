/* packet-gluster_hndsk.c
 * Routines for Gluster Handshake dissection
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
static gint proto_gluster_hndsk = -1;

/* programs and procedures */
static gint hf_gluster_hndsk_proc = -1;

/* Initialize the subtree pointers */
static gint ett_gluster_hndsk = -1;

static int
gluster_hndsk_ping_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
							proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	return offset;
}

static int
gluster_hndsk_setvolume_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);
	return offset;
}

static int
gluster_hndsk_setvolume_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);
	return offset;
}

/* procedures for GLUSTER_HNDSK_PROGRAM */
static const vsff gluster_hndsk_proc[] = {
	{ GF_HNDSK_NULL, "NULL", NULL, NULL },
	{
		GF_HNDSK_SETVOLUME, "SETVOLUME",
		gluster_hndsk_setvolume_call, gluster_hndsk_setvolume_reply
	},
	{ GF_HNDSK_GETSPEC, "GETSPEC", NULL, NULL },
	{ GF_HNDSK_PING, "PING", NULL, gluster_hndsk_ping_reply },
	{ 0, NULL, NULL, NULL }
};
static const value_string gluster_hndsk_proc_vals[] = {
	{ GF_HNDSK_NULL, "NULL" },
	{ GF_HNDSK_SETVOLUME, "DUMP" },
	{ GF_HNDSK_GETSPEC, "GETSPEC" },
	{ GF_HNDSK_PING, "PING" },
	{ 0, NULL }
};

void
proto_register_gluster_hndsk(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		/* programs */
		{ &hf_gluster_hndsk_proc,
			{ "Gluster Handshake", "gluster.hndsk", FT_UINT32,
				BASE_DEC, VALS(gluster_hndsk_proc_vals), 0,
				NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_gluster_hndsk
	};

	/* Register the protocol name and description */
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_gluster, hf, array_length(hf));

	proto_gluster_hndsk = proto_register_protocol("GlusterFS Handshake",
					"GlusterFS Handshake", "gluster-hndsk");
}

void
proto_reg_handoff_gluster_hndsk(void)
{
	rpc_init_prog(proto_gluster_hndsk, GLUSTER_HNDSK_PROGRAM,
							ett_gluster_hndsk);
	rpc_init_proc_table(GLUSTER_HNDSK_PROGRAM, 1, gluster_hndsk_proc,
							hf_gluster_hndsk_proc);
}

