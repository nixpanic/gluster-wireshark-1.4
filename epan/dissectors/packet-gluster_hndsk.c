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
static gint proto_gluster_cbk = -1;
static gint proto_gluster_hndsk = -1;

/* programs and procedures */
static gint hf_gluster_cbk_proc = -1;
static gint hf_gluster_hndsk_proc = -1;
static gint hf_gluster_spec = -1;	/* FETCHSPEC Reply */
static gint hf_gluster_key = -1;	/* FETCHSPEC Call */
static gint hf_gluster_hndsk_event_op = -1;       /* EVENT NOTIFY call */
static gint hf_gluster_uid = -1;              /* LOCK VERSION*/
static gint hf_gluster_lk_ver= -1;
static gint hf_gluster_op_errno = -1;

/* for getspec */
static gint hf_gluster_flags = -1;

/* Initialize the subtree pointers */
static gint ett_gluster_cbk = -1;
static gint ett_gluster_hndsk = -1;

/* procedures for GLUSTER_CBK_PROGRAM */
static int
gluster_cbk_fetchspec_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* spec = NULL;

	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_spec, offset, &spec);

	return offset;
}

static int
gluster_cbk_fetchspec_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* key = NULL;

	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_key, offset, &key);
	
	return offset;
}

static const vsff gluster_cbk_proc[] = {
        { GF_CBK_NULL, "NULL", NULL, NULL },
        {
		GF_CBK_FETCHSPEC, "FETCHSPEC",
		gluster_cbk_fetchspec_call, gluster_cbk_fetchspec_reply,
	},
        { GF_CBK_INO_FLUSH, "INO_FLUSH", NULL, NULL },
	{ 0, NULL, NULL, NULL }
};
static const value_string gluster_cbk_proc_vals[] = {
        { GF_CBK_NULL, "NULL" },
        { GF_CBK_FETCHSPEC, "FETCHSPEC" },
        { GF_CBK_INO_FLUSH, "INO_FLUSH" },
	{ 0, NULL }
};

/* procedures for GLUSTER_HNDSK_PROGRAM */
static int
gluster_hndsk_setvolume_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree);
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

static int
gluster_hndsk_2_setvolume_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);
	return offset;
}

static int
gluster_hndsk_2_setvolume_call(tvbuff_t *tvb, int offset,
                                packet_info *pinfo _U_, proto_tree *tree)
{
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);
	return offset;
}

static int
gluster_hndsk_2_getspec_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* spec = NULL;
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_spec, offset, &spec);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);
	return offset;
}

static int
gluster_hndsk_2_getspec_call(tvbuff_t *tvb, int offset,
                                packet_info *pinfo _U_, proto_tree *tree)
{
	guint flags;
	gchar *key = NULL;
	flags = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint_format(tree, hf_gluster_flags, tvb, offset, 4, flags, "Flags: 0x%02x", flags);
	offset += 4;
	offset = dissect_rpc_string(tvb, tree, hf_gluster_key, offset, &key);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);
	return offset;
}

static int
gluster_hndsk_2_set_lk_ver_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	offset = dissect_rpc_uint32(tvb, tree,hf_gluster_lk_ver, offset);
	return offset;
}

static int
gluster_hndsk_2_set_lk_ver_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar* uid = NULL;
	offset = dissect_rpc_string(tvb, tree, hf_gluster_uid, offset, &uid);
	offset = dissect_rpc_uint32(tvb, tree,hf_gluster_lk_ver, offset);
	return offset;
}

static int
gluster_hndsk_2_event_notify_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_hndsk_event_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);
	return offset;
}

/* In  rpc/xdr/src/glusterfs3-xdr.c. xdr_gf_event_notify_rsp */

static int
gluster_hndsk_2_event_notify_reply(tvbuff_t *tvb, int offset,
                                packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, hf_gluster_dict, offset);
	return offset;
}

static int
gluster_hndsk_2_ping_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
				proto_tree *tree)
{
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	return offset;
}


static const vsff gluster_hndsk_proc[] = {
	{ GF_HNDSK_NULL, "NULL", NULL, NULL },
	{
		GF_HNDSK_SETVOLUME, "SETVOLUME",
		gluster_hndsk_setvolume_call, gluster_hndsk_setvolume_reply
	},
	{ GF_HNDSK_GETSPEC, "GETSPEC", NULL, NULL },
	{ GF_HNDSK_PING, "PING", NULL, gluster_dissect_common_reply },
	{ 0, NULL, NULL, NULL }
};

static const vsff gluster_hndsk_2_proc[] = {
	{ GF_HNDSK_NULL, "NULL", NULL, NULL },
	{
		GF_HNDSK_SETVOLUME, "SETVOLUME",
		gluster_hndsk_2_setvolume_call, gluster_hndsk_2_setvolume_reply
	},
	{
		GF_HNDSK_GETSPEC, "GETSPEC",
		gluster_hndsk_2_getspec_call,gluster_hndsk_2_getspec_reply
	},
	{ GF_HNDSK_PING, "PING", NULL, gluster_hndsk_2_ping_reply },
	{
		GF_HNDSK_SET_LK_VER,"LOCK VERSION",
		gluster_hndsk_2_set_lk_ver_call, gluster_hndsk_2_set_lk_ver_reply
	},
	{
		GF_HNDSK_EVENT_NOTIFY, "EVENTNOTIFY",
		gluster_hndsk_2_event_notify_call, gluster_hndsk_2_event_notify_reply
	},
	{ 0, NULL, NULL, NULL }
};


static const value_string gluster_hndsk_proc_vals[] = {
	{ GF_HNDSK_NULL, "NULL" },
	{ GF_HNDSK_SETVOLUME, "DUMP" },
	{ GF_HNDSK_GETSPEC, "GETSPEC" },
	{ GF_HNDSK_PING, "PING" },
	{ GF_HNDSK_SET_LK_VER,"LOCK VERSION" },
	{ GF_HNDSK_EVENT_NOTIFY, "EVENTNOTIFY" },
	{ 0, NULL }
};

void
proto_register_gluster_hndsk(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		/* programs */
		{ &hf_gluster_cbk_proc,
			{ "GlusterFS Callback", "gluster.cbk", FT_UINT32,
				BASE_DEC, VALS(gluster_cbk_proc_vals), 0, NULL,
				HFILL }
		},
		{ &hf_gluster_hndsk_proc,
			{ "Gluster Handshake", "gluster.hndsk", FT_UINT32,
				BASE_DEC, VALS(gluster_hndsk_proc_vals), 0,
				NULL, HFILL }
		},
		/* fields used by GlusterFS Callback */
		{ &hf_gluster_spec,
			/* FIXME: rename spec to something clearer */
			{ "Spec", "gluster.fetchspec", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_key,
			{ "Key", "gluster.fetchspec.key", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		/* For Gluster handshake event notify */
                { &hf_gluster_hndsk_event_op,
                       { "Event Op", "gluster.event_notify_op", FT_UINT32, BASE_DEC,
                                 NULL, 0, NULL, HFILL }
                },/*For hand shake set_lk_ver */
		{ &hf_gluster_uid,
			{ "Name", "gluster.uid", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_lk_ver,
			{ "Event Op", "gluster.lk_ver", FT_UINT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_flags,
			{ "Flags", "gluster.flags", FT_UINT32, BASE_OCT,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_op_errno,
			{ "Errno", "gluster.op_errno", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		}
};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_gluster_cbk,
		&ett_gluster_hndsk
	};

	/* Register the protocol name and description */
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_gluster, hf, array_length(hf));

	proto_gluster_cbk = proto_register_protocol("GlusterFS Callback",
					"GlusterFS Callback", "gluster-cbk");

	proto_gluster_hndsk = proto_register_protocol("GlusterFS Handshake",
					"GlusterFS Handshake", "gluster-hndsk");
}

void
proto_reg_handoff_gluster_hndsk(void)
{
	rpc_init_prog(proto_gluster_cbk, GLUSTER_CBK_PROGRAM, ett_gluster_cbk);
	rpc_init_proc_table(GLUSTER_CBK_PROGRAM, 1, gluster_cbk_proc,
							hf_gluster_cbk_proc);

	rpc_init_prog(proto_gluster_hndsk, GLUSTER_HNDSK_PROGRAM,
							ett_gluster_hndsk);
	rpc_init_proc_table(GLUSTER_HNDSK_PROGRAM, 1, gluster_hndsk_proc,
							hf_gluster_hndsk_proc);
	rpc_init_proc_table(GLUSTER_HNDSK_PROGRAM, 2, gluster_hndsk_2_proc,
							hf_gluster_hndsk_proc);
}

