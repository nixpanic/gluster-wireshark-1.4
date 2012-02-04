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
static gint proto_gluster = -1;
static gint proto_gluster_dump = -1;
static gint proto_gluster_mgmt = -1;
static gint proto_gd_mgmt = -1;
static gint proto_gluster_hndsk = -1;
static gint proto_gluster_cli = -1;
static gint proto_gluster_pmap = -1;
static gint proto_gluster_cbk = -1;
static gint proto_gluster_fs = -1;
static gint proto_gluster3_1_fop = -1;


/* programs and procedures */
static gint hf_gluster_dump_proc = -1;
static gint hf_gluster_mgmt_proc = -1;
static gint hf_gd_mgmt_proc = -1;
static gint hf_gluster_hndsk_proc = -1;
static gint hf_gluster_cli_proc = -1;
static gint hf_gluster_pmap_proc = -1;
static gint hf_gluster_cbk_proc = -1;
static gint hf_gluster_fs_proc = -1;
static gint hf_gluster3_1_fop_proc = -1;

/* fields used by multiple programs/procedures */
static gint hf_gluster_gfsid = -1;
static gint hf_gluster_gfid = -1;
static gint hf_gluster_pargfid = -1;
static gint hf_gluster_progname = -1;
static gint hf_gluster_prognum = -1;
static gint hf_gluster_progver = -1;
static gint hf_gluster_brick = -1;
static gint hf_gluster_op = -1;
static gint hf_gluster_op_ret = -1;
static gint hf_gluster_op_errno = -1;
static gint hf_gluster_op_errstr = -1;
static gint hf_gluster_flags = -1;
static gint hf_gluster_path = -1;
static gint hf_gluster_bname = -1;
static gint hf_gluster_brick_status = -1;
static gint hf_gluster_brick_port = -1;
static gint hf_gluster_dict_key = -1;
static gint hf_gluster_dict_value = -1;

static gint hf_gluster_uuid = -1;
static gint hf_gluster_hostname = -1;
static gint hf_gluster_port = -1;
static gint hf_gluster_vols = -1;

/* gf_iatt */
static gint hf_gluster_ia_ino = -1;
static gint hf_gluster_ia_dev = -1;
static gint hf_gluster_mode = -1;
static gint hf_gluster_ia_nlink = -1;
static gint hf_gluster_ia_uid = -1;
static gint hf_gluster_ia_gid = -1;
static gint hf_gluster_ia_rdev = -1;
static gint hf_gluster_ia_size = -1;
static gint hf_gluster_ia_blksize = -1;
static gint hf_gluster_ia_blocks = -1;
static gint hf_gluster_ia_atime = -1;
static gint hf_gluster_ia_atime_nsec = -1;
static gint hf_gluster_ia_mtime = -1;
static gint hf_gluster_ia_mtime_nsec = -1;
static gint hf_gluster_ia_ctime = -1;
static gint hf_gluster_ia_ctime_nsec = -1;

/* temporarily used during development */
static gint hf_gluster_dict = -1;
static gint hf_gluster_unknown_int = -1;

/* Initialize the subtree pointers */
static gint ett_gluster = -1;
static gint ett_gluster_dump = -1;
static gint ett_gluster_mgmt = -1;
static gint ett_gd_mgmt = -1;
static gint ett_gluster_hndsk = -1;
static gint ett_gluster_cli = -1;
static gint ett_gluster_pmap = -1;
static gint ett_gluster_cbk = -1;
static gint ett_gluster_fs = -1;
static gint ett_gluster3_1_fop = -1;
static gint ett_gluster_dict = -1;
static gint ett_gluster_iatt = -1;


/* function for dissecting and adding a gluster dict_t to the tree */
static int
gluster_rpc_dissect_dict(proto_tree *tree, tvbuff_t *tvb /* FIXME: add ", int hfindex" */, int offset)
{
	gchar *key, *value;
	gint items, i, len, roundup, value_len, key_len;

	proto_item *dict_item;
	proto_tree *dict_tree;

	len = tvb_get_ntohl(tvb, offset);
	roundup = rpc_roundup(len) - len;
	proto_tree_add_text(tree, tvb, offset, 4, "Size of the dict: %d (%d bytes inc. RPC-roundup)", len, rpc_roundup(len));
	offset += 4;

	if (len == 0)
		return offset;

	items = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Items in the dict: %d", items);
	offset += 4;

	for (i = 0; i < items; i++) {
		dict_item = proto_tree_add_text(tree, tvb, offset, -1, "Item %d", i);
		dict_tree = proto_item_add_subtree(dict_item, ett_gluster_dict);

		/* key_len is the length of the key without the terminating '\0' */
		/* key_len = tvb_get_ntohl(tvb, offset) + 1; // will be read later */
		offset += 4;
		value_len = tvb_get_ntohl(tvb, offset);
		offset += 4;

		/* read the key, '\0' terminated */
		key = tvb_get_stringz(tvb, offset, &key_len);
		if (tree)
			proto_tree_add_string(dict_tree, hf_gluster_dict_key, tvb, offset, key_len, key);
		offset += key_len;
		g_free(key);

		/* read the value, '\0' terminated */
		value = tvb_get_string(tvb, offset, value_len);
		if (tree)
			proto_tree_add_string(dict_tree, hf_gluster_dict_value, tvb, offset, value_len, value);
		offset += value_len;
		g_free(value);
	}

	if (roundup) {
		if (tree)
			proto_tree_add_text(tree, tvb, offset, -1, "RPC-roundup bytes: %d", roundup);
		offset += roundup;
	}

	return offset;
}

static int
gluster_dissect_rpc_uquad_t(tvbuff_t *tvb, proto_tree *tree, int hfindex, int offset)
{
	offset = dissect_rpc_bytes(tvb, tree, hfindex, offset, 8, FALSE, NULL);
	return offset;
}

/*
 * from rpc/xdr/src/glusterfs3-xdr.c:xdr_gf_iatt()
 * FIXME: this may be inclomplete, different code-paths may require different
 * encoding/decoding.
 */
static int
gluster_rpc_dissect_gf_iatt(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_gfid, offset, 16,
								FALSE, NULL);
	offset = gluster_dissect_rpc_uquad_t(tvb, tree, hf_gluster_ia_ino, offset);
	offset = gluster_dissect_rpc_uquad_t(tvb, tree, hf_gluster_ia_dev, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_mode, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_ia_nlink, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_ia_uid, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_ia_gid, offset);
	offset = gluster_dissect_rpc_uquad_t(tvb, tree, hf_gluster_ia_rdev, offset);
	offset = gluster_dissect_rpc_uquad_t(tvb, tree, hf_gluster_ia_size, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_ia_blksize, offset);
	offset = gluster_dissect_rpc_uquad_t(tvb, tree, hf_gluster_ia_blocks, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_ia_atime, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_ia_atime_nsec, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_ia_mtime, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_ia_mtime_nsec, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_ia_ctime, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_ia_ctime_nsec, offset);

	return offset;
}

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
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);

	if (tree)
		proto_tree_add_text(tree, tvb, offset, -1, "FIXME: The data that follows is a xdr_pointer from xdr_gf_prog_detail()");
//	while (offset < tvb_reported_length(tvb))
//		offset = gluster_dump_reply_item(tvb, offset, tree);

	return offset;
}

/* DUMP request */
static int
gluster_dump_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
							proto_tree *tree)
{
	offset = gluster_dissect_rpc_uquad_t(tvb, tree, hf_gluster_gfsid, offset);

	return offset;
}

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
	offset = gluster_rpc_dissect_dict(tree, tvb, offset);
	return offset;
}

static int
gluster_hndsk_setvolume_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	offset = gluster_rpc_dissect_dict(tree, tvb, offset);
	return offset;
}

static int
gluster_hndsk_lookup_reply(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *iatt_item;
	proto_tree *iatt_tree;

	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	// FIXME: describe this better - gf_iatt (xdrs, &objp->stat
	iatt_item = proto_tree_add_text(tree, tvb, offset, -1, "Stat IATT");
	iatt_tree = proto_item_add_subtree(iatt_item, ett_gluster_iatt);
	offset = gluster_rpc_dissect_gf_iatt(iatt_tree, tvb, offset);
	// FIXME: describe this better - gf_iatt (xdrs, &objp->postparent
	iatt_item = proto_tree_add_text(tree, tvb, offset, -1, "PostParent IATT");
	iatt_tree = proto_item_add_subtree(iatt_item, ett_gluster_iatt);
	offset = gluster_rpc_dissect_gf_iatt(iatt_tree, tvb, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, offset);

	return offset;
}

static int
gluster_hndsk_lookup_call(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *path = NULL;
	gchar *bname = NULL;
	guint flags;

	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_gfid, offset, 16,
								FALSE, NULL);
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_pargfid, offset, 16,
								FALSE, NULL);
#if 0 /* example from epan/dissectors/packet-tcp.c */
    tf = proto_tree_add_uint_format(tcp_tree, hf_tcp_flags, tvb, offset + 13, 1,
        tcph->th_flags, "Flags: 0x%02x (%s)", tcph->th_flags, flags_strbuf->str);
    field_tree = proto_item_add_subtree(tf, ett_tcp_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_cwr, tvb, offset + 13, 1, tcph->th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_ecn, tvb, offset + 13, 1, tcph->th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_urg, tvb, offset + 13, 1, tcph->th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_ack, tvb, offset + 13, 1, tcph->th_flags);
    proto_tree_add_boolean(field_tree, hf_tcp_flags_push, tvb, offset + 13, 1, tcph->th_flags);
#endif
	/* FIXME: display as a list of fields */
	flags = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint_format(tree, hf_gluster_flags, tvb, offset, 4, flags, "Flags: 0x%02x", flags);
	offset += 4;
//	field_tree = proto_item_add_subtree(tf, ett_gluster_lookup_flags);
//	proto_tree_add_boolean(field_tree, hf_gluster_lookup_flag_cwr, tvb, offset + 13, 1, tcph->th_flags);

	offset = dissect_rpc_string(tvb, tree, hf_gluster_path, offset, &path);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_bname, offset, &bname);
	offset = gluster_rpc_dissect_dict(tree, tvb, offset);
	
	return offset;
}

static int
gluster_gd_mgmt_probe_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *hostname = NULL;

	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_hostname, offset, &hostname);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);

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
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
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
	/* FIXME: how to call this one? vols? */
	offset = gluster_rpc_dissect_dict(tree, tvb, offset);

	return offset;
}

static int
gluster_gd_mgmt_cluster_lock_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);

	return offset;
}

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
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_op_errstr, offset, &errstr);
	offset = gluster_rpc_dissect_dict(tree, tvb, offset);
	return offset;
}

static int
gluster_gd_mgmt_stage_op_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, offset);

	return offset;
}

static int
gluster_gd_mgmt_commit_op_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	gchar *errstr = NULL;

	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, offset);
	offset = dissect_rpc_string(tvb, tree, hf_gluster_op_errstr, offset, &errstr);
	return offset;
}

static int
gluster_gd_mgmt_commit_op_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op, offset);
	offset = gluster_rpc_dissect_dict(tree, tvb, offset);

	return offset;
}

static int
gluster_gd_mgmt_friend_update_reply(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_ret, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_op_errno, offset);

	return offset;
}

static int
gluster_gd_mgmt_friend_update_call(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	offset = dissect_rpc_bytes(tvb, tree, hf_gluster_uuid, offset, 16 * 4, FALSE, NULL);
	/* FIXME: how to call this one? vols? */
	offset = gluster_rpc_dissect_dict(tree, tvb, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_port, offset);

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
	{ GD_MGMT_CLUSTER_UNLOCK, "GD_MGMT_CLUSTER_UNLOCK", NULL, NULL},
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

/* procedures for GLUSTER_CBK_PROGRAM */
static const vsff gluster_cbk_proc[] = {
        { GF_CBK_NULL, "NULL", NULL, NULL },
        { GF_CBK_FETCHSPEC, "FETCHSPEC", NULL, NULL },
        { GF_CBK_INO_FLUSH, "INO_FLUSH", NULL, NULL },
	{ 0, NULL, NULL, NULL }
};
static const value_string gluster_cbk_proc_vals[] = {
        { GF_CBK_NULL, "NULL" },
        { GF_CBK_FETCHSPEC, "FETCHSPEC" },
        { GF_CBK_INO_FLUSH, "INO_FLUSH" },
	{ 0, NULL }
};

/*
 * procedures for GLUSTERFS_PROGRAM "GlusterFS Mops"
 *
 * This seems to be spread over multiple files (are Call/Reply seperated?)
 * - xlators/mgmt/glusterd/src/glusterd-rpc-ops.c
 * - glusterfsd/src/glusterfsd-mgmt.c
 */
static const vsff gluster_fs_proc[] = {
	{ GD_MGMT_NULL, "NULL", NULL, NULL },
	{ GD_MGMT_BRICK_OP, "BRICK_OP", NULL, NULL },
	{ GF_BRICK_NULL, "NULL", NULL, NULL },
	{ GF_BRICK_TERMINATE, "TERMINATE", NULL, NULL },
	{ GF_BRICK_XLATOR_INFO, "TRANSLATOR INFO", NULL, NULL },
	{ 0, NULL, NULL, NULL }
};
static const value_string gluster_fs_proc_vals[] = {
	{ GD_MGMT_NULL, "NULL" },
	{ GD_MGMT_BRICK_OP, "BRICK_OP" },
	{ GF_BRICK_NULL, "NULL" },
	{ GF_BRICK_TERMINATE, "TERMINATE" },
	{ GF_BRICK_XLATOR_INFO, "TRANSLATOR INFO" },
	{ 0, NULL }
};

/*
 * GLUSTER3_1_FOP_PROGRAM
 * - xlators/protocol/client/src/client3_1-fops.c
 * - xlators/protocol/server/src/server3_1-fops.c
 */
static const vsff gluster3_1_fop_proc[] = {
	{ GFS3_OP_NULL, "NULL", NULL, NULL },
	{ GFS3_OP_STAT, "STAT", NULL, NULL },
	{ GFS3_OP_READLINK, "READLINK", NULL, NULL },
	{ GFS3_OP_MKNOD, "MKNOD", NULL, NULL },
	{ GFS3_OP_MKDIR, "MKDIR", NULL, NULL },
	{ GFS3_OP_UNLINK, "UNLINK", NULL, NULL },
	{ GFS3_OP_RMDIR, "RMDIR", NULL, NULL },
	{ GFS3_OP_SYMLINK, "SYMLINK", NULL, NULL },
	{ GFS3_OP_RENAME, "RENAME", NULL, NULL },
	{ GFS3_OP_LINK, "LINK", NULL, NULL },
	{ GFS3_OP_TRUNCATE, "TRUNCATE", NULL, NULL },
	{ GFS3_OP_OPEN, "OPEN", NULL, NULL },
	{ GFS3_OP_READ, "READ", NULL, NULL },
	{ GFS3_OP_WRITE, "WRITE", NULL, NULL },
	{ GFS3_OP_STATFS, "STATFS", NULL, NULL },
	{ GFS3_OP_FLUSH, "FLUSH", NULL, NULL },
	{ GFS3_OP_FSYNC, "FSYNC", NULL, NULL },
	{ GFS3_OP_SETXATTR, "SETXATTR", NULL, NULL },
	{ GFS3_OP_GETXATTR, "GETXATTR", NULL, NULL },
	{ GFS3_OP_REMOVEXATTR, "REMOVEXATTR", NULL, NULL },
	{ GFS3_OP_OPENDIR, "OPENDIR", NULL, NULL },
	{ GFS3_OP_FSYNCDIR, "FSYNCDIR", NULL, NULL },
	{ GFS3_OP_ACCESS, "ACCESS", NULL, NULL },
	{ GFS3_OP_CREATE, "CREATE", NULL, NULL },
	{ GFS3_OP_FTRUNCATE, "FTRUNCATE", NULL, NULL },
	{ GFS3_OP_FSTAT, "FSTAT", NULL, NULL },
	{ GFS3_OP_LK, "LK", NULL, NULL },
	{ GFS3_OP_LOOKUP, "LOOKUP", gluster_hndsk_lookup_call, gluster_hndsk_lookup_reply },
	{ GFS3_OP_READDIR, "READDIR", NULL, NULL },
	{ GFS3_OP_INODELK, "INODELK", NULL, NULL },
	{ GFS3_OP_FINODELK, "FINODELK", NULL, NULL },
	{ GFS3_OP_ENTRYLK, "ENTRYLK", NULL, NULL },
	{ GFS3_OP_FENTRYLK, "FENTRYLK", NULL, NULL },
	{ GFS3_OP_XATTROP, "XATTROP", NULL, NULL },
	{ GFS3_OP_FXATTROP, "FXATTROP", NULL, NULL },
	{ GFS3_OP_FGETXATTR, "FGETXATTR", NULL, NULL },
	{ GFS3_OP_FSETXATTR, "FSETXATTR", NULL, NULL },
	{ GFS3_OP_RCHECKSUM, "RCHECKSUM", NULL, NULL },
	{ GFS3_OP_SETATTR, "SETATTR", NULL, NULL },
	{ GFS3_OP_FSETATTR, "FSETATTR", NULL, NULL },
	{ GFS3_OP_READDIRP, "READDIRP", NULL, NULL },
	{ GFS3_OP_RELEASE, "RELEASE", NULL, NULL },
	{ GFS3_OP_RELEASEDIR, "RELEASEDIR", NULL, NULL },
	{ 0, NULL, NULL, NULL }
};
static const value_string gluster3_1_fop_proc_vals[] = {
	{ GFS3_OP_NULL, "NULL" },
	{ GFS3_OP_STAT, "STAT" },
	{ GFS3_OP_READLINK, "READLINK" },
	{ GFS3_OP_MKNOD, "MKNOD" },
	{ GFS3_OP_MKDIR, "MKDIR" },
	{ GFS3_OP_UNLINK, "UNLINK" },
	{ GFS3_OP_RMDIR, "RMDIR" },
	{ GFS3_OP_SYMLINK, "SYMLINK" },
	{ GFS3_OP_RENAME, "RENAME" },
	{ GFS3_OP_LINK, "LINK" },
	{ GFS3_OP_TRUNCATE, "TRUNCATE" },
	{ GFS3_OP_OPEN, "OPEN" },
	{ GFS3_OP_READ, "READ" },
	{ GFS3_OP_WRITE, "WRITE" },
	{ GFS3_OP_STATFS, "STATFS" },
	{ GFS3_OP_FLUSH, "FLUSH" },
	{ GFS3_OP_FSYNC, "FSYNC" },
	{ GFS3_OP_SETXATTR, "SETXATTR" },
	{ GFS3_OP_GETXATTR, "GETXATTR" },
	{ GFS3_OP_REMOVEXATTR, "REMOVEXATTR" },
	{ GFS3_OP_OPENDIR, "OPENDIR" },
	{ GFS3_OP_FSYNCDIR, "FSYNCDIR" },
	{ GFS3_OP_ACCESS, "ACCESS" },
	{ GFS3_OP_CREATE, "CREATE" },
	{ GFS3_OP_FTRUNCATE, "FTRUNCATE" },
	{ GFS3_OP_FSTAT, "FSTAT" },
	{ GFS3_OP_LK, "LK" },
	{ GFS3_OP_LOOKUP, "LOOKUP" },
	{ GFS3_OP_READDIR, "READDIR" },
	{ GFS3_OP_INODELK, "INODELK" },
	{ GFS3_OP_FINODELK, "FINODELK" },
	{ GFS3_OP_ENTRYLK, "ENTRYLK" },
	{ GFS3_OP_FENTRYLK, "FENTRYLK" },
	{ GFS3_OP_XATTROP, "XATTROP" },
	{ GFS3_OP_FXATTROP, "FXATTROP" },
	{ GFS3_OP_FGETXATTR, "FGETXATTR" },
	{ GFS3_OP_FSETXATTR, "FSETXATTR" },
	{ GFS3_OP_RCHECKSUM, "RCHECKSUM" },
	{ GFS3_OP_SETATTR, "SETATTR" },
	{ GFS3_OP_FSETATTR, "FSETATTR" },
	{ GFS3_OP_READDIRP, "READDIRP" },
	{ GFS3_OP_RELEASE, "RELEASE" },
	{ GFS3_OP_RELEASEDIR, "RELEASEDIR" },
	{ 0, NULL }
};

void
proto_register_gluster(void)
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
		{ &hf_gluster_mgmt_proc,
			{ "Gluster Management", "gluster.mgmt", FT_UINT32,
				BASE_DEC, VALS(gluster_mgmt_proc_vals), 0,
				NULL, HFILL }
		},
		{ &hf_gd_mgmt_proc,
			{ "Gluster Daemon Management", "glusterd.mgmt",
				FT_UINT32, BASE_DEC, VALS(gd_mgmt_proc_vals),
				0, NULL, HFILL }
		},
		{ &hf_gluster_hndsk_proc,
			{ "Gluster Handshake", "gluster.hndsk", FT_UINT32,
				BASE_DEC, VALS(gluster_hndsk_proc_vals), 0,
				NULL, HFILL }
		},
		{ &hf_gluster_cli_proc,
			{ "Gluster CLI", "gluster.cli", FT_UINT32, BASE_DEC,
				VALS(gluster_cli_proc_vals), 0, NULL, HFILL }
		},
		{ &hf_gluster_pmap_proc,
			{ "Gluster Portmap", "gluster.pmap", FT_UINT32,
				BASE_DEC, VALS(gluster_pmap_proc_vals), 0,
				NULL, HFILL }
		},
		{ &hf_gluster_cbk_proc,
			{ "GlusterFS Callback", "gluster.cbk", FT_UINT32,
				BASE_DEC, VALS(gluster_cbk_proc_vals), 0, NULL,
				HFILL }
		},
		{ &hf_gluster_fs_proc,
			{ "GlusterFS Mops", "gluster.mops", FT_UINT32,
				BASE_DEC, VALS(gluster_fs_proc_vals), 0, NULL,
				HFILL }
		},
		{ &hf_gluster3_1_fop_proc,
			{ "GlusterFS", "glusterfs", FT_UINT32, 	BASE_DEC,
				VALS(gluster3_1_fop_proc_vals), 0, NULL, HFILL }
		},
		/* fields used by procedures */
		{ &hf_gluster_unknown_int,
			{ "Unknown Integer", "gluster.unknown.int", FT_UINT32,
				BASE_HEX, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_gfsid,
			{ "GFS ID", "gluster.gfsid", FT_BYTES,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_gfid,
			{ "GFID", "gluster.gfid", FT_BYTES,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_pargfid,
			{ "PARGFID (FIXME?)", "gluster.pargfid", FT_BYTES,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_brick,
			{ "Brick", "gluster.brick", FT_STRINGZ, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_op,
			{ "Operation (FIXME?)", "gluster.op", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_op_ret,
			{ "Return value", "gluster.op_ret", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_op_errno,
			{ "Errno", "gluster.op_errno", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_op_errstr,
			{ "Error String", "gluster.op_errstr", FT_STRING,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_flags,
			{ "Flags", "gluster.flags", FT_UINT32, BASE_OCT,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_path,
			{ "Path", "gluster.path", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_bname,
			{ "BNAME (FIXME!)", "gluster.bname", FT_STRING, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_brick_status,
			{ "Status", "gluster.brick.status", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_brick_port,
			{ "Port", "gluster.brick.port", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
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
			{ "Volumes", "gluster.vols", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},

		{ &hf_gluster_ia_ino,
			{ "is_ino", "gluster.ia_ino", FT_BYTES, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_ia_dev,
			{ "ia_dev", "gluster.ia_dev", FT_BYTES, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_mode,
			{ "mode", "gluster.mode", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_ia_nlink,
			{ "ia_nlink", "gluster.ia_nlink", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_ia_uid,
			{ "ia_uid", "gluster.ia_uid", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_ia_gid,
			{ "ia_gid", "gluster.ia_gid", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_ia_rdev,
			{ "ia_rdev", "gluster.ia_rdev", FT_BYTES, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_ia_size,
			{ "ia_size", "gluster.ia_size", FT_BYTES, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_ia_blksize,
			{ "ia_blksize", "gluster.ia_blksize", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_ia_blocks,
			{ "ia_blocks", "gluster.brick.status", FT_BYTES, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_ia_atime,
			{ "ia_time", "gluster.brick.status", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_ia_atime_nsec,
			{ "ia_atime_nsec", "gluster.brick.status", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_ia_mtime,
			{ "ia_mtime", "gluster.brick.status", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_ia_mtime_nsec,
			{ "ia_mtime_msec", "gluster.brick.status", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_ia_ctime,
			{ "ia_ctime", "gluster.brick.status", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_ia_ctime_nsec,
			{ "ia_ctime_nsec", "gluster.brick.status", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},

		{ &hf_gluster_dict,
			{ "Dict (unparsed)", "gluster.dict", FT_STRING, BASE_NONE,
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
		&ett_gluster_dump,
		&ett_gluster_mgmt,
		&ett_gd_mgmt,
		&ett_gluster_hndsk,
		&ett_gluster_cli,
		&ett_gluster_pmap,
		&ett_gluster_cbk,
		&ett_gluster_fs,
		&ett_gluster3_1_fop,
		&ett_gluster_dict,
		&ett_gluster_iatt
	};

	/* Register the protocol name and description */
	proto_gluster = proto_register_protocol("Gluster", "Gluster",
								"gluster");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_gluster, hf, array_length(hf));

	proto_gluster_dump = proto_register_protocol("Gluster Dump",
					"Gluster Dump", "gluster-dump");

	proto_gluster_mgmt = proto_register_protocol("Gluster Management",
					"Gluster Management", "gluster-mgmt");

	proto_gd_mgmt = proto_register_protocol("Gluster Daemon Management",
					"GlusterD Management", "gd-mgmt");

	proto_gluster_hndsk = proto_register_protocol("GlusterFS Handshake",
					"GlusterFS Handshake", "gluster-hndsk");

	proto_gluster_cli = proto_register_protocol("Gluster CLI",
					"Gluster CLI", "gluster-cli");

	proto_gluster_pmap = proto_register_protocol("Gluster Portmap",
					"Gluster Portmap", "gluster-pmap");

	proto_gluster_cbk = proto_register_protocol("GlusterFS Callback",
					"GlusterFS Callback", "gluster-cbk");

	proto_gluster_fs = proto_register_protocol("GlusterFS Mops",
					"GlusterFS Mops", "gluster-mops");

	proto_gluster3_1_fop = proto_register_protocol("GlusterFS",
				"GlusterFS", "glusterfs");
}


void
proto_reg_handoff_gluster(void)
{
	rpc_init_prog(proto_gluster_dump, GLUSTER_DUMP_PROGRAM,
							ett_gluster_dump);
	rpc_init_proc_table(GLUSTER_DUMP_PROGRAM, 1, gluster_dump_proc,
							hf_gluster_dump_proc);

	rpc_init_prog(proto_gluster_mgmt, GLUSTERD1_MGMT_PROGRAM,
							ett_gluster_mgmt);
	rpc_init_proc_table(GLUSTERD1_MGMT_PROGRAM, 1, gluster_mgmt_proc,
							hf_gluster_mgmt_proc);

	rpc_init_prog(proto_gd_mgmt, GD_MGMT_PROGRAM, ett_gd_mgmt);
	rpc_init_proc_table(GD_MGMT_PROGRAM, 1, gd_mgmt_proc, hf_gd_mgmt_proc);

	rpc_init_prog(proto_gluster_hndsk, GLUSTER_HNDSK_PROGRAM,
							ett_gluster_hndsk);
	rpc_init_proc_table(GLUSTER_HNDSK_PROGRAM, 1, gluster_hndsk_proc,
							hf_gluster_hndsk_proc);

	rpc_init_prog(proto_gluster_cli, GLUSTER_CLI_PROGRAM, ett_gluster_cli);
	rpc_init_proc_table(GLUSTER_CLI_PROGRAM, 1, gluster_cli_proc,
							hf_gluster_cli_proc);

	rpc_init_prog(proto_gluster_pmap, GLUSTER_PMAP_PROGRAM,
							ett_gluster_pmap);
	rpc_init_proc_table(GLUSTER_PMAP_PROGRAM, 1, gluster_pmap_proc,
							hf_gluster_pmap_proc);

	rpc_init_prog(proto_gluster_cbk, GLUSTER_CBK_PROGRAM, ett_gluster_cbk);
	rpc_init_proc_table(GLUSTER_CBK_PROGRAM, 1, gluster_cbk_proc,
							hf_gluster_cbk_proc);

	rpc_init_prog(proto_gluster_fs, GLUSTERFS_PROGRAM, ett_gluster_fs);
	rpc_init_proc_table(GLUSTERFS_PROGRAM, 1, gluster_fs_proc,
							hf_gluster_fs_proc);

	rpc_init_prog(proto_gluster3_1_fop, GLUSTER3_1_FOP_PROGRAM, ett_gluster3_1_fop);
	rpc_init_proc_table(GLUSTER3_1_FOP_PROGRAM, 310, gluster3_1_fop_proc,
							hf_gluster3_1_fop_proc);
}

