/* packet-http2.c
 * Routines for HTTP2-draft-04 dissection
 * Copyright 2013, Stephen Ludin <sludin@ludin.org>
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
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-ssl.h"
#include "packet-tcp.h"


/* Forward declaration that is needed below if using the
 * proto_reg_handoff_http2 function as a callback for when protocol
 * preferences get changed. */
void proto_reg_handoff_http2(void);

#define FRAME_HEADER_LENGTH    8
#define MAGIC_FRAME_LENGTH    24
#define DEFAULT_PORT         443
#define ALTERNATE_PORT      8443

typedef struct
{
        unsigned short length;
        unsigned char  type;
        unsigned char  flags;
        unsigned int   streamid;
} http2_frame_header;

static const value_string frametypenames[] = {
        { 0, "DATA" },
        { 1, "HEADERS" },
        { 3, "RST_STREAM" },
        { 4, "SETTINGS" },
        { 5, "PUSH_PROMISE" },
        { 6, "PING" },
        { 7, "GOAWAY" },
        { 9, "WINDOW_UPDATE" },
        { 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_http2       = -1;
static int hf_http2_length   = -1;
static int hf_http2_type     = -1;
static int hf_http2_flags    = -1;
static int hf_http2_streamid = -1;
static int hf_http2_payload  = -1;
static int hf_http2_magic    = -1;

/* Initialize the subtree pointers */
static gint ett_http2          = -1;
static gint ett_http2_length   = -1;
static gint ett_http2_type     = -1;
static gint ett_http2_flags    = -1;
static gint ett_http2_streamid = -1;
static gint ett_http2_payload  = -1;
static gint ett_http2_magic    = -1;

static    guint8 kMagicHello[] = {
        0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54,
        0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
        0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a
};

static dissector_handle_t http2_handle;


static void
dissect_http2_frame_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
        proto_item *ti;
        proto_tree *http2_tree;
        guint32 offset = 0;
    
        http2_frame_header frame;

        /* tvb_memeql makes certain there are enough bytes in the buffer.
         * returns -1 if there are not enough bytes or if there is not a
         * match.  Returns 0 on a match */
        if ( tvb_memeql( tvb, offset, kMagicHello, MAGIC_FRAME_LENGTH ) == 0 )
        {
                col_append_sep_str( pinfo->cinfo, COL_INFO, ", ", "Magic" );
                
                ti = proto_tree_add_item(tree, proto_http2, tvb, offset, MAGIC_FRAME_LENGTH, ENC_NA);
                proto_item_append_text( ti, ", Magic" );
                
                http2_tree = proto_item_add_subtree(ti, ett_http2);
                
                proto_tree_add_item(http2_tree, hf_http2_magic, tvb,
                                    offset, MAGIC_FRAME_LENGTH, ENC_BIG_ENDIAN);
                return;
        }


        frame.length   = tvb_get_ntohs( tvb, offset + 0 );
        frame.type     = tvb_get_guint8( tvb, offset + 2 );
        frame.flags    = tvb_get_guint8( tvb, offset + 3 );
        frame.streamid = tvb_get_ntohl( tvb, offset + 4 );

        col_append_sep_fstr( pinfo->cinfo, COL_INFO, ", ", "%s",
                             val_to_str( frame.type, frametypenames, "Unknown (0x%02X)" ) );

    
        /* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_http2, tvb, offset, FRAME_HEADER_LENGTH + frame.length, ENC_NA);

        proto_item_append_text( ti, ", %s", val_to_str( frame.type, frametypenames, "Unknown (0x%02X)" ) );
        proto_item_append_text( ti, ", Length: %d, Flags: %d, streamid: %d",
                                frame.length, frame.flags, frame.streamid );
    
        http2_tree = proto_item_add_subtree(ti, ett_http2);

        /* Add an item to the subtree, see section 1.6 of README.developer for more
         * information. */
        proto_tree_add_item(http2_tree, hf_http2_length, tvb,
                            offset + 0, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(http2_tree, hf_http2_type, tvb,
                            offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(http2_tree, hf_http2_flags, tvb,
                            offset + 3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(http2_tree, hf_http2_streamid, tvb,
                            offset + 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(http2_tree, hf_http2_payload, tvb,
                            offset + 8, frame.length, ENC_BIG_ENDIAN);

        offset += frame.length + FRAME_HEADER_LENGTH;

        return;
}

static guint get_http2_message_len( packet_info *pinfo, tvbuff_t *tvb, int offset )
{
        (void)(pinfo); /* Avoid the unused parameter warning */

        if ( tvb_memeql( tvb, offset, kMagicHello, MAGIC_FRAME_LENGTH ) == 0 ) {
                return MAGIC_FRAME_LENGTH;
        }

        return (guint)tvb_get_ntohs(tvb, offset) + FRAME_HEADER_LENGTH;
}


static int
dissect_http2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
              void *data _U_)
{
        /* Check that there's enough data */
        if (tvb_length(tvb) < FRAME_HEADER_LENGTH)
                return 0;
    
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "http2");
        col_clear(pinfo->cinfo, COL_INFO);
    
        tcp_dissect_pdus( tvb, pinfo, tree, TRUE, FRAME_HEADER_LENGTH,
                          get_http2_message_len, dissect_http2_frame_pdu );

        return tvb_length(tvb); 
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_http2(void)
{
        static hf_register_info hf[] = {
                { &hf_http2_length,
                  { "Length", "http2.length",
                    FT_UINT16, BASE_DEC, NULL, 0x0,
                    "Frame Length", HFILL }
                },
                { &hf_http2_type,
                  { "Type", "http2.type",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "Frame Type", HFILL }
                },
                { &hf_http2_flags,
                  { "Flags", "http2.flags",
                    FT_UINT8, BASE_DEC, NULL, 0x0,
                    "Frame Flags", HFILL }
                },
                { &hf_http2_streamid,
                  { "StreamID", "http2.streamid",
                    FT_UINT32, BASE_DEC, NULL, 0x0,
                    "Frame StreamID", HFILL }
                },
                { &hf_http2_payload,
                  { "Payload", "http2.payload",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    "Frame Payload", HFILL }
                },
                { &hf_http2_magic,
                  { "Magic", "http2.magix",
                    FT_BYTES, BASE_NONE, NULL, 0x0,
                    "HTTP2 Magic", HFILL }
                }
        };

        /* Setup protocol subtree array */
        static gint *ett[] = {
                &ett_http2,
                &ett_http2_length,
                &ett_http2_type,
                &ett_http2_flags,
                &ett_http2_streamid,
                &ett_http2_payload,
                &ett_http2_magic
            
        };


        /* Register the protocol name and description */
        proto_http2 = proto_register_protocol("HTTP-draft-04/2.0",
                                              "http-2.0", "http2");

        http2_handle = new_register_dissector("http2", dissect_http2, proto_http2);

        /* Required function calls to register the header fields and subtrees */
        proto_register_field_array(proto_http2, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));

}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
void
proto_reg_handoff_http2(void)
{
        static gboolean initialized = FALSE;
        static int currentPort;

        if (!initialized) {
                /* Use new_create_dissector_handle() to indicate that
                 * dissect_http2() returns the number of bytes it dissected (or 0
                 * if it thinks the packet does not belong to HTTP-draft-04/2.0).
                 */
                http2_handle = new_create_dissector_handle(dissect_http2,
                                                           proto_http2);
                initialized = TRUE;

        } else {
                /* If you perform registration functions which are dependent upon
                 * prefs then you should de-register everything which was associated
                 * with the previous settings and re-register using the new prefs
                 * settings here. In general this means you need to keep track of
                 * the http2_handle and the value the preference had at the time
                 * you registered.  The http2_handle value and the value of the
                 * preference can be saved using local statics in this
                 * function (proto_reg_handoff).
                 */
                dissector_delete_uint("tcp.port", currentPort, http2_handle);
        }

        currentPort = DEFAULT_PORT;

        dissector_add_uint("tcp.port", currentPort, http2_handle);

        ssl_dissector_add( DEFAULT_PORT, "http2", TRUE);
        ssl_dissector_add( ALTERNATE_PORT, "http2", TRUE);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
