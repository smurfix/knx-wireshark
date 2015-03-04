/*
 Copyright 2009 Harald Weillechner, Daniel Lechner
 see COPYING file for details.
 ============================================================================
 Name        : packet-knxnetip
 Author      : Harald Weillechner, Daniel Lechner
 Version     : 0.0.4
 Licence     : GPL
 Description : Wireshark dissector for KNXnet/IP packets
 ============================================================================
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>

#include <string.h>

//Max string size is 5+1 -> two nibbles =2x4bit -biggest number is 15 =2x 2characters  + "." + "\0"
#define KNXNETIP_MAX_VERSION_STRING_SIZE 6
//biggest number is 15.15.255 -> 9 character+ "\0" = 10
#define KNXNETIP_MAX_KNX_ADDRESS_STRING_SIZE 10
//actual version number is 1.0 = 0x10
#define KNXNETIP_PROTOCOL_VERSION 0x10
#define KNXNETIP_HEADER_LENGTH 0x06


#define PROTO_TAG_KNXNET    "KNXnet/IP"

#define _SEARCH_REQ 0x0201
#define _SEARCH_RES 0x0202
#define _DESCRIPTION_REQ 0x0203
#define _DESCRIPTION_RES 0x0204
#define _CONNECT_REQ 0x0205
#define _CONNECT_RES 0x0206
#define _CONNECTIONSTATE_REQ 0x0207
#define _CONNECTIONSTATE_RES 0x0208
#define _DISCONNECT_REQ 0x0209
#define _DISCONNECT_RES 0x020A
#define _TUNNELLING_REQ 0x0420
#define _TUNNELLING_ACK 0x0421
#define _ROUTING_IND 0x0530
#define _ROUTING_LOM 0x0531
#define _DEVICE_CONFIGURATION_REQUEST 0x0310
#define _DEVICE_CONFIGURATION_ACK 0x0311


guint16 convert_uint16(guint16 in)
{ /*converts little endian to big endian and vice versa*/
  guint16 out;
  char *p_in = (char *) &in;
  char *p_out = (char *) &out;
  p_out[0] = p_in[1];
  p_out[1] = p_in[0];
  return out;
}


/* Wireshark ID of the knxnet_ip protocol */
static int proto_knxnet_ip = -1;

/* These are the handles of our subdissectors */
// static dissector_table_t knxnetip_dissector_table;
static heur_dissector_list_t heur_subdissector_list;
// static dissector_handle_t data_handle;

//static dissector_handle_t knxnet_ip_handle;
//static dissector_handle_t knxnet_ip_body_handle;
static gboolean dissect_knxnet_ip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *unused);

//static int global_knxnet_ip_port = 3671;

static const true_false_string on_off_flg = {
  "On",
  "Off"
};

static const value_string knxnetip_service_type[] = {
    { _SEARCH_REQ, "SEARCH_REQUEST" },
    { _SEARCH_RES, "SEARCH_RESPONSE" },
    { _DESCRIPTION_REQ, "DESCRIPTION_REQUEST" },
    { _DESCRIPTION_RES, "DESCRIPTION_RESPONSE" },
    { _CONNECT_REQ, "CONNECT_REQUEST" },
    { _CONNECT_RES, "CONNECT_RESPONSE" },
    { _CONNECTIONSTATE_REQ, "CONNECTIONSTATE_REQUEST" },
    { _CONNECTIONSTATE_RES, "CONNECTIONSTATE_RESPONSE" },
    { _DISCONNECT_REQ, "DISCONNECT_REQUEST" },
    { _DISCONNECT_RES, "DISCONNECT_RESPONSE" },
    {_DEVICE_CONFIGURATION_REQUEST,"DEVICE_CONFIGURATION_REQUEST"},
    {_DEVICE_CONFIGURATION_ACK,"DEVICE_CONFIGURATION_ACK"},
    { _TUNNELLING_REQ, "TUNNELLING_REQUEST" },
    { _TUNNELLING_ACK, "TUNNELLING_ACK" },
    { _ROUTING_IND, "ROUTING_INDICATION" },
    { _ROUTING_LOM, "ROUTING_LOST_MESSAGE" },
    { 0, NULL }
};

static const value_string knxnetip_host_protocol_code[] = {
    { 0x01, "IPV4_UDP" },
    { 0x02, "IPV4_TCP" },
    { 0, NULL }
};

static const value_string knxnetip_connect_response_status[] = {
    { 0x00, "E_NO_ERROR - The connection was established succesfully" },
    { 0x22, "E_CONNECTION_TYPE - The requested connection type is not supported by the KNXnet/IP server device" },
    { 0x23, "E_CONNECTION_OPTION - On or more request connection options are not supported by the KNXnet/IP server device" },
    { 0x24, "E_NO_MORE_CONNECTIONS - The KNXnet/IP server could not accept the new data connection (Maximum reached)" },
    { 0, NULL }
};

static const value_string knxnetip_disconnect_response_status[] = {
    { 0x00, "E_NO_ERROR - The connection was closed succesfully" },
    { 0, NULL }
};

static const value_string knxnetip_configuration_status[] = {
    { 0x00, "E_NO_ERROR - The message was received succesfully" },
    { 0, NULL }
};

static const value_string knxnetip_connectionstate_response_status[] = {
    { 0x00, "E_NO_ERROR - The connection state is normal" },
    { 0x21, "E_CONNECTION_ID - The KNXnet/IP server device could not find an active data connection with the given ID" },
    { 0x26, "E_DATA_CONNECTION - The KNXnet/IP server device detected an erro concerning the Dat connection with the given ID" },
    { 0x27, "E_KNX_CONNECTION - The KNXnet/IP server device detected an error concerning the KNX Bus with the given ID" },
    { 0, NULL }
};

static const value_string knxnetip_connection_types[] = {
    { 0x03, "DEVICE_MANAGEMENT_CONNECTION" },
    { 0x04, "TUNNELING_CONNECTION" },
    { 0x06, "REMOTE_LOGGING_CONNECTION" },
    { 0x07, "REMOTE_CONFIGURATION_CONNECTION" },
    { 0x08, "OBJECT_SERVER_CONNECTION" },
    { 0, NULL }
};

static const value_string knxnetip_description_types[] = {
    { 0x01, "DEVICE_INFO" },
    { 0x02, "SUPP_SVC_FAMILIES - Service families supported by the device" },
    { 0xFE, "MFR_DATA - DIB structure for further data defined by device manufacturer" },
    { 0, NULL }
};

static const value_string knxnetip_tunneling_error_codes[] = {
    { 0x00, "E_NO_ERROR - The message was received succesfully" },
    { 0x29, "E_TUNNELLING_LAYER - The requested tunnelling layer is not supported by the KNXnet/IP Server device" },
    { 0, NULL }
};

static const value_string knxnetip_KNX_medium_codes[] = {
    { 0x01, "TP0" },
    { 0x02, "TP1" },
    { 0x04, "PL110" },
    { 0x08, "PL132" },
    { 0x10, "RF" },
    { 0, NULL }
};

 static const value_string knxnetip_service_families[] = {
    { 0x02, "KNXnet/IP Core" },
    { 0x03, "KNXnet/IP Device Management" },
    { 0x04, "KNXnet/IP Tunneling" },
    { 0x05, "KNXnet/IP Routing" },
    { 0, NULL }
};
/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_knxnet_ip()
*/
//static int hf_knxnet_ip_pdu = -1;
/** Kts attempt at defining the protocol */
static gint hf_knxnet_ip_header = -1;
static gint hf_knxnet_ip_hlength = -1;
static gint hf_knxnet_ip_version = -1;
static gint hf_knxnet_ip_type = -1;
static gint hf_knxnet_ip_tlength = -1;
static gint hf_knxnet_ip_body = -1;

static gint hf_knxnet_ip_hpai = -1;
static gint hf_knxnet_ip_hpai_length = -1;
static gint hf_knxnet_ip_hpai_host_protocol_code = -1;
static gint hf_knxnet_ip_hpai_ip_address = -1;
static gint hf_knxnet_ip_hpai_port_number = -1;

static gint hf_knxnet_ip_communication_channel_id = -1;
static gint hf_knxnet_ip_connect_response_status = -1;
static gint hf_knxnet_ip_connectionstate_response_status = -1;
static gint hf_knxnet_ip_structure_length = -1;
static gint hf_knxnet_ip_connection_type = -1;
static gint hf_knxnet_ip_sequence_counter = -1;
static gint hf_knxnet_ip_reserved = -1;
static gint hf_knxnet_ip_tunnelling_error_code = -1;
static gint hf_knxnet_ip_disconnect_response_status = -1;
static gint hf_knxnet_ip_description_type = -1;
static gint hf_knx_medium_code = -1;
static gint hf_knxnet_ip_device_status = -1;
static gint hf_knxnet_ip_physical_address = -1;
static gint hf_knxnet_ip_project_installation_ID = -1;
static gint hf_knx_serial_number = -1;
static gint hf_knxnet_ip_device_routing_multicast_address = -1;
static gint hf_knxnet_ip_MAC_address = -1;
static gint hf_knxnet_ip_device_friendly_name = -1;

static gint hf_knxnet_ip_service_family_ID = -1;
static gint hf_knxnet_ip_knx_manufacturer_ID = -1;

static gint hf_knxnet_ip_device_configuration_status = -1;

// dummy field to indicate present cEMI record
static gint hf_knxnet_ip_cemi = -1;
static gint hf_knxnet_ip_device_state = -1;
static gint hf_knxnet_ip_number_of_lost_messages = -1;
 

/* static gint hf_knxnet_ip_text = -1;
static gint hf_knx_ip_text2 = -1;
static gint hf_knx_ip_wert2 = -1; */

/* These are the ids of the subtrees that we may be creating */
static gint ett_knxnet_ip = -1;
static gint ett_knxnet_ip_header = -1;
static gint ett_knxnet_ip_hlength = -1;
static gint ett_knxnet_ip_version = -1;
static gint ett_knxnet_ip_type = -1;
static gint ett_knxnet_ip_tlength = -1;
static gint ett_knxnet_ip_body = -1;

static gint ett_knxnet_ip_hpai = -1;
static gint ett_knxnet_ip_hpai_length = -1;
static gint ett_knxnet_ip_hpai_host_protocol_code = -1;
static gint ett_knxnet_ip_hpai_ip_address = -1;
static gint ett_knxnet_ip_hpai_port_number = -1;

static gint ett_knxnet_ip_communication_channel_id = -1;
static gint ett_knxnet_ip_connect_response_status = -1;
static gint ett_knxnet_ip_connectionstate_response_status = -1;
static gint ett_knxnet_ip_structure_length = -1;
static gint ett_knxnet_ip_connection_type = -1;
static gint ett_knxnet_ip_sequence_counter = -1;
static gint ett_knxnet_ip_reserved = -1;
static gint ett_knxnet_ip_tunnelling_error_code = -1;
static gint ett_knxnet_ip_disconnect_response_status = -1;
static gint ett_knxnet_ip_description_type = -1;
static gint ett_knx_medium_code = -1;
static gint ett_knxnet_ip_device_status = -1;
static gint ett_knxnet_ip_physical_address = -1;
static gint ett_knxnet_ip_project_installation_ID = -1;
static gint ett_knx_serial_number = -1;
static gint ett_knxnet_ip_device_routing_multicast_address = -1;
static gint ett_knxnet_ip_MAC_address = -1;
static gint ett_knxnet_ip_device_friendly_name = -1;

static gint ett_knxnet_ip_service_family_ID = -1;
static gint ett_knxnet_ip_knx_manufacturer_ID = -1;

static gint ett_knxnet_ip_device_configuration_status = -1;

static gint ett_knxnet_ip_cemi = -1;
static gint ett_knxnet_ip_device_state = -1;
static gint ett_knxnet_ip_number_of_lost_messages = -1;

void proto_reg_handoff_knxnet_ip(void)
{
    /* static gboolean initialized=FALSE;

    if (!initialized) {
        data_handle = find_dissector("data");
        knxnet_ip_handle = create_dissector_handle(dissect_knxnet_ip, proto_knxnet_ip);
        dissector_add("udp.port", global_knxnet_ip_port, knxnet_ip_handle);
    } */

    static int KNXnetIP_inited = FALSE;

   // dissector_handle_t KNXnetIP_handle=NULL;



    if ( !KNXnetIP_inited )

    {
//        data_handle = find_dissector("data");

        heur_dissector_add("udp", dissect_knxnet_ip, proto_knxnet_ip);
        heur_dissector_add("tcp", dissect_knxnet_ip, proto_knxnet_ip);

        /* KNXnetIP_handle = new_create_dissector_handle(dissect_knxnet_ip, proto_knxnet_ip);

		dissector_add("ip.proto", IP_PROTO_PROTOABBREV, KNXnetIP_handle); */

//        data_handle = find_dissector("data");
//        knxnet_ip_body_handle = create_dissector_handle(dissect_knxnet_ip_body, proto_knxnet_ip);
//        dissector_add("knxnetip.type", _DEVICE_CONFIGURATION_REQUEST, knxnet_ip_body_handle);

        KNXnetIP_inited = TRUE;

    }

}


void proto_register_knxnet_ip (void)
{
    /* A header field is something you can search/filter on.
    *
    * We create a structure to register our fields. It consists of an
    * array of hf_register_info structures, each of which are of the format
    * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
    */
    static hf_register_info hf[] = {
        { &hf_knxnet_ip_header,
        { "Header", "knxnetip.header", FT_NONE, BASE_NONE, NULL, 0x0,
         "knxnet_ip Header", HFILL }},
        { &hf_knxnet_ip_hlength,
        { "Header Length", "knxnetip.hlen", FT_UINT8, BASE_DEC, NULL, 0x0,
        "knxnet_ip header Length", HFILL }},
        { &hf_knxnet_ip_version,
        { "Protocol Version", "knxnetip.version", FT_NONE, BASE_NONE, NULL, 0x0,
         "Text", HFILL }},
        { &hf_knxnet_ip_type,
        { "Service Type", "knxnetip.type", FT_UINT16, BASE_HEX, VALS(knxnetip_service_type), 0x0,
         "Package Type", HFILL }},
        { &hf_knxnet_ip_tlength,
        { "Total Length", "knxnetip.tlen", FT_UINT16, BASE_DEC, NULL, 0x0,
        "knxnet_ip total Length", HFILL }},
        { &hf_knxnet_ip_body,
        { "Body", "knxnetip.body", FT_NONE, BASE_NONE, NULL, 0x0,
         "knxnet_ip Body", HFILL }},
        { &hf_knxnet_ip_hpai,
        { "Host Protocol Adress Information (HPAI)", "knxnetip.hpai", FT_NONE, BASE_NONE, NULL, 0x0,
         "knxnet_ip HPAI", HFILL }},
        { &hf_knxnet_ip_hpai_length,
        { "HPAI length", "knxnetip.hpai_length", FT_UINT8, BASE_DEC, NULL, 0x0,
         "knxnet_ip HPAI_length", HFILL }},
        { &hf_knxnet_ip_hpai_host_protocol_code,
        { "Host Protocol Code", "knxnetip.hpai_host_protocol_code", FT_UINT8, BASE_HEX, VALS(knxnetip_host_protocol_code), 0x0,
         "knxnet_ip HPAI_host_protocol_code", HFILL }},
        { &hf_knxnet_ip_hpai_ip_address,
        { "IP Address", "knxnetip.hpai_ip_address", FT_IPv4, BASE_NONE, NULL, 0x0,
         "knxnet_ip HPAI_ip_address", HFILL }},
        { &hf_knxnet_ip_hpai_port_number,
        { "Port Number", "knxnetip.hpai_port_number", FT_UINT16, BASE_DEC, NULL, 0x0,
         "knxnet_ip HPAI_port_number", HFILL }},
        { &hf_knxnet_ip_communication_channel_id,
        { "Communication Channel ID", "knxnetip.com_ch_id", FT_UINT8, BASE_DEC, NULL, 0x0,
         "knxnet_ip Communiction Channel ID", HFILL }},
        { &hf_knxnet_ip_connect_response_status,
        { "Status", "knxnetip.connect_response_status", FT_UINT8, BASE_HEX, VALS(knxnetip_connect_response_status), 0x0,
         "knxnet_ip Connect Resonse Status", HFILL }},
        { &hf_knxnet_ip_connectionstate_response_status,
        { "Status", "knxnetip.connectionstate_response_status", FT_UINT8, BASE_HEX, VALS(knxnetip_connectionstate_response_status), 0x0,
         "knxnet_ip Connect Resonse Status", HFILL }},
        { &hf_knxnet_ip_structure_length,
        { "Structure Length", "knxnetip.structure_length", FT_UINT8, BASE_DEC, NULL, 0x0,
         "knxnet_ip Structure Length", HFILL }},
        { &hf_knxnet_ip_connection_type,
        { "Connection Type", "knxnetip.connection_type", FT_UINT8, BASE_HEX, VALS(knxnetip_connection_types), 0x0,
         "knxnet_ip Connection Type", HFILL }},
        { &hf_knxnet_ip_sequence_counter,
        { "Sequence Counter", "knxnetip.sequence_counter", FT_UINT8, BASE_DEC,NULL, 0x0,
         "knxnet_ip Sequence Counter", HFILL }},
		{ &hf_knxnet_ip_reserved,
        { "reserved", "knxnetip.reserved", FT_UINT8, BASE_DEC,NULL, 0x0,
         "knxnet_ip reserved", HFILL }},
        { &hf_knxnet_ip_tunnelling_error_code,
        { "Status", "knxnetip.tunnelling_status", FT_UINT8, BASE_HEX, VALS(knxnetip_tunneling_error_codes), 0x0,
         "knxnet_ip Tunneling Status", HFILL }},
        { &hf_knxnet_ip_disconnect_response_status,
        { "Status", "knxnetip.disconnect_response_status", FT_UINT8, BASE_HEX, VALS(knxnetip_disconnect_response_status), 0x0,
         "knxnet_ip Disconnect Resonse Status", HFILL }},
        { &hf_knxnet_ip_description_type,
        { "Description Type", "knxnetip.description_type", FT_UINT8, BASE_HEX, VALS(knxnetip_description_types), 0x0,
         "knxnet_ip Description Type", HFILL }},
        { &hf_knx_medium_code,
        { "KNX medium", "knxnetip.knx_medium_code", FT_UINT8, BASE_HEX, VALS(knxnetip_KNX_medium_codes), 0x0,
         "knxnet_ip KNX medium code", HFILL }},
        { &hf_knxnet_ip_device_status,
        { "Device Status", "knxnetip.device_status", FT_UINT8,BASE_HEX,NULL, 0x0,
         "knxnet_ip Device Status", HFILL }},
        { &hf_knxnet_ip_physical_address,
        { "Physical / Individual Address", "knxnetip.physical_address", FT_UINT16, BASE_HEX, NULL, 0x0,
         "knxnet_ip Physical Address", HFILL }}, /*FT_ETHER*/
        { &hf_knxnet_ip_project_installation_ID,
        { "Project-Installation ID", "knxnetip.project_installation_ID", FT_UINT16, BASE_HEX, NULL, 0x0,
         "knxnet_ip Project-Installation ID", HFILL }},
        { &hf_knx_serial_number,
        { "KNX Device Serial Number", "knxnetip.knx_device_serial_number", FT_ETHER, BASE_NONE, NULL, 0x0,
         "knxnet_ip KNX Device Serial Number", HFILL }},
        { &hf_knxnet_ip_device_routing_multicast_address,
        { "Device Routing Multicast Address", "knxnetip.device_routing_multicast_address", FT_IPv4, BASE_NONE, NULL, 0x0,
         "knxnet_ip Device Routing Multicast Address", HFILL }},
        { &hf_knxnet_ip_MAC_address,
        { "MAC Address", "knxnetip.mac_address", FT_ETHER, BASE_NONE, NULL, 0x0,
         "knxnet_ip MAC Address", HFILL }},
        { &hf_knxnet_ip_device_friendly_name,
        { "Device Friendly Name", "knxnetip.device_friendly_name", FT_STRING, BASE_NONE, NULL, 0x0,
         "knxnet_ip Device Friendly Name", HFILL }},
        { &hf_knxnet_ip_service_family_ID,
        { "Service Family ID", "knxnetip.service_family_id", FT_UINT8, BASE_HEX, VALS(knxnetip_service_families), 0x0,
         "knxnet_ip Service Family ID", HFILL }},
        { &hf_knxnet_ip_knx_manufacturer_ID,
        { "KNX Manafacturer ID", "knxnetip.knx_manufacturer_ID", FT_UINT16, BASE_HEX, NULL, 0x0,
         "knxnet_ip KNX Manafacturer ID", HFILL }},
        { &hf_knxnet_ip_device_configuration_status,
        { "KNX Manafacturer ID", "knxnetip.knx_manufacturer_ID", FT_UINT8, BASE_HEX, VALS(knxnetip_configuration_status), 0x0,
         "knxnet_ip KNX Manafacturer ID", HFILL }},
         { &hf_knxnet_ip_cemi,
         { "KNX cEMI", "knxnetip.cemi", FT_BYTES, BASE_NONE, NULL, 0x0,
          "knxnet_ip cEMI", HFILL }},
		{ &hf_knxnet_ip_device_state,
        { "DeviceState", "knxnetip.devicestate", FT_UINT8, BASE_HEX, NULL, 0x0,
         "knxnet_ip DeviceState", HFILL }},
		{ &hf_knxnet_ip_number_of_lost_messages,
        { "NumberOfLostMessages", "knxnetip.numberoflostmessages", FT_UINT16, BASE_DEC, NULL, 0x0,
         "knxnet_ip NumberOfLostMessages", HFILL }},
    };
    static gint *ett[] = {
        &ett_knxnet_ip,
        &ett_knxnet_ip_header,
        &ett_knxnet_ip_hlength,
        &ett_knxnet_ip_version,
        &ett_knxnet_ip_type,
        &ett_knxnet_ip_tlength,
        &ett_knxnet_ip_body,
        &ett_knxnet_ip_hpai,
        &ett_knxnet_ip_hpai_length,
        &ett_knxnet_ip_hpai_host_protocol_code,
        &ett_knxnet_ip_hpai_ip_address,
        &ett_knxnet_ip_hpai_port_number,
        &ett_knxnet_ip_communication_channel_id,
        &ett_knxnet_ip_connect_response_status,
        &ett_knxnet_ip_connectionstate_response_status,
        &ett_knxnet_ip_structure_length,
        &ett_knxnet_ip_connection_type,
        &ett_knxnet_ip_sequence_counter,
		&ett_knxnet_ip_reserved,
        &ett_knxnet_ip_tunnelling_error_code,
        &ett_knxnet_ip_disconnect_response_status,
        &ett_knxnet_ip_description_type,
        &ett_knx_medium_code,
        &ett_knxnet_ip_device_status,
        &ett_knxnet_ip_physical_address,
        &ett_knxnet_ip_project_installation_ID,
        &ett_knx_serial_number,
        &ett_knxnet_ip_device_routing_multicast_address,
        &ett_knxnet_ip_MAC_address,
        &ett_knxnet_ip_device_friendly_name,
        &ett_knxnet_ip_service_family_ID,
        &ett_knxnet_ip_knx_manufacturer_ID,
        &ett_knxnet_ip_device_configuration_status,
        &ett_knxnet_ip_cemi,
		&ett_knxnet_ip_device_state,
		&ett_knxnet_ip_number_of_lost_messages
    };




    proto_knxnet_ip = proto_register_protocol ("KNXnet/IP Protocol", "KNXnet / IP", "knxnetip");

    proto_register_field_array (proto_knxnet_ip, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));

	/* subdissector code */
//TODO: CONTINUE HERE!!!
	// knxnetip_dissector_table = register_dissector_table("knxnetip.cemi","KNXnet/IP cEMI present", FT_BOOLEAN, BASE_DEC);
    register_heur_dissector_list("knxnetip.cEMI", &heur_subdissector_list);
}

static guint8 dissect_dib(tvbuff_t *tvb,guint32 offset,proto_tree *sub_tree)
{
    guint8 individualaddress1 = 0;
    guint8 individualaddress2 = 0;
    guint8 counter = 0;
    guint8 version = 0;
    gchar individual_adddress[KNXNETIP_MAX_KNX_ADDRESS_STRING_SIZE];
    gchar version_str[KNXNETIP_MAX_VERSION_STRING_SIZE];

    proto_item *dib_item = NULL;
    guint8 structure_length = 0;

    tvb_memcpy(tvb, (guint8 *)&structure_length, offset, 1); /*get header length*/

	switch(tvb_get_guint8(tvb, offset+1)) {
        case(0x01): /* DEVICE_INFO*/
            proto_tree_add_text(sub_tree, tvb, offset, structure_length,"Device Information DIB (Description Information Block)");
            break;
        case(0x02): /* SUPPORTED SERVICE FAMILIES*/
            proto_tree_add_text(sub_tree, tvb, offset, structure_length,"Supported Service Families DIB (Description Information Block)");
            break;
        case(0xFE): /* MANUFACTURER DATA*/
            proto_tree_add_text(sub_tree, tvb, offset, structure_length,"Manufacturer Data DIB (Description Information Block)");
            break;
        }

    /*DIB Structure Length*/
    proto_tree_add_uint(sub_tree, hf_knxnet_ip_structure_length, tvb, offset, 1, structure_length);
    offset+=1;
    /*DIB Description Type Code*/
    proto_tree_add_item( sub_tree, hf_knxnet_ip_description_type, tvb, offset, 1, FALSE );
    offset+=1;

	
    switch(tvb_get_guint8(tvb, offset+1)) {
        case(0x01): /* DEVICE_INFO*/
            /*DIB KNX Medium*/
            proto_tree_add_item( sub_tree, hf_knx_medium_code, tvb, offset, 1, FALSE );
            offset+=1;
            /*DIB Device Status*/
            proto_tree_add_item( sub_tree, hf_knxnet_ip_device_status, tvb, offset, 1, FALSE );
			offset+=1;
            /*KNX physical address / KNX Individual Address 4-4-8 Area-Line-Device*/
            tvb_memcpy(tvb, (guint8 *)&individualaddress1, offset, 1);
            tvb_memcpy(tvb, (guint8 *)&individualaddress2, offset, 1);
            g_snprintf(individual_adddress,KNXNETIP_MAX_KNX_ADDRESS_STRING_SIZE,"%d%s%d%s%d",(individualaddress1&0xF0)>>4,".",(individualaddress1&0x0F),".",(individualaddress2));
            dib_item = proto_tree_add_uint(sub_tree, hf_knxnet_ip_physical_address, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
            proto_item_append_text(dib_item, ": %s",individual_adddress);
            offset+=2;
            /*Project-Installation Identifier - 2  octets*/
            proto_tree_add_uint(sub_tree, hf_knxnet_ip_project_installation_ID, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
            offset+=2;
            /*KNXnet/IP device serial number - 6 octets*/
            proto_tree_add_item( sub_tree, hf_knx_serial_number, tvb, offset, 6, FALSE );
            offset+=6;
            /*KNXnet/IP device routing multicast address - 4 octets*/
            proto_tree_add_item( sub_tree, hf_knxnet_ip_device_routing_multicast_address, tvb, offset, 4, FALSE );
            offset+=4;
            /*KNXnet/IP device MAC address - 6 octets*/
            proto_tree_add_item( sub_tree, hf_knxnet_ip_MAC_address, tvb, offset, 6, FALSE );
            offset+=6;
            /*Device Friendly Name*/
            proto_tree_add_item( sub_tree, hf_knxnet_ip_device_friendly_name, tvb, offset, 30, FALSE );
            offset+=30;
            break;
        case(0x02): /* SUPPORTED SERVICE FAMILIES*/
            for(counter=2;counter<=structure_length;counter+=2)
            {
             /*Service Family ID*/
             proto_tree_add_item( sub_tree, hf_knxnet_ip_service_family_ID, tvb, offset, 1, FALSE );
             offset+=1;
             /*Service Family Version*/
             tvb_memcpy(tvb, (guint8 *)&version, offset, 1);
             g_snprintf(version_str,KNXNETIP_MAX_VERSION_STRING_SIZE,"%d%s%d",(version&0xF0)>>4,".",(version&0x0F));
             dib_item=proto_tree_add_text(sub_tree, tvb, offset, 1,"Service Family Version");
             proto_item_append_text(dib_item, ": %s",version_str);
             offset+=1;
            }
            break;
        case(0xFE): /* MANUFACTURER DATA*/
            proto_tree_add_uint(sub_tree, hf_knxnet_ip_knx_manufacturer_ID, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
            offset+=2;
            proto_tree_add_text(sub_tree, tvb, offset,structure_length-4,"Manufacturer Specific Data");
            offset= offset+(structure_length-4);
            break;
        }
    return offset;

}
static guint8 dissect_hpai(tvbuff_t *tvb,guint32 offset,proto_tree *sub_tree, const char *additional_text)
{
    proto_item *hpai_item = NULL;
    guint8 structure_length = 0;
    guint16 port_number = 0;

    tvb_memcpy(tvb, (guint8 *)&structure_length, offset, 1); /*get header length*/
    hpai_item = proto_tree_add_item( sub_tree, hf_knxnet_ip_hpai, tvb, offset, structure_length, FALSE );
    if(additional_text != NULL)
    	proto_item_append_text(hpai_item, "%s", additional_text);
    /*HPAI Structure Length*/
    proto_tree_add_uint(sub_tree, hf_knxnet_ip_hpai_length, tvb, offset, 1, structure_length);
    offset+=1;
    /*HPAI host protocol code*/
    proto_tree_add_item( sub_tree, hf_knxnet_ip_hpai_host_protocol_code, tvb, offset, 1, FALSE );
    offset+=1;
    proto_tree_add_item( sub_tree, hf_knxnet_ip_hpai_ip_address, tvb, offset, 4, FALSE );
    offset+=4;
    tvb_memcpy(tvb, (guint8 *)&port_number, offset, 2);
    port_number = convert_uint16(port_number);
    proto_tree_add_uint(sub_tree, hf_knxnet_ip_hpai_port_number, tvb, offset, 2, port_number);
    offset+=2;
    return offset;
}

static void checkcEMISubDissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset) {
	gint len;
	gint reported_len;
	tvbuff_t *next_tvb;

	/**
	 * call - if available - the subdissector
	 */
	len = tvb_length_remaining(tvb, offset);
	reported_len = tvb_reported_length_remaining(tvb, offset);
	//'backing_length' of -1 means "to the end of the backing buffer"
	next_tvb = tvb_new_subset(tvb, offset, len, reported_len);
//	if (dissector_try_port(knxnetip_dissector_table, (TRUE), next_tvb, pinfo, tree))
//		return (TRUE);
//	// call the predefined data-dissector for body
//	call_dissector(data_handle,next_tvb, pinfo, tree);
//    return (FALSE);


    /* Allow sub dissectors to have a chance with this data */
    if(!dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, NULL,NULL))
    {
       /* No sub dissector did recognize this data, dissect it as data only */
       proto_tree_add_item(tree, hf_knxnet_ip_cemi, tvb, offset, len, FALSE);
       //proto_tree_add_item(knxnet_ip_tree, hf_knxnet_ip_header, tvb, offset, hlength, FALSE );
       // call_dissector(data_handle,next_tvb, pinfo, tree);
       return;
    }
    else
    {
       /* A sub dissector handled the data */
		return;
    }

}


static gboolean /*use a gboolean return value for a heuristic dissector, void  otherwise*/
dissect_knxnet_ip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *unused)
{

    proto_item *knxnet_ip_item = NULL;
    proto_item *knxnet_ip_sub_item = NULL;
    //proto_item *knxnet_ip_sub_sub_item = NULL;
    proto_item *knxnet_ip_version_item = NULL;

    proto_tree *knxnet_ip_tree = NULL;
    proto_tree *knxnet_ip_header_tree = NULL;
    proto_tree *knxnet_ip_body_tree = NULL;

    guint16 type = 0;
	gint index = -1;

    /*-----------------Heuristic Checks - Begin*/
    if ( tvb_get_guint8(tvb, 0) != KNXNETIP_HEADER_LENGTH) return (FALSE); //check for Header length (is always 6Bytes)
    if ( tvb_get_guint8(tvb, 1) !=  KNXNETIP_PROTOCOL_VERSION) return (FALSE); //check for version
    //check for Service Type identifier
	match_strval_idx((guint32)tvb_get_ntohs(tvb, 2),knxnetip_service_type,&index);
	if(index == -1) return (FALSE);
	/*check for length: The total length is expressing the total KNXnet/IP frame length in octets.
	 *The length includes the complete KNXnet/IP frame, starting with the header length of the KNXnet/IP header and including the whole KNXnet/IP body.
	 */
	if(tvb_length(tvb)!=tvb_get_ntohs(tvb, 4)) return (FALSE);
    /*-----------------Heuristic Checks - End*/


    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_KNXNET);
    /* Clear out stuff in the info column */
    if(check_col(pinfo->cinfo,COL_INFO)){
        col_clear(pinfo->cinfo,COL_INFO);
    }

    // This is not a good way of dissecting packets.  The tvb length should
    // be sanity checked so we aren't going past the actual size of the buffer.
    type = tvb_get_ntohs( tvb, 2 ); // Get the type  - 2bytes


    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s %d > %d",
			val_to_str(type, knxnetip_service_type, "Unknown Type:0x%02x"),
			pinfo->srcport, pinfo->destport);
    }

    if (tree) { /* we are being asked for details */
        guint32 offset = 0;
        guint8 hlength = 0;
        guint8 com_ch_id = 0;
		guint16 tlength = 0;
        guint8 version = 0;
        guint8 crd_length = 0;
        guint8 sequence_counter = 0;
		guint8 reserved = 0;
		
		// variables for routing lost messages only - begin
		guint16 numberoflostmessages = 0;
		guint8 devicestate = 0;
		guint8 structure_length = 0;
		// variables for routing lost messages only - begin
		

        gchar version_str[KNXNETIP_MAX_VERSION_STRING_SIZE];

        knxnet_ip_item = proto_tree_add_item(tree, proto_knxnet_ip, tvb, 0, -1, FALSE);
        knxnet_ip_tree =        proto_item_add_subtree(knxnet_ip_item, ett_knxnet_ip);

        /*Header*/
        tvb_memcpy(tvb, (guint8 *)&hlength, offset, 1); /*get header length*/
        knxnet_ip_sub_item = proto_tree_add_item( knxnet_ip_tree, hf_knxnet_ip_header, tvb, offset, hlength, FALSE );
        knxnet_ip_header_tree = proto_item_add_subtree(knxnet_ip_sub_item, ett_knxnet_ip);
        /*KNXnet/IP Headerlength */
        proto_tree_add_uint(knxnet_ip_header_tree, hf_knxnet_ip_hlength, tvb, offset, 1, hlength);
        offset+=1;
        /*KNXnet/IP Version*/
        tvb_memcpy(tvb, (guint8 *)&version, offset, 1);
        g_snprintf(version_str,KNXNETIP_MAX_VERSION_STRING_SIZE,"%d%s%d",(version&0xF0)>>4,".",(version&0x0F));
        knxnet_ip_version_item = proto_tree_add_item(knxnet_ip_header_tree, hf_knxnet_ip_version, tvb, offset, 1, FALSE);
        proto_item_append_text(knxnet_ip_version_item, ": %s",version_str);
        /* proto_tree_add_uint(knxnet_ip_header_tree, hf_knxnet_ip_version, tvb, offset, 1, version); */
        offset+=1;
        /*KNXnet/IP Type*/
        proto_tree_add_item(knxnet_ip_header_tree, hf_knxnet_ip_type, tvb, offset, 2, FALSE);
        offset+=2;
        tvb_memcpy(tvb, (guint8 *)&tlength, offset, 2);
        tlength = convert_uint16(tlength);
        proto_tree_add_uint(knxnet_ip_header_tree, hf_knxnet_ip_tlength, tvb, offset, 2, tlength);
        offset+=2;
        /*Body*/

		//if(type != _ROUTING_IND) {
		// subtree "body" not for routing-indications
		knxnet_ip_sub_item = proto_tree_add_item( knxnet_ip_tree, hf_knxnet_ip_body, tvb, offset, -1, FALSE );
		knxnet_ip_body_tree = proto_item_add_subtree(knxnet_ip_sub_item, ett_knxnet_ip);
		//}
		
		// encode the body
		/** Type Byte */
      switch(type) {
        case(_SEARCH_REQ): /* SEARCH_REQUEST*/
            dissect_hpai(tvb,offset,knxnet_ip_body_tree," Discovery endpoint");
            break;
        case(_SEARCH_RES): /*SEARCH_RESPONSE */
            offset = dissect_hpai(tvb,offset,knxnet_ip_body_tree," Control endpoint");
            offset = dissect_dib(tvb,offset,knxnet_ip_body_tree);
            offset = dissect_dib(tvb,offset,knxnet_ip_body_tree);
            break;
        case(_DESCRIPTION_REQ): /* DESCRIPTION_REQUEST */
            offset = dissect_hpai(tvb,offset,knxnet_ip_body_tree," Control endpoint");
            break;
        case(_DESCRIPTION_RES): /* DESCRIPTION_RESPONSE */
            offset = dissect_dib(tvb,offset,knxnet_ip_body_tree);
            offset = dissect_dib(tvb,offset,knxnet_ip_body_tree);
            break;
        case(_CONNECT_REQ): /* CONNECT_REQUEST */
            offset = dissect_hpai(tvb,offset,knxnet_ip_body_tree," Control endpoint");
            offset = dissect_hpai(tvb,offset,knxnet_ip_body_tree," Data endpoint");
            /*Connection Request Information Data Block*/
            proto_tree_add_text(knxnet_ip_body_tree, tvb, offset, -1,"Connection Request Information Data Block");
            tvb_memcpy(tvb, (guint8 *)&crd_length, offset, 1); /*get crd structure length*/
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_structure_length, tvb, offset, 1, crd_length);
            offset+=1;
            proto_tree_add_item( knxnet_ip_body_tree, hf_knxnet_ip_connection_type, tvb, offset, 1, FALSE );
            offset+=1;
            break;
        case(_CONNECT_RES): /* CONNECT_RESPONSE */
            /*Communication Channel ID*/
            tvb_memcpy(tvb, (guint8 *)&com_ch_id, offset, 1); /*get Communication Channel ID*/
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_communication_channel_id, tvb, offset, 1, com_ch_id);
            offset+=1;
            /*CONNECT RESPONSE Status*/
            proto_tree_add_item( knxnet_ip_body_tree, hf_knxnet_ip_connect_response_status, tvb, offset, 1, FALSE );
            offset+=1;
            /*HPAI*/
            offset = dissect_hpai(tvb,offset,knxnet_ip_body_tree," Data endpoint");
            /*Connection Response Data Block*/
            proto_tree_add_text(knxnet_ip_body_tree, tvb, offset, -1,"Connection Response Data Block");
            tvb_memcpy(tvb, (guint8 *)&crd_length, offset, 1); /*get crd structure length*/
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_structure_length, tvb, offset, 1, crd_length);
            offset+=1;
            proto_tree_add_item( knxnet_ip_body_tree, hf_knxnet_ip_connection_type, tvb, offset, 1, FALSE );
            offset+=1;
            break;
        case(_CONNECTIONSTATE_REQ): /* CONNECTIONSTATE_REQUEST */
            /*Communication Channel ID*/
            tvb_memcpy(tvb, (guint8 *)&com_ch_id, offset, 1); /*get Communication Channel ID*/
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_communication_channel_id, tvb, offset, 1, com_ch_id);
            offset+=2;
            /*HPAI*/
            offset = dissect_hpai(tvb,offset,knxnet_ip_body_tree," Control endpoint");
            break;
        case(_CONNECTIONSTATE_RES): /* CONNECTIONSTATE_RESPONSE */
            /*Communication Channel ID*/
            tvb_memcpy(tvb, (guint8 *)&com_ch_id, offset, 1); /*get Communication Channel ID*/
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_communication_channel_id, tvb, offset, 1, com_ch_id);
            offset+=1;
            /*CONNECTION STATE RESPONSE Status*/
            proto_tree_add_item( knxnet_ip_body_tree, hf_knxnet_ip_connectionstate_response_status, tvb, offset, 1, FALSE );
            offset+=1;

            break;
        case(_DISCONNECT_REQ): /* DISCONNECT_REQUEST  */
            /*Communication Channel ID*/
            tvb_memcpy(tvb, (guint8 *)&com_ch_id, offset, 1); /*get Communication Channel ID*/
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_communication_channel_id, tvb, offset, 1, com_ch_id);
            offset+=2;
            /*HPAI*/
            offset = dissect_hpai(tvb,offset,knxnet_ip_body_tree," Control endpoint");
            break;
        case(_DISCONNECT_RES): /* DISCONNECT_RESPONSE */
            /*Communication Channel ID*/
            tvb_memcpy(tvb, (guint8 *)&com_ch_id, offset, 1); /*get Communication Channel ID*/
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_communication_channel_id, tvb, offset, 1, com_ch_id);
            offset+=1;
            /*DISCONNECT RESPONSE Status */
            proto_tree_add_item( knxnet_ip_body_tree, hf_knxnet_ip_disconnect_response_status, tvb, offset, 1, FALSE );
            offset+=1;
            break;
        case(_DEVICE_CONFIGURATION_REQUEST):
            /*Connection Header*/
            tvb_memcpy(tvb, (guint8 *)&crd_length, offset, 1); /*get crd structure length*/
            proto_tree_add_text(knxnet_ip_body_tree, tvb, offset, crd_length,"Connection Header");
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_structure_length, tvb, offset, 1, crd_length);
            offset+=1;
            tvb_memcpy(tvb, (guint8 *)&com_ch_id, offset, 1); /*get Communication Channel ID*/
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_communication_channel_id, tvb, offset, 1, com_ch_id);
            offset+=1;
            /*Sequence Counter*/
            tvb_memcpy(tvb, (guint8 *)&sequence_counter, offset, 1); /*get Sequence Counter*/
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_sequence_counter, tvb, offset, 1, sequence_counter);
			offset+=1;
			/*reserved*/
			tvb_memcpy(tvb, (guint8 *)&reserved, offset, 1); /*get reserved byte*/
			proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_reserved, tvb, offset, 1, reserved);
			offset+=1;
			// cEMI
			// proto_tree_add_boolean(knxnet_ip_body_tree,hf_knxnet_ip_cemi, tvb, offset, 0, TRUE);
			checkcEMISubDissector(tvb,pinfo,knxnet_ip_body_tree,offset);
            break;
        case(_DEVICE_CONFIGURATION_ACK):
            /*Connection Header*/
            tvb_memcpy(tvb, (guint8 *)&crd_length, offset, 1); /*get crd structure length*/
            proto_tree_add_text(knxnet_ip_body_tree, tvb, offset, crd_length,"Connection Header");
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_structure_length, tvb, offset, 1, crd_length);
            offset+=1;
            tvb_memcpy(tvb, (guint8 *)&com_ch_id, offset, 1); /*get Communication Channel ID*/
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_communication_channel_id, tvb, offset, 1, com_ch_id);
            offset+=1;
            /*Sequence Counter*/
            tvb_memcpy(tvb, (guint8 *)&sequence_counter, offset, 1); /*get Sequence Counter*/
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_sequence_counter, tvb, offset, 1, sequence_counter);
            offset+=1;
            /*Configuration Status*/
            proto_tree_add_item( knxnet_ip_body_tree, hf_knxnet_ip_device_configuration_status, tvb, offset, 1, FALSE );
            offset+=1;
            break;
        case(_TUNNELLING_REQ): /* TUNNELLING_REQUEST */
            /*Connection Header*/
            tvb_memcpy(tvb, (guint8 *)&crd_length, offset, 1); /*get crd structure length*/
            proto_tree_add_text(knxnet_ip_body_tree, tvb, offset, crd_length,"Connection Header");
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_structure_length, tvb, offset, 1, crd_length);
            offset+=1;
            tvb_memcpy(tvb, (guint8 *)&com_ch_id, offset, 1); /*get Communication Channel ID*/
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_communication_channel_id, tvb, offset, 1, com_ch_id);
            offset+=1;
            /*Sequence Counter*/
            tvb_memcpy(tvb, (guint8 *)&sequence_counter, offset, 1); /*get Sequence Counter*/
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_sequence_counter, tvb, offset, 1, sequence_counter);
            offset+=1;
			/*reserved*/
			tvb_memcpy(tvb, (guint8 *)&reserved, offset, 1); /*get reserved byte*/
			proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_reserved, tvb, offset, 1, reserved);
			offset+=1;
			// cEMI
			// proto_tree_add_boolean(knxnet_ip_body_tree,hf_knxnet_ip_cemi, tvb, offset, 0, TRUE);
			checkcEMISubDissector(tvb,pinfo,knxnet_ip_body_tree,offset);
            break;
        case(_TUNNELLING_ACK): /* TUNNELLING_ACK */
            /*Connection Header*/
            tvb_memcpy(tvb, (guint8 *)&crd_length, offset, 1); /*get crd structure length*/
            proto_tree_add_text(knxnet_ip_body_tree, tvb, offset, crd_length,"Connection Header");
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_structure_length, tvb, offset, 1, crd_length);
            offset+=1;
            tvb_memcpy(tvb, (guint8 *)&com_ch_id, offset, 1); /*get Communication Channel ID*/
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_communication_channel_id, tvb, offset, 1, com_ch_id);
            offset+=1;
            /*Sequence Counter*/
            tvb_memcpy(tvb, (guint8 *)&sequence_counter, offset, 1); /*get Sequence Counter*/
            proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_sequence_counter, tvb, offset, 1, sequence_counter);
            offset+=1;
            /*Tunnelling Status*/
            proto_tree_add_item( knxnet_ip_body_tree, hf_knxnet_ip_tunnelling_error_code, tvb, offset, 1, FALSE );
            offset+=1;
            break;
        case(_ROUTING_IND): /* ROUTING_INDICATION */
			// cEMI
			// proto_tree_add_boolean(knxnet_ip_body_tree,hf_knxnet_ip_cemi, tvb, offset, 0, TRUE);
			checkcEMISubDissector(tvb,pinfo,knxnet_ip_body_tree,offset);
			
            break;
        case(_ROUTING_LOM): /* ROUTING_LOST_MESSAGE */
			/*LostMessageInfo*/
			proto_tree_add_text(knxnet_ip_body_tree, tvb, offset, 4,"LostMessageInfo");
			
			tvb_memcpy(tvb, (guint8 *)&structure_length, offset, 1); /*get structure length*/
			proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_structure_length, tvb, offset, 1, structure_length);
			offset+=1;
			tvb_memcpy(tvb, (guint8 *)&devicestate, offset, 1); /*get structure length*/
			proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_device_state, tvb, offset, 1, devicestate);
			offset+=1;
			tvb_memcpy(tvb, (guint8 *)&numberoflostmessages, offset, 2); /*get structure length*/
			numberoflostmessages = convert_uint16(numberoflostmessages);
			proto_tree_add_uint(knxnet_ip_body_tree, hf_knxnet_ip_number_of_lost_messages, tvb, offset, 2, numberoflostmessages);
			offset+=2;
			//offset = dissect_hpai(tvb,offset,knxnet_ip_body_tree,NULL);
			
            break;
        default:
            offset = dissect_hpai(tvb,offset,knxnet_ip_body_tree,NULL);
        }
    }
    return TRUE;
}
