/*
 * MIT License
 *
 * Copyright (c) 2018 sruester
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef __SMBGEN_H
#define __SMBGEN_H

#include <string>
#include <cstdlib>
#include <time.h>
#include <inttypes.h>
#include <list>

using namespace std;

class SmbGen {

public:

	enum NBT_NAME_TYPE {
		NBT_NAME_CLIENT   = 0x00,
		NBT_NAME_MS       = 0x01,
		NBT_NAME_USER     = 0x03,
		NBT_NAME_SERVER   = 0x20,
		NBT_NAME_PDC      = 0x1B,
		NBT_NAME_LOGON    = 0x1C,
		NBT_NAME_MASTER   = 0x1D,
		NBT_NAME_BROWSER  = 0x1E
	};

	enum SMB_OPCODE {
		OPCODE_QUERY = 0,
		OPCODE_REGISTRATION = 5,
		OPCODE_RELEASE = 6,
		OPCODE_WACK = 7,
		OPCODE_REFRESH = 8
	};

	enum SMB_RCODE {
		RCODE_FMT_ERR = 0x01,
		RCODE_SRV_ERR = 0x02,
		RCODE_IMP_ERR = 0x04,
		RCODE_RFS_ERR = 0x05,
		RCODE_ACT_ERR = 0x06,
		RCODE_CFT_ERR = 0x07
	};

	typedef struct _smb_header {
		uint16_t name_trn_id;
		unsigned is_response:1;
		unsigned opcode:4;
		unsigned nm_aa:1;
		unsigned nm_tc:1;
		unsigned nm_rd:1;
		unsigned nm_ra:1;
		unsigned nm_res0:1;
		unsigned nm_res1:1;
		unsigned nm_b:1;
		unsigned rcode:4;
		uint16_t qdcount;
		uint16_t ancount;
		uint16_t nscount;
		uint16_t arcount;
	} smb_header;

	enum SMB_NODE_TYPE {
		NTYPE_B_NODE = 0,
		NTYPE_P_NODE = 1,
		NTYPE_M_NODE = 2,
	};

	typedef struct _netbios_name {
		uint8_t len;
		string  encoded;
		string  decoded;
		enum NBT_NAME_TYPE type;
	} netbios_name;

	typedef struct _node_name {
		string   name_string;
		uint8_t  service_type;
		struct {
			unsigned g:1;
			unsigned ont:2;
			unsigned drg:1;
			unsigned cnf:1;
			unsigned act:1;
			unsigned prm:1;
			unsigned reserved:9;
		} flags;
	} node_name;

	#define STATUS_RESP_MAX_NODE_NAMES	20
	typedef struct _status_response_msg {
		smb_header   head;
		netbios_name rr_name;
		uint16_t nbstat;
		uint16_t in;
		uint32_t res0;
		uint16_t rdlength;
		uint8_t  num_names;
		node_name names[STATUS_RESP_MAX_NODE_NAMES];
	} status_response_msg;

	typedef struct _status_request_msg {
		smb_header   head;
		netbios_name question_name;
		uint16_t nbstat;
		uint16_t in;
	} status_request_msg;


	SmbGen();

	static const uint16_t TRN_RAND_ID = 0x0000;
	static bool ParseStatusRequest(string &request, status_request_msg *srm);
	static string GenStatusRequest(uint16_t name_trn_id, string question_name);

	static bool ParseStatusResponse(string &response, status_response_msg *srm);
	static string GenStatusResponse(uint16_t name_trn_id, string rr_name, node_name *names, size_t numnames);
	static string GetPrintableResponseInfo(status_response_msg *srm);

	static bool EncodeNetbiosName(string nbname, enum NBT_NAME_TYPE type, string &retval);
	static bool DecodeNetBiosName(string &name, enum NBT_NAME_TYPE *type);

	static bool PackNodeName(node_name *nn, string &retval);
	static bool UnpackNodeName(const char *msg, node_name *nn);

	static bool PackHeaderData(smb_header *sh, string &data);
	static bool UnpackHeaderData(smb_header *sh, string &data);

private:

	static int seedoffset;
	static uint8_t rnd(void);

};

#endif // __SMBGEN_H
