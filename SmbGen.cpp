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
#include "SmbGen.h"
#include "HexDumper.h"
#include <sstream>
#include <iostream>
#include <iomanip>
#include <string>



#define NAME_FLAGS_PRM				0x02
#define NAME_FLAGS_ACT				0x04
#define NAME_FLAGS_CNF				0x08
#define NAME_FLAGS_DRG				0x10
#define NAME_FLAGS_NODE_MASK		0x60
#define NAME_FLAGS_NODE_B				0x00
#define NAME_FLAGS_NODE_P				0x20
#define NAME_FLAGS_NODE_M				0x40
#define NAME_FLAGS_NODE_RES			0x60
#define NAME_FLAGS_GRP				0x80


#define SWAB16(x)	((((x) & 0x00FF) << 8) | (((x) & 0xFF00) >> 8))
#define SWAB8(x)	((((x) & 0x0F) << 4) | (((x) & 0xF0) >> 4))

#define hexW2		hex << setw(2) << setfill('0') << uppercase

using namespace std;

int SmbGen::seedoffset = 1;


SmbGen::SmbGen(void){
	srandom((unsigned int)time(0) + seedoffset++);
}

uint8_t SmbGen::rnd(void){
	return (uint8_t)(random() % 256);
}

/*
 * * * * * * * * * * * * * * * * * * * * * *
 *  NETBIOS NAME HANDLING
 * * * * * * * * * * * * * * * * * * * * * *
 */
/*
  compress a name component
 */
bool SmbGen::EncodeNetbiosName(string nbname, enum NBT_NAME_TYPE type, string &retval){
	uint8_t cname[33];
	const uint8_t *name = (const uint8_t *)nbname.c_str();
	int i;
	uint8_t pad_char;

	if (nbname.length() > 15) {
		return false;
	}

	for (i=0;name[i];i++) {
		cname[2*i]   = 'A' + (name[i]>>4);
		cname[1+2*i] = 'A' + (name[i]&0xF);
	}
	if(nbname.compare("*") == 0) {
		pad_char = 0;
	} else {
		pad_char = ' ';
	}
	for (;i<15;i++) {
		cname[2*i]   = 'A' + (pad_char>>4);
		cname[1+2*i] = 'A' + (pad_char&0xF);
	}

	pad_char = type;
	cname[2*i]   = 'A' + (pad_char>>4);
	cname[1+2*i] = 'A' + (pad_char&0xF);

	cname[32] = 0;

	string tmp;
	tmp.assign((const char*)cname);

	retval = (char)0x20 + tmp;

	return true;
}


/*
  decompress a 'compressed' name component
 */
bool SmbGen::DecodeNetBiosName(string &encname, enum NBT_NAME_TYPE *type){
	int i;
	char name[40];

	name[encname.copy(name, 39, 0)] = '\0';

	for (i=0;name[2*i];i++) {
		uint8_t c1 = name[2*i];
		uint8_t c2 = name[1+(2*i)];
		if (c1 < 'A' || c1 > 'P' ||
		    c2 < 'A' || c2 > 'P') {
			return false;
		}
		name[i] = ((c1-'A')<<4) | (c2-'A');
	}

	name[i] = 0;
	if (i == 16) {
		*type = (enum NBT_NAME_TYPE)(name[15]);
		name[15] = 0;
		i--;
	} else {
		*type = NBT_NAME_CLIENT;
	}

	/* trim trailing spaces */
	for (;i>0 && name[i-1]==' ';i--) {
		name[i-1] = 0;
	}

	encname = name;

	return true;
}

/*
 * * * * * * * * * * * * * * * * * * * * * *
 *  NODE_NAME PACKING
 * * * * * * * * * * * * * * * * * * * * * *
 */
bool SmbGen::PackNodeName(node_name *nn, string &retval){
	uint8_t buf[18];
	size_t i;

	for(i = 0; i < 15; i++){
		if(i < nn->name_string.length())
			buf[i] = nn->name_string[i];
		else
			buf[i] = ' ';
	}
	buf[15] = (char)nn->service_type;
	buf[16] = 0x00;
	buf[16] |= nn->flags.g << 7;
	buf[16] |= nn->flags.ont << 5;
	buf[16] |= nn->flags.drg << 4;
	buf[16] |= nn->flags.cnf << 3;
	buf[16] |= nn->flags.act << 2;
	buf[16] |= nn->flags.prm << 1;
	buf[17] = 0x00;

	retval.assign((char *)buf, 18);
	return true;
}

bool SmbGen::UnpackNodeName(const char *msg, node_name *nn){
	uint16_t flags;
	nn->name_string.assign(msg, 15);
	nn->service_type = ((uint8_t *)msg)[15];
	flags = (((((uint8_t *)msg)[16]) << 8) | ((uint8_t *)msg)[17]);
	nn->flags.g   = (flags & 0x8000) >> 15;
	nn->flags.ont = (flags & 0x6000) >> 13;
	nn->flags.drg = (flags & 0x1000) >> 12;
	nn->flags.cnf = (flags & 0x0800) >> 11;
	nn->flags.act = (flags & 0x0400) >> 10;
	nn->flags.prm = (flags & 0x0200) >> 9;
	nn->flags.reserved = (flags & 0x01FF);
	return true;
}


/*
4.2.1.1.  HEADER

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         NAME_TRN_ID           | OPCODE  |   NM_FLAGS  | RCODE |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          QDCOUNT              |           ANCOUNT             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          NSCOUNT              |           ARCOUNT             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
bool SmbGen::PackHeaderData(smb_header *sh, string &data){
	uint8_t buf[12] = {0,0,0,0,0,0,0,0,0,0,0,0};

	buf[0] = (sh->name_trn_id & 0xFF00) >> 8;
	buf[1] = (sh->name_trn_id & 0x00FF);
	buf[2] = (sh->is_response << 7);
	buf[2] |= (sh->opcode << 3);
	buf[2] |= (sh->nm_aa << 2);
	buf[2] |= (sh->nm_tc << 1);
	buf[2] |= (sh->nm_rd);
	buf[3] = (sh->nm_ra << 7);
	buf[3] |= (sh->nm_b  << 4);
	buf[3] |= (sh->rcode);
	buf[4] = (sh->qdcount & 0xFF00) << 8;
	buf[5] = (sh->qdcount & 0xFF);
	buf[6] = (sh->ancount & 0xFF00) << 8;
	buf[7] = (sh->ancount & 0xFF);
	buf[8] = (sh->nscount & 0xFF00) << 8;
	buf[9] = (sh->nscount & 0xFF);
	buf[10] = (sh->arcount & 0xFF00) << 8;
	buf[11] = (sh->arcount & 0xFF);

	data.assign((char *)buf, 12);
	return true;
}

bool SmbGen::UnpackHeaderData(smb_header *sh, string &data){
	// 2222 2222 3333 3333
	// ROOO OATR R00B RCOD
	const uint8_t *msg;
	if(data.length() < 12) return false;
	msg = (const uint8_t *)data.c_str();
	sh->name_trn_id = (msg[0] << 8) | msg[1];
	sh->is_response = (msg[2] & 0x80) >> 7;
	sh->opcode      = (msg[2] & 0x78) >> 3;
	sh->nm_aa       = (msg[2] & 0x04) >> 2;
	sh->nm_tc       = (msg[2] & 0x02) >> 1;
	sh->nm_rd       = (msg[2] & 0x01);
	sh->nm_ra       = (msg[3] & 0x80) >> 7;
	sh->nm_res0     = 0;
	sh->nm_res1     = 0;
	sh->nm_b        = (msg[3] & 0x10) >> 4;
	sh->rcode       =  msg[3] & 0x0F;
	sh->qdcount     = (msg[4] << 8)  | msg[5];
	sh->ancount     = (msg[6] << 8)  | msg[7];
	sh->nscount     = (msg[8] << 8)  | msg[9];
	sh->arcount     = (msg[10] << 8) | msg[11];
	return true;
}



/*
4.2.18.  NODE STATUS RESPONSE

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         NAME_TRN_ID           |1|  0x0  |1|0|0|0|0 0|0|  0x0  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          0x0000               |           0x0001              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          0x0000               |           0x0000              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /                            RR_NAME                            /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        NBSTAT (0x0021)        |         IN (0x0001)           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          0x00000000                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          RDLENGTH             |   NUM_NAMES   |               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
   |                                                               |
   +                                                               +
   /                         NODE_NAME ARRAY                       /
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   /                           STATISTICS                          /
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	http://ubiqx.org/cifs/rfc-draft/rfc1002.html#s4.2.17
*/
string SmbGen::GenStatusResponse(uint16_t name_trn_id, string rr_name, node_name *names, size_t numnames){
	smb_header head;
	if(name_trn_id == TRN_RAND_ID){
		name_trn_id = rnd() << 8;
		name_trn_id |= rnd();
	}
	head.name_trn_id = name_trn_id;
	head.is_response = 1;
	head.opcode  = 0;
	head.nm_aa   = 1;
	head.nm_tc   = 0;
	head.nm_rd   = 0;
	head.nm_ra   = 0;
	head.nm_res0 = 0;
	head.nm_res1 = 0;
	head.nm_b    = 0;
	head.rcode   = 0;
	head.qdcount = 0;
	head.ancount = 1;
	head.nscount = 0;
	head.arcount = 0;

	string header;
	PackHeaderData(&head, header);

	string rrname;
	EncodeNetbiosName(rr_name, NBT_NAME_CLIENT, rrname);

	string flags;
	uint8_t _flags[] = {0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
	flags.assign((char*)_flags, sizeof(_flags));

	string nbtnames = "";
	string tmp;
	nbtnames += (char)numnames;
	for(unsigned int i = 0; i < numnames; i++){
		PackNodeName(&names[i], tmp);
		nbtnames += tmp;
	}

	string rdlen = "";
	uint16_t rdl = nbtnames.length();
	rdlen += (char)((rdl & 0xFF00) >> 8);
	rdlen += (char)(rdl & 0xFF);

	string ret;
	ret = header + rrname + ((char)0x00) + flags + rdlen + nbtnames;

	return ret;
}

bool SmbGen::ParseStatusResponse(string &response, status_response_msg *srm){
	string tmp = "";
	stringstream ss;
	const uint8_t *msg = (const uint8_t *)response.c_str();
	int mlen;

	if((mlen = response.length()) < 56)
		return false;

	if(!UnpackHeaderData(&srm->head, response))
		return false;

	if(srm->head.is_response != 1) return false;
	if(srm->head.opcode      != 0) return false;
	if(srm->head.nm_aa       != 1) return false;
	if(srm->head.nm_tc       != 0) return false;
	if(srm->head.nm_rd       != 0) return false;
	if(srm->head.nm_ra       != 0) return false;
	if(srm->head.nm_b        != 0) return false;
	if(srm->head.rcode       != 0) return false;
	if(srm->head.qdcount     != 0) return false;
	if(srm->head.ancount     != 1) return false;
	if(srm->head.nscount     != 0) return false;
	if(srm->head.arcount     != 0) return false;

	srm->rr_name.len = response[12];
	srm->rr_name.encoded = response.substr(13, 32);
	srm->rr_name.decoded = srm->rr_name.encoded;

	//RR_NAME
	if(!DecodeNetBiosName(srm->rr_name.decoded, &srm->rr_name.type)){
		return false;
	}

	srm->nbstat = ((response[46] << 8) | response[47]);
	srm->in     = ((response[48] << 8) | response[49]);

	srm->res0 = ((msg[50] << 24) | (msg[51] << 16) | (msg[52] << 8) | (msg[53]));

	srm->rdlength = (msg[54] << 8) | msg[55];

	if(mlen - 56 < srm->rdlength)
		return false;

	srm->num_names = msg[56];
	if(srm->num_names > STATUS_RESP_MAX_NODE_NAMES){
		srm->num_names = STATUS_RESP_MAX_NODE_NAMES;
	}

	if(srm->num_names * 18 > srm->rdlength)
		return false;

	for(int i = 0; i < srm->num_names; i++){
		UnpackNodeName((const char *)&msg[57 + (i * 18)], &srm->names[i]);
	}

	return true;
}
#include <stdio.h>
/* Dump response messages */
string SmbGen::GetPrintableResponseInfo(status_response_msg *srm){
	stringstream ss;
	for(int i = 0; i < srm->num_names; i++){
			ss << "\t";
			ss << setw(15) << setfill(' ') << srm->names[i].name_string;
			ss << " <" << hexW2 << (int)srm->names[i].service_type << "> - ";
		if(srm->names[i].flags.g)
			ss << "<GROUP> ";
		else
			ss << "        ";
		switch(srm->names[i].flags.ont){
			case 0:	ss << "B "; break;
			case 1:	ss << "P "; break;
			case 2:	ss << "M "; break;
			case 3:	ss << "R "; break;
		}
		if(srm->names[i].flags.act) ss << "<ACTIVE> ";
		if(srm->names[i].flags.drg) ss << "<DEREGISTER> ";
		if(srm->names[i].flags.cnf) ss << "<CONFLICT> ";
		if(srm->names[i].flags.prm) ss << "<PERMANENT> ";
		ss << endl;
	}
	return ss.str();
}

/*
4.2.17.  NODE STATUS REQUEST

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         NAME_TRN_ID           |0|  0x0  |0|0|0|0|0 0|B|  0x0  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          0x0001               |           0x0000              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          0x0000               |           0x0000              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /                         QUESTION_NAME                         /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         NBSTAT (0x0021)       |        IN (0x0001)            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 */
bool SmbGen::ParseStatusRequest(string &request, status_request_msg *srm){
	string tmp = "";
	stringstream ss;
	const uint8_t *msg = (const uint8_t *)request.c_str();
	int mlen;

	if((mlen = request.length()) < 50)
		return false;

	if(!UnpackHeaderData(&srm->head, request))
		return false;

	if(srm->head.is_response != 0) return false;
	if(srm->head.opcode      != 0) return false;
	if(srm->head.nm_aa       != 0) return false;
	if(srm->head.nm_tc       != 0) return false;
	if(srm->head.nm_rd       != 0) return false;
	if(srm->head.nm_ra       != 0) return false;
	if(srm->head.rcode       != 0) return false;
	if(srm->head.qdcount     != 1) return false;
	if(srm->head.ancount     != 0) return false;
	if(srm->head.nscount     != 0) return false;
	if(srm->head.arcount     != 0) return false;

	srm->question_name.len = request[12];
	srm->question_name.encoded = request.substr(13, 32);
	srm->question_name.decoded = srm->question_name.encoded;

	//QUESTION_NAME
	if(!DecodeNetBiosName(srm->question_name.decoded, &srm->question_name.type)){
		return false;
	}

	//cout << "Decoded to : " << srm->question_name.decoded << endl;

	srm->nbstat = ((msg[46] << 8) | msg[47]);
	srm->in     = ((msg[48] << 8) | msg[49]);

	return true;
}

string SmbGen::GenStatusRequest(uint16_t name_trn_id, string question_name){
	SmbGen::smb_header head;
	if(name_trn_id == TRN_RAND_ID){
		name_trn_id = rnd() << 8;
		name_trn_id |= rnd();
	}
	head.name_trn_id = name_trn_id;
	head.is_response = 0;
	head.opcode  = 0;
	head.nm_aa   = 0;
	head.nm_tc   = 0;
	head.nm_rd   = 0;
	head.nm_ra   = 0;
	head.nm_res0 = 0;
	head.nm_res1 = 0;
	head.nm_b    = 0;
	head.rcode   = 0;
	head.qdcount = 1;
	head.ancount = 0;
	head.nscount = 0;
	head.arcount = 0;

	string header;
	PackHeaderData(&head, header);

	string qname;
	EncodeNetbiosName(question_name, NBT_NAME_CLIENT, qname);

	string flags;
	uint8_t _flags[] = {0x00, 0x21, 0x00, 0x01};
	flags.assign((char*)_flags, sizeof(_flags));

	string ret;
	ret = header + qname + ((char)0x00) + flags;

	return ret;
}

