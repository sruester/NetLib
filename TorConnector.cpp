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
#include "TorConnector.h"


TorConnector::TorConnector(string torip, unsigned short torport){
	cli = new ClientSocket(torip, torport);
}

TorConnector::~TorConnector(){
	delete cli;
}

bool TorConnector::DoSocks5Stuff(string hostname, unsigned short port){

	string buff;
	size_t len;

	if(!cli->Open())
		return false;

	/* version identifier/method selection message */
	buff  = (char)5;
	buff += (char)1;
	buff += (char)0;
	if(!cli->Tx(buff))
		return false;

	/* METHOD selection message */
	len = 2;
	if(cli->Rx(buff, len) != 1)
		return false;

	if(buff[0] != 5)	throw "TOR Socks Version not supported";
	if(buff[1] != 0)	throw "TOR Authentication required";

	/* SOCKS request */
	buff  = (char)5;
	buff += (char)1;
	buff += (char)0;
	buff += (char)3;
	buff += (char)(hostname.length());
	buff += hostname;
	buff += (char)((port & 0xff00) >> 8);
	buff += (char)(port & 0xff);
	if(!cli->Tx(buff))
		return false;

	/* The SOCKS request information */
	len = 4;
	if(cli->Rx(buff, len, 5) != 1)
		return false;

	if(buff[0] != 5)	throw "TOR Socks Version not supported";
	if(buff[1] != 0)	throw "TOR request didn't succeed";
	switch(buff[3]){
		case 1:
			len = 6;
			break;
		case 3:
			len = 18;
			break;
		case 4:
			len = buff[4] + 2;
			break;
		default:
			throw "TOR reply not understood";
	}
	if(cli->Rx(buff, len) != 1)
		return false;

  return true;
}

bool TorConnector::TunnelTo(string hostname, unsigned short port){
	try {

		return DoSocks5Stuff(hostname, port);

	}catch(const char *err){

		cerr << err << endl;
		return false;

	}
}
