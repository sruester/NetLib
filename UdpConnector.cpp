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
#include "UdpConnector.h"

#include <unistd.h>

/*
 *	CONSTRUCTOR / DESTRUCTOR
 */

UdpConnector::UdpConnector(){
	sock = 0;
	destination_ok = false;
	bindport = 0;
	pthread_mutex_init(&sock_lock, NULL);
}

UdpConnector::~UdpConnector(){
	pthread_mutex_destroy(&sock_lock);
}


/*
 *	CONNECTION ESTABLISHMENT
 */

void UdpConnector::CreateSocket(void){
	if(IsOpen()) return;

	pthread_mutex_lock(&sock_lock);
		sock = socket(AF_INET, SOCK_DGRAM, 0);
		if(sock < 0)	sock = 0;
	pthread_mutex_unlock(&sock_lock);

	if(!sock)
		throw "Create socket failed";
}

void UdpConnector::Close(void){
	if(!IsOpen()) return;

	pthread_mutex_lock(&sock_lock);
		if(sock != 0){
			close(sock);
			sock = 0;
		}
	pthread_mutex_unlock(&sock_lock);
}

bool UdpConnector::Bind(unsigned short port){
	struct sockaddr_in sin;

	if(!IsOpen())
		return false;

	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);

	if(bind(sock, (struct sockaddr *)&sin, sizeof(sin)) != 0){
		//perror("bind()");
		return false;
	}

	bindport = port;
	return true;
}

bool UdpConnector::Open(void){
	bool ret = false;

	try {

		CreateSocket();

		ret = true;

	}catch(const char *err){
		Close();
		cerr << err << endl;
	}
	return ret;
}


/*
 *	WRITE FUNCTIONS
 */

void UdpConnector::ResolveHostname(string host){
	struct addrinfo *ai, hints;
	int r;

	/* Remote Adresse */
	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;	//Nur IPv4

	r = getaddrinfo(host.c_str(), NULL, &hints, &ai);

	if(r)
		throw "getaddrinfo() failed";

	if(ai->ai_family != AF_INET){
		freeaddrinfo(ai);
		throw "Could not resolve to IPv4 address";
	}

	if(ai->ai_addrlen != sizeof(struct sockaddr_in) || ai->ai_addr == NULL){
		freeaddrinfo(ai);
		throw "API Error";
	}

	memcpy(&this->dest, ai->ai_addr, ai->ai_addrlen);

	freeaddrinfo(ai);
}

bool UdpConnector::SetDestination(string host, unsigned short port){
	try {

		ResolveHostname(host);
		dest.sin_port = htons(port);

		destination_ok = true;

	}catch(const char *err){
		destination_ok = false;
		cerr << err << endl;
	}
	return destination_ok;
}

void UdpConnector::WriteData(const uint8_t *data, size_t len){
	int r;

	if(!len)
		return;

	if(!IsOpen())
		return;

	if(!destination_ok)
		throw "No destination set. Use SetDestination first";

	r = sendto(sock, data, len, 0, (struct sockaddr *)&dest, sizeof(dest));
	if(r < 0)
		throw "Error when trying to write to socket";

	if(r != (int)len)
		throw "Could not send all data";

	return;
}

bool UdpConnector::Tx(const uint8_t *data, unsigned int datalen){
	try {
		WriteData(data, datalen);
	}catch(const char *err){
		Close();
		cerr << err << endl;
		return false;
	}
	return true;
}

bool UdpConnector::Tx(string data){
	return Tx((const uint8_t*)data.c_str(), data.length());
}



/*
 *	READ FUNCTIONS
 */

bool UdpConnector::TryRead(long to_sec, long to_usec){
	fd_set fdsr, fdse;

	FD_ZERO(&fdsr); FD_SET(sock, &fdsr);
	FD_ZERO(&fdse); FD_SET(sock, &fdse);

	struct timeval tv;
	tv.tv_sec  = to_sec;
	tv.tv_usec = to_usec;

	int r;
	r = select(sock + 1, &fdsr, NULL, &fdse, &tv);

	if(r == 0)
		return false;

	if(r < 0)
		throw "Error while trying to read from socket";

	if(FD_ISSET(sock, &fdse))
		throw "Error found while trying to read from socket";

	return true;
}

int UdpConnector::Rx(string &data, string &from, long to_sec = 0, long to_usec = 0){
	uint16_t waste;
	return Rx(data, from, waste, to_sec, to_usec);
}

int UdpConnector::Rx(string &data, string &from, uint16_t &fromport, long to_sec = 0, long to_usec = 0){
	int r = 0;

	struct sockaddr_in source;
	socklen_t slen = sizeof(source);
	char srcbuf[INET_ADDRSTRLEN];
	from = "";

	int blen = 4096;
	char buff[blen];
	data = "";

	if(!IsOpen())
		return RX_SCK_NA;

	try {
		if(to_sec > 0 || to_usec > 0)
			if(!TryRead(to_sec, to_usec))
				return RX_TIMEOUT;

		r = recvfrom(sock, buff, blen, 0, (struct sockaddr *)&source, &slen);

		if(r == 0){
			Close();
			return RX_EOF;
		}

		if(r < 0){
			Close();
			return RX_ERROR;
		}

		from = inet_ntop(AF_INET, &source.sin_addr, srcbuf, INET_ADDRSTRLEN);
		fromport = ntohs(source.sin_port);
		data.append(buff, r);

	}catch(const char *err){
		Close();
		cerr << err << endl;
		return RX_ERROR;
	}

	return RX_OK;
}

