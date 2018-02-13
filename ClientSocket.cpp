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
#include "ClientSocket.h"

#include <unistd.h>

#define EXIT_FLAG_IS_SET			(exit_flag && (*exit_flag))
#define EXIT_FLAG_IS_NOT_SET	(!EXIT_FLAG_IS_SET)

/*
 *	CONSTRUCTOR / DESTRUCTOR
 */

ClientSocket::ClientSocket(string host, unsigned short port)
{
	this->host = host;
	this->port = port;
	exit_flag = NULL;
	sock = 0;
	pthread_mutex_init(&sock_lock, NULL);
}

ClientSocket::~ClientSocket(){
	pthread_mutex_destroy(&sock_lock);
}


/*
 *	CONNECTION ESTABLISHMENT
 */

void ClientSocket::CreateSocket(void){
	Close();

	pthread_mutex_lock(&sock_lock);
		sock = socket(AF_INET, SOCK_STREAM, 0);
		if(sock < 0)	sock = 0;
	pthread_mutex_unlock(&sock_lock);

	if(!sock)
		throw "Create socket failed";
}

void ClientSocket::ResolveHostname(void){
	struct addrinfo *ai, hints;
	int r;

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

	memcpy(&this->hostadr, ai->ai_addr, ai->ai_addrlen);
	hostadr.sin_port = htons(port);

	freeaddrinfo(ai);
}

void ClientSocket::Connect(void){
	if(connect(sock, (struct sockaddr *)&hostadr, sizeof(hostadr)) != 0){
		throw "Connect failed";
	}
}


/*
 *	CONNECTION HANDLING
 */

bool ClientSocket::Open(void){
	bool ret = false;

	try {

		CreateSocket();
		ResolveHostname();
		Connect();

		ret = true;

	}catch(const char *err){
		Close();
		//cerr << err << endl;
	}
	return ret;
}

void ClientSocket::Close(void){
	if(!sock)
		return;

	pthread_mutex_lock(&sock_lock);
		close(sock);
		sock = 0;
	pthread_mutex_unlock(&sock_lock);
}


/*
 *	WRITE FUNCTIONS
 */

void ClientSocket::CheckSockReady(void){
	fd_set fdsw, fdse;

	FD_ZERO(&fdsw); FD_SET(sock, &fdsw);
	FD_ZERO(&fdse); FD_SET(sock, &fdse);

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 1000;

	int r;
	r = select(sock + 1, NULL, &fdsw, &fdse, &tv);

	if(r < 0)
		throw "Error while checking socket";

	if(r == 0)
		return;

	if(FD_ISSET(sock, &fdse))
		throw "Error found while checking socket";

}

void ClientSocket::WriteData(const char *data, size_t len){
	int r;

	if(!len)
		return;

	if(!IsOpen())
		return;

	CheckSockReady();

    r = write(sock, data, len);

	if(r < 0)
		throw "Error when trying to write to socket";

	if(r != (int)len)
		throw "Could not send all data";

	return;
}

bool ClientSocket::Tx(const char *data, unsigned int datalen){
	try {
		WriteData(data, datalen);
	}catch(const char *err){
		Close();
		cerr << err << endl;
		return false;
	}
	return true;
}

bool ClientSocket::Tx(string data){
	return Tx(data.c_str(), data.length());
}


/*
 *	READ FUNCTIONS
 */

bool ClientSocket::TryRead(long to_sec = 0, long to_usec){
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

int ClientSocket::ReadChar(char &c, long to_sec, long to_usec){
	int r = 0;

	if(!IsOpen())
		return RX_SCK_NA;

	try {
		if(!TryRead(to_sec, to_usec))
			return RX_TIMEOUT;

        r = read(sock, &c, 1);

		if(r == 0){
			Close();
			return RX_EOF;
		}

		if(r < 0){
			Close();
			return RX_ERROR;
		}

	}catch(const char *err){
		Close();
		cerr << err << endl;
		return RX_ERROR;
	}

	//cout << c;

	return 1;
}

/**
 * @param		buff	Zeiger auf Puffer
 * @param		plen	Zeiger auf Pufferlänge. Enthält nach Rückkehr die Anzahl gelesener Zeichen
 * @param		to_sec	Timeout in Sekunden
 * @param		to_usec	Timeout in Mikrosekunden
 * @return	Gibt bei Timeout 0 zurück, bei Fehlern einen Wert < 0. Ansonsten 1.
 */
int ClientSocket::Rx(char *buff, size_t &plen, long to_sec, long to_usec){
	int r;
	size_t maxlen;
	char c;

	maxlen = plen;
	plen = 0;

	for(size_t i = 0; i < maxlen && EXIT_FLAG_IS_NOT_SET; i++){
		if((r = ReadChar(c, to_sec, to_usec)) != 1)
			return r;

		buff[i] = c;
		plen++;
	}

	return 1;
}

/**
 * @param		buff	Zeiger auf Puffer
 * @param		to_sec	Timeout in Sekunden
 * @param		to_usec	Timeout in Mikrosekunden
 * @return	Gibt bei Timeout 0 zurück, bei Fehlern einen Wert < 0. Ansonsten 1.
 */
int ClientSocket::RxLine(string &buff, long to_sec, long to_usec){
	int r;
	char c;
	buff = "";

	for(;EXIT_FLAG_IS_NOT_SET ;){
		if((r = ReadChar(c, to_sec, to_usec)) != 1)
			return r;

		if(c == '\r')
			continue;

		if(c == '\n')
			break;

		buff += c;
	}

	return 1;
}

/**
 * @param		buff	Zeiger auf Puffer
 * @param		to_sec	Timeout in Sekunden
 * @param		to_usec	Timeout in Mikrosekunden
 * @return	Gibt bei Timeout 0 zurück, bei Fehlern einen Wert < 0. Ansonsten 1.
 */
int ClientSocket::Rx(string &buff, size_t &len, long to_sec, long to_usec){
	int r;
	size_t maxlen;
	char c;

	buff = "";
	maxlen = len;
	len = 0;

	for(size_t i = 0; i < maxlen && EXIT_FLAG_IS_NOT_SET; i++){
		if((r = ReadChar(c, to_sec, to_usec)) != 1)
			return r;

		buff += c;
		len++;
	}

	return 1;
}
