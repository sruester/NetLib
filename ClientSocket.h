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
#ifndef __CLIENTSOCKET_H
#define __CLIENTSOCKET_H

#include <iostream>
#include <string>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <netdb.h>
#include <strings.h>
#include <string.h>
#include <pthread.h>


using namespace std;

class ClientSocket {

public:

	static const int RX_TIMEOUT	=  0;
	static const int RX_EOF	    = -1;
	static const int RX_ERROR	  = -2;
	static const int RX_SCK_NA  = -3;

	volatile bool *exit_flag;

	ClientSocket(string host, unsigned short port);
	virtual ~ClientSocket();

	bool Open(void);
	void Close(void);

	bool IsOpen(void) { return (sock != 0); }

	bool Tx(const char *data, unsigned int datalen);
	bool Tx(string data);

	int Rx(char *, size_t &, long to_sec = 1, long to_usec = 0);
	int RxLine(string &buff, long to_sec = 1, long to_usec = 0);
	int Rx(string &buff, size_t &len, long to_sec = 1, long to_usec = 0);

protected:
	int sock;

	string host;
	unsigned short port;

	void CheckSockReady(void);

private:

	pthread_mutex_t sock_lock;

	struct sockaddr_in hostadr;

	void CreateSocket(void);
	void ResolveHostname(void);
	void Connect(void);

	virtual void WriteData(const char *data, size_t len);

	virtual bool TryRead(long, long to_usec = 1);
	virtual int  ReadChar(char &, long to_sec = 1, long to_usec = 0);

};

#endif // __CLIENTSOCKET_H
