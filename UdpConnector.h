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
#ifndef __UDPCONNECOTR_H
#define __UDPCONNECOTR_H

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
#include <arpa/inet.h>
#include <pthread.h>

using namespace std;

class UdpConnector {

public:

	static const int RX_OK			=  1;
	static const int RX_TIMEOUT	=  0;
	static const int RX_EOF	    = -1;
	static const int RX_ERROR	  = -2;
	static const int RX_SCK_NA  = -3;

	UdpConnector();
	~UdpConnector();

	bool Open(void);
	bool Bind(unsigned short port);
	void Close(void);

	bool IsOpen(void) { return (sock != 0); }

	int Rx(string &data, string &from, long to_sec, long to_usec);
	int Rx(string &data, string &fromip, uint16_t &fromport, long to_sec, long to_usec);

	bool SetDestination(string host, unsigned short port);
	bool Tx(const uint8_t *data, unsigned int datalen);
	bool Tx(string data);

private:

	unsigned short bindport;
	pthread_mutex_t sock_lock;

	int sock;
	void CreateSocket(void);

	bool destination_ok;
	struct sockaddr_in dest;
	void ResolveHostname(string host);

	void WriteData(const uint8_t *data, size_t len);

	bool TryRead(long to_sec, long to_usec);
};

#endif // __UDPCONNECOTR_H
