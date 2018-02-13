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
#include "ServerSocket.h"
#include "ClientSocket.h"

using namespace std;



ServerSocket::ServerSocket(unsigned short port){
	this->port = port;
	pthread_mutex_init(&sock_lock, NULL);
}

ServerSocket::~ServerSocket(){
	pthread_mutex_destroy(&sock_lock);
}


void ServerSocket::CreateSocket(void){
	Close();

	pthread_mutex_lock(&sock_lock);
		sock = socket(AF_INET, SOCK_STREAM, 0);
		if(sock < 0)	sock = 0;
	pthread_mutex_unlock(&sock_lock);

	if(!sock)
		throw "Create socket failed";
}

void ServerSocket::StartListen(void){
	throw "Not Implemented";
}

bool ServerSocket::Listen(void){
	try {
		CreateSocket();
		StartListen();

	}catch(const char*s){
		cerr << s << endl;
		return false;
	}

	return true;
}

void ServerSocket::Close(void){
	if(!sock)
		return;

	pthread_mutex_lock(&sock_lock);
		close(sock);
		sock = 0;
	pthread_mutex_unlock(&sock_lock);
}




