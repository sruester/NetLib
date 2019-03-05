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
#ifndef __SSLCLIENT_H_SEEN
#define __SSLCLIENT_H_SEEN

#include <string>
#include <openssl/ssl.h>
#include <pthread.h>
#include "ClientSocket.h"

using namespace std;

class SSLClient : public ClientSocket
{

public:

    enum SSL_VERSION {
        TLS_ANY,
        SSL_v23,
        #ifndef OPENSSL_NO_SSL3_METHOD
        SSL_v3,
        #endif
    };

    enum SSLCLIENT_ERROR {
        NO_ERROR = 0,
        ERR_CONNECTION_ALREADY_OPEN,
        ERR_TCP_CONNECT_FAILED,
        ERR_CREATE_SSL_CONTEXT_FAILED,
        ERR_CREATE_SSL_OBJECT_FAILED,
        ERR_CONNECTTION_SHUTDOWN,
        ERR_CONNECTTION_TERMINATED,
        ERR_SEND_FAILED,
        ERR_SENT_PARTIAL,
        ERR_RECEIVE_FAILED,
    };

    SSLClient(string host, unsigned short port);
    ~SSLClient();

    void RestrictSSLVersion(SSL_VERSION useSSLVersion);
    void RestrictCipherSuites(std::string ciphers);
    void RestrictECCurves(std::string curves);

    void SetSSLOptions(long options);
    void ClearSSLOptions(long options);

    std::string GetCurrentCipherName()    { return currentCipherName; }
    std::string GetCurrentCipherVersion() { return currentCipherVersion; }
    std::string GetKeyExchangeMethod()    { return kxMethod; }
    std::string GetCurrentCipherDesc();
    int GetCurrentCipherBitLength()       { return currentCipherBitLength; }
    int GetKeyExchangeBits()              { return kxBits; }

    SSLCLIENT_ERROR GetLastError()        { return last_error; }

	bool Open(void);
	void Close(void);

private:

    /* attributes */

    static bool libssl_is_initialized;
    static pthread_mutex_t glob_sslclient_lock;

    pthread_mutex_t ssl_lock = PTHREAD_MUTEX_INITIALIZER;

    SSL_CTX *ctx;
    SSL *ssl;

    BIO *bio_stdout;

    SSL_VERSION useSSLVersion;
    std::string ciphers;
    std::string curves;
    std::string kxMethod;
    int kxBits;
    long set_options, clear_options;

    std::string currentCipherName;
    std::string currentCipherVersion;
    int currentCipherBitLength;
    std::string cipher_desc;

    SSLCLIENT_ERROR last_error;

    /* methods */

    void StartSSLConnection();
    const char *GetSSLError(int ret);

    void WriteData(const char *data, size_t len);
    bool TryRead(long to_sec = 0, long to_usec = 100);
    int ReadChar(char &c, long to_sec = 0, long to_usec = 100);

};


#endif // __SSLCLIENT_H_SEEN
