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
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "SSLClient.h"

/*
 * Constructor / Destructor
 */

SSLClient::SSLClient(string host, unsigned short port) : ClientSocket(host, port)
{
    if(!libssl_is_initialized) {
        pthread_mutex_lock(&glob_sslclient_lock);
            if(!libssl_is_initialized)
            {
                OpenSSL_add_all_algorithms();
                ERR_load_BIO_strings();
                ERR_load_crypto_strings();
                SSL_load_error_strings();
                SSL_library_init();
                libssl_is_initialized = true;
            }
        pthread_mutex_unlock(&glob_sslclient_lock);
    }

    ctx = NULL;
    ssl = NULL;
    useSSLVersion = TLS_ANY;
    ciphers = "";
    curves = "";
    kxMethod = "";
    kxBits = 0;
    set_options = 0;
    clear_options = 0;
    bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
    last_error = NO_ERROR;
}

SSLClient::~SSLClient()
{
    Close();
}

/*
 * Configuration
 */

void SSLClient::RestrictSSLVersion(SSL_VERSION useSSLVersion)
{
    this->useSSLVersion = useSSLVersion;
}

void SSLClient::RestrictCipherSuites(std::string ciphers)
{
    this->ciphers = ciphers;
}

void SSLClient::RestrictECCurves(std::string curves)
{
    this->curves = curves;
}

void SSLClient::SetSSLOptions(long options)
{
    set_options |= options;
}

void SSLClient::ClearSSLOptions(long options)
{
    clear_options |= options;
}


/*
 * Open / Close
 */

void SSLClient::Close(void)
{
    if(!IsOpen())
        return;

    SSL_shutdown(ssl);

    pthread_mutex_lock(&ssl_lock);

        ClientSocket::Close();

        SSL_free(ssl);
        ClientSocket::Close();
        SSL_CTX_free(ctx);

    pthread_mutex_unlock(&ssl_lock);
}

bool SSLClient::Open()
{
    bool ret = false;

    pthread_mutex_lock(&ssl_lock);

        try
        {
            StartSSLConnection();
            ret = true;
        }
        catch(const char *err)
        {
            //std::cerr << err << std::endl;
        }

    pthread_mutex_unlock(&ssl_lock);

    if(!ret)
        ClientSocket::Close();

    return ret;
}

void SSLClient::StartSSLConnection()
{
    if(IsOpen())
    {
        last_error = ERR_CONNECTION_ALREADY_OPEN;
        throw "Connection already open";
    }

    if(ClientSocket::Open() == false)
    {
        last_error = ERR_TCP_CONNECT_FAILED;
        throw "Could not connect to host";
    }

    ERR_clear_error();

    // Choose TLS/SSL version
    const SSL_METHOD *method;

    switch (useSSLVersion)
    {
    case SSL_v23:   method = SSLv23_method();  break;
    #ifndef OPENSSL_NO_SSL3_METHOD
    case SSL_v3:    method = SSLv3_method();   break;
    #endif
    default:        method = TLS_method();     break;
    }

    // Create SSL context
    if((ctx = SSL_CTX_new(method)) == NULL)
    {
        ClientSocket::Close();
        last_error = ERR_CREATE_SSL_CONTEXT_FAILED;
        throw "Could not create SSL context";
    }

    // Restrict ciphers and curves
    if(ciphers != "")
        SSL_CTX_set_cipher_list(ctx, ciphers.c_str());

    if(curves != "")
        SSL_CTX_set1_curves_list(ctx, curves.c_str());

    // Set SSL options
    SSL_CTX_set_options(ctx, set_options);
    SSL_CTX_clear_options(ctx, clear_options);

    // Create SSL object
    if((ssl = SSL_new(ctx)) == NULL)
    {
        ClientSocket::Close();
        SSL_CTX_free(ctx);
        last_error = ERR_CREATE_SSL_OBJECT_FAILED;
        throw "Could not create SSL object";
    }

    // Link SSL object to TCP socket
    SSL_set_fd(ssl, sock);

    // Do SSL handshake
    int ret;
    if((ret = SSL_connect(ssl)) != 1)
    {
        ClientSocket::Close();
        SSL_free(ssl);
        SSL_CTX_free(ctx);

        //ERR_print_errors(bio_stdout);

        if(ret == 0)
        {
            last_error = ERR_CONNECTTION_SHUTDOWN;
            throw "SSL connect failed. Connection shut down";
        }
        else
        {
            last_error = ERR_CONNECTTION_TERMINATED;
            throw "SSL connect failed. Connection terminated";
        }
    }

    currentCipherName = SSL_get_cipher_name(ssl);
    SSL_get_cipher_bits(ssl, &currentCipherBitLength);
    currentCipherVersion = SSL_get_cipher_version(ssl);

    EVP_PKEY *key;
    if (SSL_get_server_tmp_key(ssl, &key))
    {
        kxBits = EVP_PKEY_bits(key);

        switch (EVP_PKEY_id(key)) {
        case EVP_PKEY_RSA:
            kxMethod = "RSA";
            break;

        case EVP_PKEY_DH:
            kxMethod = "DH";
            break;

        case EVP_PKEY_EC:
            int nid;
            EC_KEY *ec;
            ec = EVP_PKEY_get1_EC_KEY(key);
            nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
            EC_KEY_free(ec);

            const char *cname;
            cname = EC_curve_nid2nist(nid);
            if (!cname)
                cname = OBJ_nid2sn(nid);

            kxMethod = cname;
            break;

        default:
            kxMethod = OBJ_nid2sn(EVP_PKEY_id(key));
        }
        EVP_PKEY_free(key);
    }

}


/*
 * Information & error handling
 */

std::string SSLClient::GetCurrentCipherDesc()
{
    cipher_desc = "";

    if(IsOpen())
    {
        int n = 1024;
        char buf[n + 1];

        const SSL_CIPHER *c = SSL_get_current_cipher(ssl);
        if(SSL_CIPHER_description(c, buf, n))
        {
            cipher_desc = buf;
        }

    }

    return cipher_desc;
}

const char *SSLClient::GetSSLError(int ret)
{
    switch(ret)
    {
    case SSL_ERROR_NONE:
        return "SSL_ERROR_NONE";
    case SSL_ERROR_ZERO_RETURN:
        return "SSL_ERROR_ZERO_RETURN";
    case SSL_ERROR_WANT_READ:
        return "SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE";
    case SSL_ERROR_WANT_WRITE:
        return "SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE";
    case SSL_ERROR_WANT_CONNECT:
        return "SSL_ERROR_WANT_CONNECT, SSL_ERROR_WANT_ACCEPT";
    case SSL_ERROR_WANT_ACCEPT:
        return "SSL_ERROR_WANT_CONNECT, SSL_ERROR_WANT_ACCEPT";
    case SSL_ERROR_WANT_X509_LOOKUP:
        return "SSL_ERROR_WANT_X509_LOOKUP";
    case SSL_ERROR_WANT_ASYNC:
        return "SSL_ERROR_WANT_ASYNC";
    case SSL_ERROR_WANT_ASYNC_JOB:
        return "SSL_ERROR_WANT_ASYNC_JOB";
    case SSL_ERROR_SYSCALL:
        return "SSL_ERROR_SYSCALL";
    case SSL_ERROR_SSL:
        return "SSL_ERROR_SSL";
    default:
        return "Unknown SSL error";
    }
}


/*
 *	WRITE FUNCTIONS
 */

void SSLClient::WriteData(const char *data, size_t len){
	int r;

	if(!len)
		return;

	if(!IsOpen())
		return;

	CheckSockReady();

    r = SSL_write(ssl, data, len);

	if(r < 0)
    {
        last_error = ERR_SEND_FAILED;
		throw "Error when trying to write to socket";
    }

	if(r != (int)len)
    {
        last_error = ERR_SENT_PARTIAL;
		throw "Could not send all data";
    }

	return;
}


/*
 *	READ FUNCTIONS
 */

bool SSLClient::TryRead(long to_sec, long to_usec){
    if(SSL_has_pending(ssl))
        return true;

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
    {
        last_error = ERR_RECEIVE_FAILED;
		throw "Error while trying to read from socket";
    }

	if(FD_ISSET(sock, &fdse))
    {
        last_error = ERR_RECEIVE_FAILED;
		throw "Error found while trying to read from socket";
    }

	return true;
}

int SSLClient::ReadChar(char &c, long to_sec, long to_usec){
	int r = 0;

	if(!IsOpen())
		return RX_SCK_NA;

	try {
		if(!TryRead(to_sec, to_usec))
			return RX_TIMEOUT;

        r = SSL_read(ssl, &c, 1);

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
		//cerr << err << endl;
		return RX_ERROR;
	}

	return 1;
}
