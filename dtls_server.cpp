#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "my_cbio.h"

#define COOKIE_SECRET_LENGTH 16
#define EPOLL_TIMEOUT 1000 // miliseconds
#define SOCKET_IDLE_TIMEOUT 600 // seconds
#define SHUTDOWN_TIMEOUT 5 // seconds

#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define MIN(x, y) ((x) <= (y) ? (x) : (y))


struct UdpConnectInfo;
typedef int (*EventHandler)(UdpConnectInfo* pstConnInfo);


#if (__cplusplus >= 201103L)  // c++11
#include <unordered_map>
typedef std::unordered_map<CustomBuffer*, UdpConnectInfo*, HashCustomBuffer, CompareCustomBuffer> ConnectMap; 
typedef std::unordered_map<CustomBuffer*, UdpConnectInfo*, HashCustomBuffer, CompareCustomBuffer>::iterator ConnectMapIterator;

#else // c++98

#include <tr1/unordered_map>
typedef std::tr1::unordered_map<CustomBuffer*, UdpConnectInfo*, HashCustomBuffer, CompareCustomBuffer> ConnectMap;
typedef std::tr1::unordered_map<CustomBuffer*, UdpConnectInfo*, HashCustomBuffer, CompareCustomBuffer>::iterator ConnectMapIterator;

#endif

typedef enum{
	DTLS_STATUS_INIT=0, // wait connect
	DTLS_STATUS_CONNECTED=1, // connected
	DTLS_STATUS_SHUTDOWN=2, // shutdown & wait close
}ConnStatusType;

struct UdpConnectInfo{
	CustomBioData	m_stBioData;
	SSL*			m_pstSSL;
	int 			m_iStatus;
	time_t			m_tLastAccess;
	ConnectMap*		m_pstConnMap;
	EventHandler	m_fEvHandle;

	UdpConnectInfo()
	{
		m_pstSSL = NULL;
		m_iStatus = DTLS_STATUS_INIT;
		m_tLastAccess = 0;
		m_pstConnMap = NULL;
		m_fEvHandle = NULL;
	}

	~UdpConnectInfo()
	{
		if(m_pstConnMap != NULL)
			m_pstConnMap->erase(&(m_stBioData.m_stAddrBuf));

		if(m_pstSSL != NULL)
			SSL_free(m_pstSSL);
		m_pstSSL = NULL;
		m_iStatus = DTLS_STATUS_INIT;
		m_tLastAccess = 0;
		m_pstConnMap = NULL;
		m_fEvHandle = NULL;
	}
};

unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int listen_fd;
SSL_CTX *ctx;
ConnectMap stConnMap;
UdpConnectInfo* pstListenConnInfo = NULL;


UdpConnectInfo* new_udpconnect_info();


void signal_handler(int sig)
{
    if (sig==SIGINT)
        fprintf(stderr, "signal SIGINT\n");
    else
        fprintf(stderr, "get signal[%d]\n", sig);
}

int init_cookie_secret()
{
	if(!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH)){
		printf("error setting random cookie secret\n");
		return -1;
	}

	return 0;
}


int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	
	BIO_ADDR* pstPeerAddr = BIO_ADDR_new();
	struct sockaddr_storage stAddr;
	struct sockaddr_in* ipv4_addr = (struct sockaddr_in*)&stAddr;
	struct sockaddr_in6* ipv6_addr = (struct sockaddr_in6*)&stAddr;

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), pstPeerAddr);
 
	stAddr.ss_family = BIO_ADDR_family(pstPeerAddr);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (stAddr.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			ipv4_addr->sin_port = BIO_ADDR_rawport(pstPeerAddr);
			BIO_ADDR_rawaddress(pstPeerAddr, &ipv4_addr->sin_addr, NULL);
			break;

		case AF_INET6:
			length += sizeof(struct in6_addr);
			ipv6_addr->sin6_port = BIO_ADDR_rawport(pstPeerAddr);
			BIO_ADDR_rawaddress(pstPeerAddr, &ipv6_addr->sin6_addr, NULL);
			break;

		default:
			printf("unknow family:%d. AF_UNSPEC=%d\n", BIO_ADDR_family(pstPeerAddr), AF_UNSPEC);
			BIO_ADDR_free(pstPeerAddr);
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);

	BIO_ADDR_free(pstPeerAddr);

	buffer = (unsigned char*) OPENSSL_malloc(length);
	if(buffer == NULL){
		printf("out of memory\n");
		
		return 0;
	}
 
	switch (stAddr.ss_family) {
		case AF_INET:
			memcpy(buffer, &ipv4_addr->sin_port, sizeof(in_port_t));
			memcpy(buffer + sizeof(ipv4_addr->sin_port), &ipv4_addr->sin_addr, sizeof(struct in_addr));
			break;

		case AF_INET6:
			memcpy(buffer, &ipv6_addr->sin6_port, sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t), &ipv6_addr->sin6_addr, sizeof(struct in6_addr));
			break;

		default:
			OPENSSL_assert(0);
			break;
	}
 
	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH, (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);
 
	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
	int ret;
	unsigned char result[EVP_MAX_MD_SIZE];
	unsigned int result_len;

	ret = generate_cookie(ssl, result, &result_len);
	if(ret != 1)
		return ret;

	if(cookie_len == result_len && memcmp(result, cookie, result_len) == 0)
		return 1;

	return 0;
}


int dtls_verify_callback (int ok, X509_STORE_CTX *ctx)
{
     /* This function should ask the user
     * if he trusts the received certificate.
     * Here we always trust.
     */
     return 1;
}



int on_message(UdpConnectInfo* pstInfo)
{
	int len;
	char buf[200];

	printf("socket[%d] %s ...\n", pstInfo->m_stBioData.m_iFd, __FUNCTION__);

	len = SSL_read(pstInfo->m_pstSSL, buf, sizeof(buf) - 1);
	if(len == 0){
		SSL_shutdown(pstInfo->m_pstSSL);
		
		dump_addr((struct sockaddr *)&pstInfo->m_stBioData.m_stClientAddr, "client close: ");
		return(1);
	}
	else if(len <= 0){
		switch (SSL_get_error(pstInfo->m_pstSSL, len)) {
			case SSL_ERROR_NONE:
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_ZERO_RETURN:
				return(0);

			case SSL_ERROR_SYSCALL:
				printf("ssl error syscall\n");
				return(-1);

			case SSL_ERROR_SSL:
				printf("ssl error ssl\n");
				return(-1);

			default:
				printf("unknow error when ssl accept\n");
				return(-1);
		}
	}
	buf[len] = 0;

	printf("recv: %d bytes:%s\n", len, buf);

	len = SSL_write(pstInfo->m_pstSSL, buf, len);
	if(len <= 0){
		switch (SSL_get_error(pstInfo->m_pstSSL, len)) {
			case SSL_ERROR_NONE:
			case SSL_ERROR_WANT_WRITE:
			case SSL_ERROR_ZERO_RETURN:
				return(0);

			case SSL_ERROR_SYSCALL:
				printf("ssl error syscall\n");
				return(-1);

			case SSL_ERROR_SSL:
				printf("ssl error ssl\n");
				return(-1);

			default:
				printf("unknow error when ssl accept\n");
				return(-1);
		}
	}
	printf("send %d bytes\n", len);

	return(0);
}

int on_connect(UdpConnectInfo* pstInfo)
{
	int iRet;
	int tmp;

	iRet = SSL_accept(pstInfo->m_pstSSL);
	printf("SSL_accept():%d\n", iRet);

	if(iRet == 1){
		dump_addr((struct sockaddr *)&pstInfo->m_stBioData.m_stClientAddr, "new connection: ");

		pstInfo->m_fEvHandle = on_message;
		pstInfo->m_iStatus = DTLS_STATUS_CONNECTED;
	}
	
	else{
		tmp = SSL_get_error(pstInfo->m_pstSSL, iRet);
		switch (tmp) {
			case SSL_ERROR_NONE:
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				printf("SSL_accept delay\n");
				return(0);

			case SSL_ERROR_SYSCALL:
				printf("SSL_accept error syscall\n");
				return(0);

			case SSL_ERROR_SSL:
				printf("SSL_accept error ssl\n");
				return(-1);

			default:
				printf("unknow error when ssl accept:%d\n", tmp);
				return(-1);
		}
	}

	return(0);
}

int do_new_connection(UdpConnectInfo*& pstInfo)
{
	int iRet;

	BIO_ADDR* pstPeerAddr = BIO_ADDR_new();
	iRet = DTLSv1_listen(pstInfo->m_pstSSL, pstPeerAddr);
	printf("DTLSv1_listen():%d\n", iRet);

	BIO_ADDR_free(pstPeerAddr);

	if(iRet != 1)
		return(0);

	(*pstInfo->m_pstConnMap)[&pstInfo->m_stBioData.m_stAddrBuf] = pstInfo;
	pstInfo->m_fEvHandle(pstInfo);

	pstInfo = new_udpconnect_info();

	return(0);
}

UdpConnectInfo* new_udpconnect_info()
{
	UdpConnectInfo* pstInfo;

	pstInfo = new UdpConnectInfo;
	if(pstInfo == NULL){
		printf("new UdpConnectInfo fail: %m\n");
		return(NULL);
	}

	pstInfo->m_pstSSL = SSL_new(ctx);
	if(pstInfo->m_pstSSL == NULL){
		printf("SSL_new fail:%m\n");
		delete pstInfo;
		return(NULL);
	}

	pstInfo->m_stBioData.m_stAddrBuf.m_iCap = sizeof(struct sockaddr_storage);
	pstInfo->m_stBioData.m_stAddrBuf.m_iLen = sizeof(struct sockaddr_storage);
	memset(&pstInfo->m_stBioData.m_stClientAddr, 0, sizeof(struct sockaddr_storage));
	pstInfo->m_stBioData.m_iPeekMode = 0;
	pstInfo->m_pstConnMap = &stConnMap; // connect map
	pstInfo->m_fEvHandle = on_connect;

	BIO *bio = BIO_new(BIO_s_custom());
	BIO_set_data(bio, (void *)&pstInfo->m_stBioData);
	BIO_set_init(bio, 1);
	SSL_set_bio(pstInfo->m_pstSSL, bio, bio);

	return pstInfo;
}


void check_idle_socket(time_t time_now)
{
	for(ConnectMapIterator it=stConnMap.begin(); it != stConnMap.end(); ){
		UdpConnectInfo* pstInfo = it->second;
		if(time_now - pstInfo->m_tLastAccess < SOCKET_IDLE_TIMEOUT){
			++it;
			continue;
		}

		if(pstInfo->m_iStatus == DTLS_STATUS_SHUTDOWN){
			if(time_now - pstInfo->m_tLastAccess < SOCKET_IDLE_TIMEOUT + SHUTDOWN_TIMEOUT){
				++it;
				continue;
			}

			printf("client socket[%d] shutdown timeout, release it now\n", pstInfo->m_stBioData.m_iFd);
		
			stConnMap.erase(it++);

			delete pstInfo;
		}
		else{
			printf("client socket[%d] idle timeout, shutdown it now\n", pstInfo->m_stBioData.m_iFd);
		
			SSL_shutdown(pstInfo->m_pstSSL);
			++it;
		}

	}

	return;
}


void show_usage(const char* name)
{
	printf("usage: %s ip:port\n", name);
}

int main(int argc, char* argv[])
{
	int ret;
	char* p;
	int port;
	int listen_fd;
	sockaddr_in listen_addr;
	unsigned int listen_addr_len = sizeof(struct sockaddr_in);
	int on = 1, off = 0;
	int epfd;

	if(argc < 2){
		show_usage(argv[0]);
		exit(1);
	}

	p = strchr(argv[1], ':');
	if(p == NULL){
		show_usage(argv[0]);
		exit(1);
	}
	port = atoi(p+1);
	if(port <= 0 || port > 65535){
		printf("invalid port:%d\n", port);
		exit(1);
	}
	char ip[32];
	memset(ip, 0, sizeof(ip));
	strncpy(ip, argv[1],  MIN(sizeof(ip) - 1, p - argv[1]));

	memset(&listen_addr, 0, sizeof(listen_addr));
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_port = htons(port);

	ret = inet_pton(AF_INET, ip, &listen_addr.sin_addr);
	if(ret == 0){
		printf("listen address invalid:%s\n", ip);
		exit(1);
	}


	init_cookie_secret();

	// ssl init
	SSL_load_error_strings();
    SSL_library_init();

    const SSL_METHOD *mtd = DTLS_server_method();
    ctx = SSL_CTX_new(mtd);
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    if(SSL_CTX_use_certificate_chain_file(ctx, "server-cert.pem") != 1){
    	printf("load cert chain file fail\n");
    	exit(1);
    }
    if(SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM) != 1){
    	printf("load private key file fail\n");
    	exit(1);
    }
    if(SSL_CTX_check_private_key (ctx) != 1){
		printf("invalid private key!\n");
		exit(1);
	}

	/* Client has to authenticate */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);

	ret = SSL_CTX_load_verify_locations(ctx, "root-ca.pem", NULL);
    printf("SSL_CTX_load_verify_location(): %d\n", ret);
    
    ret = SSL_CTX_set_default_verify_file(ctx);
    printf("SSL_CTX_set_default_verify_file(): %d\n", ret);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

 
	SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);


    epfd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event epe = {0};

    listen_fd = socket(listen_addr.sin_family, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
    if(listen_fd < 0){
    	printf("listen socket fail:%m\n");
    	exit(3);
    }
    else{
    	printf("listen fd:%d\n", listen_fd);
    }
    
    UdpConnectInfo* pstListenConnInfo = new_udpconnect_info();
    if(pstListenConnInfo == NULL){
    	printf("new udpconnect info error:%m\n");
    	exit(4);
    }
    pstListenConnInfo->m_fEvHandle = on_connect;
    

	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));
#ifdef SO_REUSEPORT
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, (const void*) &on, (socklen_t) sizeof(on));
#endif

    ret = bind(listen_fd, (struct sockaddr *)&listen_addr, (socklen_t)listen_addr_len);
    if(ret != 0){
    	printf("bind addr[%s] error:%m\n", argv[0]);
    	exit(2);
    }


    epe.events = EPOLLIN|EPOLLET;
    epe.data.fd = listen_fd;
	epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &epe);


	signal(SIGINT, signal_handler);

	int ev_num;
	struct epoll_event evs[10];
	time_t last_time=0, time_now=0;
	CustomBuffer* pstPkg = CustomBuffer::NewBuf(2000); // buffer must large than MTU

	while(1){
		ev_num = epoll_wait(epfd, evs, sizeof(evs)/sizeof(evs[0]), EPOLL_TIMEOUT);
		if(ev_num == -1){
			printf("epoll_wait error: %m\n");
			break;
		}

		time_now = time(NULL);

		for(int i=0; i < ev_num; i++){
			if(evs[i].data.fd < 0){
				printf("invalid epoll event. fd:%d\n", evs[i].data.fd);
				continue;
			}

			while((pstPkg->m_iLen = recvfrom(evs[i].data.fd, pstPkg->BufBegin(), pstPkg->m_iCap, 0, (struct sockaddr *)&pstListenConnInfo->m_stBioData.m_stClientAddr, (socklen_t*)&pstListenConnInfo->m_stBioData.m_stAddrBuf.m_iLen)) > 0){
				dump_addr((struct sockaddr *)&pstListenConnInfo->m_stBioData.m_stClientAddr, "<< ");

				ConnectMapIterator it = stConnMap.find(&(pstListenConnInfo->m_stBioData.m_stAddrBuf));
				if(it != stConnMap.end()){
					dump_addr((struct sockaddr *)&pstListenConnInfo->m_stBioData.m_stClientAddr, "recv data from client: ");

					UdpConnectInfo* pstConn = it->second;

					pstConn->m_tLastAccess = time_now;
					pstConn->m_stBioData.m_stQueue.push_back((void*)pstPkg);
					ret = pstConn->m_fEvHandle(pstConn);
					if(ret != 0){
						if(ret > 0)
							dump_addr((struct sockaddr *)&pstConn->m_stBioData.m_stClientAddr, "client shutdown socket: ");
						else
							dump_addr((struct sockaddr *)&pstConn->m_stBioData.m_stClientAddr, "event process fail! ");

						stConnMap.erase(it);
						delete pstConn;
					}
				}
				else{
					dump_addr((struct sockaddr *)&pstListenConnInfo->m_stBioData.m_stClientAddr, "new connection: ");

					pstListenConnInfo->m_stBioData.m_iFd = evs[i].data.fd;
					pstListenConnInfo->m_stBioData.m_stQueue.push_back((void*)pstPkg);

					ret = do_new_connection(pstListenConnInfo);
				}

				pstPkg = CustomBuffer::NewBuf(2000);
			}
		}
		
		
		if(time_now - last_time >= (SOCKET_IDLE_TIMEOUT / 2)){
			check_idle_socket(time_now);
			last_time = time_now;
		}
	}

	for(ConnectMapIterator it=stConnMap.begin(); it != stConnMap.end(); ){
		UdpConnectInfo* pstConn = it->second;
		
		stConnMap.erase(it++);

		delete pstConn;
	}

	free(pstPkg);
	pstPkg = NULL;

	delete pstListenConnInfo;
	pstListenConnInfo = NULL;

	close(listen_fd);
	SSL_CTX_free(ctx);

	BIO_s_custom_meth_free();

	return(0);
}
