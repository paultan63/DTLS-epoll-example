#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <readline/readline.h>

#include "my_cbio.h"


#define EPOLL_TIMEOUT 8000 // ms

#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define MIN(x, y) ((x) <= (y) ? (x) : (y))

void signal_handler(int sig)
{
    if (sig==SIGINT)
        fprintf(stderr, "signal SIGINT\n");
    else
        fprintf(stderr, "get signal[%d]\n", sig);

    fflush(stderr);
}

SSL *ssl;

int run = 1;
int connected = 0;

void readline_handler(char *line)
{
    if (line)
    {
        if (connected)
            SSL_write(ssl, line, strlen(line));
        else
            fputs("NOT connected\n", stderr);

        free(line);
    }
    else
    {
        fprintf(stderr, "^D\n");
        run = 0;
        if (connected)
            SSL_shutdown(ssl);
    }
}

void show_usage(const char* name)
{
    printf("usage: %s ip:port\n", name);
}

int main(int argc, char **argv)
{
    int ret;
    char* p;
    int port;
    int epfd;
    CustomBioData bio_data;

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

    struct sockaddr_in* ipv4_addr = (struct sockaddr_in*)&bio_data.m_stClientAddr;
    bio_data.m_stAddrBuf.m_iLen = sizeof(struct sockaddr_in);

    memset(ipv4_addr, 0, sizeof(struct sockaddr_in));
    ipv4_addr->sin_family = AF_INET;
    ipv4_addr->sin_port = htons(port);

    ret = inet_pton(AF_INET, ip, &ipv4_addr->sin_addr);
    if(ret == 0){
        printf("server address invalid:%s\n", ip);
        exit(1);
    }


    int sockfd = socket(ipv4_addr->sin_family, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);

    if (connect(sockfd, (struct sockaddr *)&bio_data.m_stClientAddr, bio_data.m_stAddrBuf.m_iLen)){
        fputs("failed to connect\n", stderr);

        exit(1);
    }
    bio_data.m_iFd = sockfd;
    bio_data.m_iPeekMode = 0;

    epfd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event epe = {0};

    epe.data.fd = fileno(stdin);
    epe.events = EPOLLIN;

    epoll_ctl(epfd, EPOLL_CTL_ADD, epe.data.fd, &epe);

    fcntl(fileno(stdin), F_SETFL, fcntl(fileno(stdin), F_GETFL) | O_NONBLOCK);

    SSL_load_error_strings();
    SSL_library_init();

    SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
 
    SSL_CTX_use_certificate_chain_file(ctx, "client-cert.pem");
    SSL_CTX_use_PrivateKey_file(ctx, "client-key.pem", SSL_FILETYPE_PEM);
    ret = SSL_CTX_load_verify_locations(ctx, "root-ca.pem", NULL);
    printf("SSL_CTX_load_verify_locations(): %d\n", ret);

    ret = SSL_CTX_set_default_verify_file(ctx);
    printf("SSL_CTX_set_default_verify_file(): %d\n", ret);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    ssl = SSL_new(ctx);

    BIO *custom_bio = BIO_new(BIO_s_custom());
    BIO_set_data(custom_bio, (void *)&bio_data);
    BIO_set_init(custom_bio, 1);
    SSL_set_bio(ssl, custom_bio, custom_bio);

    epe.data.fd = sockfd;
    epe.events = EPOLLIN|EPOLLET;

    epoll_ctl(epfd, EPOLL_CTL_ADD, epe.data.fd, &epe);

    signal(SIGINT, signal_handler);

    CustomBuffer *packet;
    packet = CustomBuffer::NewBuf(2000);

    ret = SSL_connect(ssl);
    if (ret==1)
    {
        connected = 1;
        fputs("connected\n", stderr);
    }
    else if (SSL_get_error(ssl, ret)==SSL_ERROR_SSL)
    {
        dump_addr((struct sockaddr *)&bio_data.m_stClientAddr, "ssl error: ");
        ERR_print_errors_fp(stderr);
    }

    rl_callback_handler_install(">> ", readline_handler);

    while(run)
    {
        ret = epoll_wait(epfd, &epe, 1, EPOLL_TIMEOUT);
        if (ret<0)
        {
            if (connected)
                SSL_shutdown(ssl);

            break;
        }
        else if (ret==0) // time out
            continue;

        if (epe.data.fd==fileno(stdin))
            rl_callback_read_char();
        if (epe.data.fd==sockfd)
        {
            while ((packet->m_iLen=recv(sockfd, packet->m_auchBuf, packet->m_iCap, 0))>=0)
            {
                fprintf(stderr, "\033[2K\r<< %d bytes\n", packet->m_iLen);

                bio_data.m_stQueue.push_back(packet);


                packet = CustomBuffer::NewBuf(2000);

                if (connected)
                {
                    packet->m_iLen = SSL_read(ssl, packet->m_auchBuf, packet->m_iCap);

                    if (packet->m_iLen>0)
                    {
                    packet->m_auchBuf[packet->m_iLen] = 0;
                    printf("recv: %s\n", (const char*)packet->m_auchBuf);
                    }
                    else if (packet->m_iLen==0)
                    {
                        SSL_shutdown(ssl);
                        run = 0;
                    }
                }
                else
                {
                    ret = SSL_connect(ssl);

                    if (ret==1)
                    {
                        connected = 1;
                        fputs("connected\n", stderr);
                    }
                    else if (SSL_get_error(ssl, ret)==SSL_ERROR_SSL)
                    {
                        dump_addr((struct sockaddr *)&bio_data.m_stClientAddr, "ssl error: ");
                        ERR_print_errors_fp(stderr);

                        run = 0;
                        break;
                    }
                }
                rl_forced_update_display();
            }
        }
    }

    delete packet;

    SSL_free(ssl);
    SSL_CTX_free(ctx);

    BIO_s_custom_meth_free();

    rl_cleanup_after_signal();
    fputc('\n', stderr);

    close(sockfd);

    rl_callback_handler_remove();

    return 0;
}

