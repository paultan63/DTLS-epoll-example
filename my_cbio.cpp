#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include <openssl/ssl.h>

#include "my_cbio.h"


void dump_hex(const unsigned char *buf, size_t len, const char *indent)
{
    size_t i;

    for(i=0; i<len; ++i)
    {
        if (i%16==0)
            fputs(indent, stderr);
        fprintf(stderr, "%02X", buf[i]);
        switch (i%16)
        {
            case 7:
                fputs("   ", stderr);
                break;
            case 15:
                fputc('\n', stderr);
                break;
            default:
                fputc(' ', stderr);
                break;
        }
    }
    if (i%16)
        fputc('\n', stderr);
}


const char *sdump_addr(struct sockaddr *sa)
{
    static char buf[1024];

    switch (sa->sa_family)
    {
        case AF_INET:
            memmove(buf, "INET: ", 6);
            inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, buf+6, sizeof(buf)-6);
            sprintf(buf+strlen(buf), ":%d", ntohs(((struct sockaddr_in *)sa)->sin_port));
            break;

        case AF_INET6:
            memmove(buf, "INET6: [", 8);
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, buf+8, sizeof(buf)-8);
            sprintf(buf+strlen(buf), "]:%d", ntohs(((struct sockaddr_in6 *)sa)->sin6_port));
            break;

        default:
            memmove(buf, "unknown", 8);
            break;
    }

    return buf;
}

void dump_addr(struct sockaddr *sa, const char *indent)
{
    fprintf(stderr, "%s%s\n", indent, sdump_addr(sa));
}


// #define fprintf(...)

int BIO_s_custom_write_ex(BIO *b, const char *data, size_t dlen, size_t *written)
{
    fprintf(stderr, "%s: BIO[0x%016lX], data[0x%016lX], dlen[%ld], *written[%ld]\n", __FUNCTION__, b, data, dlen, *written);
    fflush(stderr);

    return -1;
}

int BIO_s_custom_write(BIO *b, const char *data, int dlen)
{
    int ret;
    CustomBioData *cdp;

    ret = -1;
    fprintf(stderr, "%s: BIO[0x%016lX], buf[0x%016lX], dlen[%ld]\n", __FUNCTION__, b, data, dlen);
    
    cdp = (CustomBioData *)BIO_get_data(b);

    dump_addr((struct sockaddr *)&cdp->m_stClientAddr, ">> ");
//     dump_hex((unsigned const char *)data, dlen, "    ");
    ret = sendto(cdp->m_iFd, data, dlen, 0, (struct sockaddr *)&cdp->m_stClientAddr, cdp->m_stAddrBuf.m_iLen);
    if (ret >= 0)
        fprintf(stderr, "  %d bytes sent\n", ret);
    else
        fprintf(stderr, "  ret: %d errno: [%d] %s\n", ret, errno, strerror(errno));

    return ret;
}

int BIO_s_custom_read_ex(BIO *b, char *data, size_t dlen, size_t *readbytes)
{
    fprintf(stderr, "%s: BIO[0x%016lX], data[0x%016lX], dlen[%ld], *readbytes[%ld]\n", __FUNCTION__, b, data, dlen, *readbytes);
    
    return -1;
}

int BIO_s_custom_read(BIO *b, char *data, int dlen)
{
    int ret;
    CustomBioData *cdp;
    std::deque<void*> *dp;
    CustomBuffer *bp;

    ret = -1;
    cdp = (CustomBioData *)BIO_get_data(b);

    fprintf(stderr, "%s: BIO[0x%016lX], data[0x%016lX], dlen[%ld], peekmode:%d\n", __FUNCTION__, b, data, dlen, cdp->m_iPeekMode);

    
    dp = &cdp->m_stQueue;
    fprintf(stderr, "  data[0x%016lX] queue_size: %d\n", dp, dp->size());
    if (!dp->empty()){
        bp = (CustomBuffer*)dp->front();

        ret = (bp->m_iLen <= dlen) ? bp->m_iLen : dlen;
        memmove(data, bp->BufBegin(), ret);

        fprintf(stderr, "  buf[0x%016lX] read len:%d\n", bp, ret);

        if (cdp->m_iPeekMode == 0){
            dp->pop_front();
            free(bp);
        }
    }

    return ret;
}

int BIO_s_custom_gets(BIO *b, char *data, int size);

int BIO_s_custom_puts(BIO *b, const char *data);


static int copy_addr(struct sockaddr_storage* peer, const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        *(struct sockaddr_in *)peer = *(const struct sockaddr_in *)sa;
        return 1;
    }

    if (sa->sa_family == AF_INET6) {
        *(struct sockaddr_in6 *)peer = *(const struct sockaddr_in6 *)sa;
        return 1;
    }

    if (sa->sa_family == AF_UNIX) {
        *(struct sockaddr_un *)peer = *(const struct sockaddr_un *)sa;
        return 1;
    }


    return 0;
}

long BIO_s_custom_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 0;

//    fprintf(stderr, "%s: BIO[0x%016lX], cmd[%d], num[%ld], ptr[0x%016lX]\n", __FUNCTION__, b, cmd, num, ptr);
//    fflush(stderr);

    CustomBioData* pstData = (CustomBioData *)BIO_get_data(b);

    switch(cmd)
    {
        case BIO_CTRL_FLUSH:
            ret = 1;
            break;
            
        case BIO_CTRL_DGRAM_CONNECT:
            copy_addr(&pstData->m_stClientAddr, (struct sockaddr *)ptr);
            break;

        case BIO_CTRL_DGRAM_SET_CONNECTED:
            if(ptr != NULL) {
                pstData->m_iConnected = 1;
                copy_addr(&pstData->m_stClientAddr, (struct sockaddr *)ptr);
            } else {
                pstData->m_iConnected = 0;
                memset(&pstData->m_stClientAddr, 0, sizeof(pstData->m_stClientAddr));
            }
            break;

        case BIO_CTRL_DGRAM_SET_PEER: 
            if(ptr == NULL)
                break;

            copy_addr(&pstData->m_stClientAddr, (struct sockaddr *)ptr);
            break;

        case BIO_CTRL_DGRAM_GET_PEER:
            if(ptr == NULL)
                break;

            switch(pstData->m_stClientAddr.ss_family){
                case AF_INET:
                    ret = sizeof(struct sockaddr_in);
                    break;

                case AF_INET6:
                    ret = sizeof(struct sockaddr_in6);
                    break;

                case AF_UNIX:
                default:
                    ret = sizeof(pstData->m_stClientAddr);
                    break;
            }
            /* FIXME: if num < ret, we will only return part of an address.
               That should bee an error, no? */
            if (num == 0 || num > ret)
                num = ret;
            memcpy(ptr, &pstData->m_stClientAddr, (ret = num));
            break;


        case BIO_CTRL_WPENDING:
            ret = 0;
            break;
        case BIO_CTRL_DGRAM_QUERY_MTU:
        case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
            ret = 1500;
            break;
        case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
            ret = 96; // random guess
            break;
        case BIO_CTRL_DGRAM_SET_PEEK_MODE:
            ((CustomBioData *)BIO_get_data(b))->m_iPeekMode = !!num;
            ret = 1;
            break;
        case BIO_CTRL_PUSH:
        case BIO_CTRL_POP:
        case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
            ret = 0;
            break;
        default:
            fprintf(stderr, "%s unknow cmd. BIO[0x%016lX], cmd[%d], num[%ld], ptr[0x%016lX]\n", __FUNCTION__, b, cmd, num, ptr);
            ret = 0;
            raise(SIGTRAP);
            break;
    }

    return ret;
}

int BIO_s_custom_create(BIO *b)
{
    fprintf(stderr, "%s: BIO[0x%016lX]\n", __FUNCTION__, b);
    fflush(stderr);

    return 1;
}

int BIO_s_custom_destroy(BIO *b)
{
    fprintf(stderr, "%s: BIO[0x%016lX]\n", __FUNCTION__, b);
    fflush(stderr);

    return 1;
}

// long BIO_s_custom_callback_ctrl(BIO *, int, BIO_info_cb *);

BIO_METHOD *_BIO_s_custom = NULL; // FixMe: multi-thread race condition
BIO_METHOD *BIO_s_custom(void)
{
    if (_BIO_s_custom)
        return _BIO_s_custom;

    _BIO_s_custom = BIO_meth_new(BIO_get_new_index()|BIO_TYPE_SOURCE_SINK, "BIO_s_custom");

//     BIO_meth_set_write_ex(_BIO_s_custom, BIO_s_custom_write_ex);
    BIO_meth_set_write(_BIO_s_custom, BIO_s_custom_write);
//     BIO_meth_set_read_ex(_BIO_s_custom, BIO_s_custom_read_ex);
    BIO_meth_set_read(_BIO_s_custom, BIO_s_custom_read);
    BIO_meth_set_ctrl(_BIO_s_custom, BIO_s_custom_ctrl);
    BIO_meth_set_create(_BIO_s_custom, BIO_s_custom_create);
    BIO_meth_set_destroy(_BIO_s_custom, BIO_s_custom_destroy);
//     BIO_meth_set_callback_ctrl(_BIO_s_custom, BIO_s_custom_callback_ctrl);

    return _BIO_s_custom;
}

void BIO_s_custom_meth_free(void)
{
    if (_BIO_s_custom)
        BIO_meth_free(_BIO_s_custom);

    _BIO_s_custom = NULL;
}

