#ifndef MY_CBIO_H
#define MY_CBIO_H

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <deque>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/bio.h"

struct CustomBuffer{
	int	m_iCap;
	int	m_iLen;
//	unsigned char m_auchBuf[];

	CustomBuffer()
	{
		m_iCap = 0;
		m_iLen = 0;
	}

	~CustomBuffer()
	{
		m_iCap = 0;
		m_iLen = 0;
	}

	unsigned char* BufBegin() const
	{
		return (unsigned char*)&m_iLen + sizeof(int);
	}

	static CustomBuffer* NewBuf(unsigned int uiBufSize)
	{
		CustomBuffer* p = (CustomBuffer*)calloc(1, sizeof(CustomBuffer) + uiBufSize);
		if(p == NULL)
			return(NULL);

		p->m_iCap = uiBufSize;
		p->m_iLen = 0;

		return(p);
	}
};

struct CustomBioData{
	CustomBuffer			m_stAddrBuf;
	struct sockaddr_storage	m_stClientAddr;
	int						m_iFd;
//	BIO_ADDR				m_stPeer; // set by bio
	int						m_iConnected; // set by bio
	int 					m_iPeekMode;
	std::deque<void*> 		m_stQueue;

	CustomBioData()
	{
		m_iFd = -1;
//		memset(&m_stPeer, 0, sizeof(m_stPeer));
		m_iConnected = 0;
		m_iPeekMode = 0;
	}

	~CustomBioData()
	{
		m_iFd = -1;
		m_iPeekMode = 0;

		if(!m_stQueue.empty()){
			for(std::deque<void*>::iterator it=m_stQueue.begin(); it != m_stQueue.end(); ){
				CustomBuffer* p = (CustomBuffer*)*it;
				m_stQueue.erase(it++);
				delete p;
			}
		}
	}
};

struct HashCustomBuffer
{
	inline size_t hash_unsigned_string(const char* pchKey, unsigned int uiKeySize) const
	{
	    unsigned int h = 0, g = 0;
	    const char *pchEnd = pchKey + uiKeySize;

	    //key hash
	    while (pchKey < pchEnd){
				h = (h << 4) + *pchKey++;
				if ((g = (h & 0xF0000000))){
				    h = h ^ (g >> 24);
				    h = h ^ g;
				}
	    }
	    
	    return size_t(h);
	}

	size_t operator()(const CustomBuffer* o) const
	{ 
		
		return hash_unsigned_string((const char*)o->BufBegin(), (unsigned int)o->m_iLen);
	}
};

struct CompareCustomBuffer{
	bool operator()(const CustomBuffer* a, const CustomBuffer* b) const
	{
		if(a->m_iLen != b->m_iLen)
			return(0);

		const int len = a->m_iLen;
		for(int i=0; i < len; i++){
			if(a->BufBegin()[i] != b->BufBegin()[i])
				return(0);
        }

		return(1);
	}
};  


void dump_hex(const unsigned char *buf, size_t len, const char *indent);
void dump_addr(struct sockaddr *sa, const char *indent);


int BIO_s_custom_write_ex(BIO *b, const char *data, size_t dlen, size_t *written);
int BIO_s_custom_write(BIO *b, const char *data, int dlen);
int BIO_s_custom_read_ex(BIO *b, char *data, size_t dlen, size_t *readbytes);
int BIO_s_custom_read(BIO *b, char *data, int dlen);
int BIO_s_custom_gets(BIO *b, char *data, int size);
int BIO_s_custom_puts(BIO *b, const char *data);
long BIO_s_custom_ctrl(BIO *b, int cmd, long num, void *ptr);
int BIO_s_custom_create(BIO *b);
int BIO_s_custom_destroy(BIO *b);
// long BIO_s_custom_callback_ctrl(BIO *, int, BIO_info_cb *);

BIO_METHOD *BIO_s_custom(void);
void BIO_s_custom_meth_free(void);

#endif
