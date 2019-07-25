# dtls_epoll_example

* A DTLS server/client example with openssl-1.1.0 or above
* Server support multi-client
* A custom BIO with STL hash_map and deque
* Tested on CentOS 7.6

# Install
* yum install -y readline-devel
* Modify Makefile if needed
* make all

# Usage:
* ./dtls_server 127.0.0.1:9000
* ./dtls_client 127.0.0.1:9000
