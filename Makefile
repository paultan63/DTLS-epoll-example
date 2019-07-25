
OPENSSL_DIR=/usr/local/openssl
OPENSSL_INC=-I$(OPENSSL_DIR)/include
OPENSSL_LIB=-L$(OPENSSL_DIR)/lib -Wl,-rpath=$(OPENSSL_DIR)/lib -lssl -lcrypto
OPENSSL=$(OPENSSL_DIR)/bin/openssl

CPPFLAGS=-g -O3 $(OPENSSL_INC)
LDFLAGS=$(OPENSSL_LIB)

.PHONY: all clean certs distclean

all: dtls_server dtls_client certs

dtls_server: dtls_server.cpp my_cbio.cpp
	g++ -g $(CPPFLAGS) -o $@ $^ $(LDFLAGS)

dtls_client: dtls_client.cpp my_cbio.cpp
	g++ -g $(CPPFLAGS) -o $@ $^ $(LDFLAGS) -lreadline


certs: root-key.pem root-ca.pem server-key.pem server-csr.pem server-cert.pem client-key.pem client-csr.pem client-cert.pem

clean: 
	rm -f dtls_server dtls_client

distclean: clean
	rm -f *.pem *.srl

%-key.pem:
	$(OPENSSL) ecparam -name secp384r1 -genkey -noout -out $@

%-cert.pem: %-csr.pem root-ca.pem root-key.pem
	$(OPENSSL) x509 -req -in $< -out $@ -CA root-ca.pem -CAkey root-key.pem -days 7

%-csr.pem: %-key.pem
	$(OPENSSL) req -new -key $< -out $@ -subj /CN=test_$*/

root-ca.pem: root-key.pem
	$(OPENSSL) req -new -x509 -nodes -days 7 -key $< -out $@ -subj /CN=test_rootCA/
	test -f root-ca.srl || echo 00 > root-ca.srl

