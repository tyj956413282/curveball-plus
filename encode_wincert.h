#ifndef _ENCODE_WINCERT_H
#define _ENCODE_WINCERT_H

#include <openssl/x509.h>

#define ADD_MY		0
#define ADD_CA		1
#define ADD_ROOT	2

bool addWinLocalCert(X509_STORE* store, int add_whom);

#endif