#ifndef CURVEBALL_H
#define CURVEBALL_H
#include <openssl/ec.h>
#include <openssl/x509.h>

bool curveball_keygen(const EC_POINT* P, const EC_GROUP* G, BIGNUM** d, EC_GROUP** newG);

bool curveball_explicit(X509* target, EC_KEY** user_key, X509 **user, STACK_OF(X509)** others);

int X509_get_Param_str_of_pubkey(const X509* x, const unsigned char** out);

#endif