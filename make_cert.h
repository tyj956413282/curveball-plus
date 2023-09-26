#ifndef _MAKE_CERT_H
#define _MAKE_CERT_H
#include "head.h"
#include <openssl/ec.h>
#include <openssl/x509.h>

// *key如果有值，则直接用该值
bool make_root_certificate(int type, const char* name, X509** cert, EC_KEY** key);

// *key如果有值，则直接用该值作为用户临时公私钥
bool make_user_certificate(int type, const char* name, X509* ca_cert, EC_KEY* ca_key, X509** cert, EC_KEY** key);

#define VALIDATE_INIT			0xFFFFFFFF
#define VALIDATE_UNKNOWN		0xFFFFFFFE
#define VALIDATE_SUCCESS		0x00000000

#endif