#ifndef _VALIDATE_CERT_H
#define _VALIDATE_CERT_H
#include "head.h"
#include "my_ctl_cache.h"
#include <openssl/x509.h>

// FULLSIZE_CTL
// EXTENDEDSIZE_CTL

int validate_cert_like_win(MY_STORAGE_CTX* ctx, EVP_PKEY** out_key = NULL);
bool cmp_pubkey(EVP_PKEY* key1, EVP_PKEY* key2);
bool cmp_pubkey(EC_KEY* key1, EVP_PKEY* key2);
#endif
