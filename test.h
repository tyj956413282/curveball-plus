#ifndef _TEST_H
#define _TEST_H

#include <openssl/x509.h>
#include "ecqv.h"

bool test11(X509** c, EC_KEY** k);
bool test12(ECQV_CERT** c, EC_KEY** k);
bool test13(X509* ca, EC_KEY* ca_key, X509** c, EC_KEY** k);
bool test14(ECQV_CERT* ca, EC_KEY* ca_key, ECQV_CERT** c, EC_KEY** k);
int test_ecqv();

bool test31();
bool test32();
bool test33(int length = 5);
bool test35(int length = 5);

bool test41_curveball_explicit();

bool test51();


bool test6_generate_certs();
bool test6_read_file();

bool test71();


#endif