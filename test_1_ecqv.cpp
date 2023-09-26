#include <openssl/x509v3.h>
#include "ecqv.h"
#include "color.h"
#include "make_cert.h"

#define DEBUG


bool test11(X509 **c, EC_KEY **k) {
	X509* cert = NULL;
	EC_KEY* key = NULL;
	unsigned char* out;

	SET_CUSTUM(0x4e) printf("\nTest 1-1: Create a Root Explicit Certificate.\n"); SET_CLEAR

	if (make_root_certificate(TYPE_EXPLICIT, "root_explicit", &cert, &key)) {
		SET_CUSTUM(0x0a) printf("create success!\n"); SET_CLEAR
			ecqv_print_cert(stdout, "Test 1", cert);

		//printf("x509_check_ca result: %d\n", X509_check_ca(cert));

		if (c) *c = cert;
		if (k) *k = key;
		return true;
	}
	else {
		SET_CUSTUM(0x0c) printf("create failed!\n"); SET_CLEAR
		return false;
	}
}

bool test12(ECQV_CERT** c, EC_KEY** k) {
	ECQV_CERT* cert = NULL;
	EC_KEY* key = NULL;

	SET_CUSTUM(0x4b) printf("\nTest 1-2: Create a Root Implicit Certificate.\n"); SET_CLEAR

		if (make_root_certificate(TYPE_IMPLICIT, "root_implicit", &cert, &key)) {
			SET_CUSTUM(0x0a) printf("create success!\n"); SET_CLEAR
				ecqv_print_cert(stdout, "Test 2", cert);
			if (c) *c = cert;
			if (k) *k = key;
			return true;
		}
		else {
			SET_CUSTUM(0x0c) printf("create failed!\n"); SET_CLEAR
				return false;
		}
}

bool test13(X509 *ca, EC_KEY *ca_key, X509** c, EC_KEY** k) {
	X509* cert = NULL;
	EC_KEY* key = NULL;

	SET_CUSTUM(0x4e) printf("\nTest 1-3: Create an User Explicit Certificate.\n"); SET_CLEAR

		if (make_user_certificate(TYPE_EXPLICIT, "user_explicit", ca, ca_key, &cert, &key)) {
			SET_CUSTUM(0x0a) printf("create success!\n"); SET_CLEAR
				ecqv_print_cert(stdout, "Test 3", cert);
			if (c) *c = cert;
			if (k) *k = key;
			return true;
		}
		else {
			SET_CUSTUM(0x0c) printf("create failed!\n"); SET_CLEAR
				return false;
		}
}

bool test14(ECQV_CERT* ca, EC_KEY* ca_key, ECQV_CERT** c, EC_KEY** k) {
	X509* cert = NULL;
	EC_KEY* key = NULL;

	SET_CUSTUM(0x4e) printf("\nTest 1-4: Create an User Implicit Certificate.\n"); SET_CLEAR

		if (make_user_certificate(TYPE_IMPLICIT, "user_implicit", ca, ca_key, &cert, &key)) {
			SET_CUSTUM(0x0a) printf("create success!\n"); SET_CLEAR
				ecqv_print_cert(stdout, "Test 4", cert);
			if (c) *c = cert;
			if (k) *k = key;
			return true;
		}
		else {
			SET_CUSTUM(0x0c) printf("create failed!\n"); SET_CLEAR
				return false;
		}
}

int test_ecqv() {
	X509* root_exp_crt = NULL; EC_KEY* root_exp_key = NULL;
	X509* root_imp_crt = NULL; EC_KEY* root_imp_key = NULL;
	X509* user_exp_crt = NULL; EC_KEY* user_exp_key = NULL;
	X509* user_imp_crt = NULL; EC_KEY* user_imp_key = NULL;
	
	test11(&root_exp_crt, &root_exp_key);
	test12(&root_imp_crt, &root_imp_key);
	test13(root_exp_crt, root_exp_key, &user_exp_crt, &user_exp_key);
	test14(root_imp_crt, root_imp_key, &user_imp_crt, &user_imp_key);

	return 0;
}