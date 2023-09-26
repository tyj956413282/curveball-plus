#include "encode_wincert.h"
#include "color.h"

int test_encode_wincert() {
	X509_STORE* store = NULL;

	SET_CUSTUM(0x4e) printf("\nTest : Read [My] Windows Cert Storage.\n"); SET_CLEAR
	
	if (!(store = X509_STORE_new())) {
		goto ERR;
	}

	if (!addWinLocalCert(store, ADD_MY)) {
		goto ERR;
	}

	// X509_STORE_get1_all_certs() // OpenSSL 3.0 Support!

	SET_CUSTUM(0x0a) printf("test success!\n"); SET_CLEAR
	return 0;
ERR:
	SET_CUSTUM(0x0c) printf("test failed!\n"); SET_CLEAR
	if (store) X509_STORE_free(store);
	return 1;
}