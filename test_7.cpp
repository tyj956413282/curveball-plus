#include "head.h"
#include "test.h"

#include "ecqv.h"
#include "make_cert.h"
#include "my_ctl_cache.h"

#define ROOT_NUM 5
#define CA_NUM 30

#define TEST_CHAIN_LENGTH 3
#define RECEIVE_LENGTH 2

bool test71() {
	X509* root[ROOT_NUM]; EC_KEY* root_key[ROOT_NUM] = { NULL }; EVP_PKEY* root_pkey[ROOT_NUM] = { NULL };
	X509* ca[CA_NUM]; EC_KEY* ca_key[CA_NUM] = { NULL }; EVP_PKEY* ca_pkey[CA_NUM] = { NULL };
	X509* test[CA_NUM]; EC_KEY* test_key[CA_NUM] = { NULL }; EVP_PKEY* test_pkey[CA_NUM] = { NULL };

	MY_STORAGE* store = NULL;
	MY_STORAGE_CTX* ctx = NULL;
	STACK_OF(X509)* uchain = NULL;

	if (!(store = MY_STORAGE_new()) ||
		!(ctx = MY_STORAGE_CTX_new()) ||
		!(uchain = sk_X509_new_null())
		) {
		printf("NEW error!\n");
		return false;
	}

	char name[10] = "";
	for (int i = 0; i < ROOT_NUM; i++) {
		sprintf(name, "root-%d", i);
		if (!make_root_certificate(TYPE_IMPLICIT, name, &root[i], &root_key[i])) {
			printf("Generate ROOT Cert-%d failed!\n", i);
			return false;
		}
		root_pkey[i] = EVP_PKEY_new();
		EVP_PKEY_set1_EC_KEY(root_pkey[i], root_key[i]);

		// 填充到信任區
#ifdef MINIMUM_FINAL_KEY
		if (!(MY_STORAGE_add_key(store, root_key[i], NULL))) {
#else
		if (!(MY_STORAGE_add_cert(store, root[i]))) {
#endif
			printf("MY_STORAGE_add_cert error\n");
			return false;
		}

	}

	// 使用root[0]签发若干CA证书
	for (int i = 0; i < CA_NUM; i++) {
		sprintf(name, "ca-%d", i);
		if (!make_user_certificate(TYPE_IMPLICIT, name, root[0], root_key[0], &ca[i], &ca_key[i])) {
			printf("Generate CA Cert-%d failed!\n", i);
			return false;
		}
		ca_pkey[i] = EVP_PKEY_new();
		EVP_PKEY_set1_EC_KEY(ca_pkey[i], ca_key[i]);

		// 填充到信任區
#ifdef MINIMUM_FINAL_KEY
		if (!(MY_STORAGE_add_key(store, ca_key[i], root_pkey[0]))) {
#else
		if (!(MY_STORAGE_add_cert(store, ca[i]))) {
#endif
			printf("MY_STORAGE_add_cert error\n");
			return false;
		}
	}

	test[0] = root[0]; test_key[0] = root_key[0]; test_pkey[0] = root_pkey[0];
	test[1] = ca[CA_NUM - 1]; test_key[1] = ca_key[CA_NUM - 1]; test_pkey[1] = ca_pkey[CA_NUM - 1];
	// 填充测试区
	for (int i = 2; i < TEST_CHAIN_LENGTH; i++) {
		sprintf(name, "test-%d", i);
		if (!make_user_certificate(TYPE_IMPLICIT, name, test[i - 1], test_key[i - 1], &test[i], &test_key[i - 1])) {
			printf("Generate test Cert-%d failed!\n", i);
			return false;
		}
	}
	for (int i = TEST_CHAIN_LENGTH - 1, j = 0; j < RECEIVE_LENGTH; i--, j++) {
		if (!sk_X509_push(uchain, test[i])) {
			printf("sk_push %d failed!\n", j);
		}
	}
	


}