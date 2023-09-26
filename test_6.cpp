#include "head.h"
#include "test.h"
#include <openssl/pkcs7.h>
#include <openssl/pem.h>

#include "ecqv.h"
#include "make_cert.h"

const char* root_file_name = "root.pkcs7";
const char* root_key_file_name = "root_key.out";

#define ROOT_NUM 5
#define INT_NUM 30

bool test6_generate_certs() {
	
	PKCS7* root_pkcs = PKCS7_new();
	PKCS7* int_ca_pkcs = PKCS7_new();
	
	X509* root[ROOT_NUM] = { NULL }; EC_KEY* root_key[ROOT_NUM] = { NULL }; EVP_PKEY* root_pkey[ROOT_NUM] = { NULL };
	X509* int_ca[30] = { NULL }; EC_KEY* int_ca_key[30] = { NULL }; EVP_PKEY* int_ca_pkey[30] = { NULL };

	FILE* root_file = NULL, * root_key_file = NULL;
	root_file = fopen(root_file_name, "w");
	root_key_file = fopen(root_key_file_name, "w");
	if (!root_file || !root_key_file) {
		printf("file create failed!\n");
		return false;
	}
	
	char name[10] = "";
	for (int i = 0; i < ROOT_NUM; i++) {
		sprintf(name, "root-%d", i);
		if (!make_root_certificate(TYPE_IMPLICIT, name, &root[i], &root_key[i])) {
			printf("Generate Cert-%d failed!\n", i);
		}
		root_pkey[i] = EVP_PKEY_new();
		EVP_PKEY_set1_EC_KEY(root_pkey[i], root_key[i]);
	}
	for (int i = 0; i < ROOT_NUM; i++) {
		unsigned char* cert_out = NULL; int cert_out_len = 0;
		unsigned char* key_out = NULL; int key_out_len = 0;
		cert_out_len = i2d_X509(root[i], &cert_out);
		key_out_len = i2d_PrivateKey(root_pkey[i], &key_out);
		if (cert_out_len <= 0 || key_out_len <= 0) {
			printf("i2d error!\n");
			continue;
		}
		if (!PEM_write(root_file, "X509 ECQV CERTIFICATE", NULL, cert_out, cert_out_len)) {
			printf("PEM write cert failed!\n");
			continue;
		}
		if (!PEM_write(root_key_file, "ECC private", NULL, key_out, key_out_len)) {
			printf("PEM write key failed!\n");
			continue;
		}
	}
	fclose(root_file);
	fclose(root_key_file);
	return true;
}

bool test6_read_file() {
	PKCS7* root_in = NULL;
	X509* root[ROOT_NUM] = { NULL };

	FILE* root_file = NULL, * root_key_file = NULL;
	root_file = fopen(root_file_name, "r");
	root_key_file = fopen(root_key_file_name, "r");
	if (!root_file || !root_key_file) {
		printf("file create failed!\n");
		return false;
	}

	char* name = NULL;
	unsigned char* cert_in = NULL; long cert_in_len = 0;
	unsigned char* key_in = NULL; long key_in_len = 0;
	const unsigned char* c_cert_in = cert_in, *c_key_in = key_in;
	int cnt = 0;
	cert_in = (unsigned char*)OPENSSL_malloc(2048);

	char buf[500];
	fgets(buf, 50, root_file);
	puts(buf);
	while (PEM_read(root_file, NULL, NULL, &cert_in, &cert_in_len)) {
		root[cnt] = d2i_X509(NULL, &c_cert_in, cert_in_len);
		if (root[cnt] == NULL) {
			printf("d2i error!\n");
		}
		cnt += 1;
	}

	for (int i = 0; i < cnt; i++) {
		ecqv_print_cert(stdout, "test", root[i]);
	}
	
	
	fclose(root_file);
	return true;
}