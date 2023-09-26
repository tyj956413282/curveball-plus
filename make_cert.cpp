#include "ecqv.h"
#include "make_cert.h"

static int global_serial = 1;
extern BN_CTX* bn_ctx;

bool make_root_certificate(int type, const char* name, X509** cert, EC_KEY** key) {
	EC_KEY* key_seed = NULL;
	ECQV_CERT_INFO info;
	X509* c = NULL;
	BIGNUM* r = NULL;
	const EC_POINT* K_seed = NULL;
	const BIGNUM* k_seed = NULL;
	EVP_PKEY* vk = NULL;

	const EC_GROUP* group = NULL;//  = EC_GROUP_new_by_curve_name(NID_secp256k1);
	EC_KEY* only_group = EC_KEY_new(); //仅包含group
	if (!only_group) {
		goto ERR;
	}

	if (key && *key) {
		key_seed = *key;
	}

	if (key_seed) {
		group = EC_KEY_get0_group(key_seed);
	}
	else {
		if (!(group = EC_GROUP_new_by_curve_name(NID_secp256k1))) {
			goto ERR;
		}
	}

	EC_KEY_set_group(only_group, group);

	

	// set requst info
	info.type = type;
	info.subject_name = name;
	info.issuer = NULL;
	info.serial = global_serial++;
	info.notBefore = time(NULL);
	info.days = 365;
	info.key_usage = (1 << 5); // CertSign

	// generate certificate
	if (type == TYPE_EXPLICIT) {
		if (!key_seed) {
			if (!ecqv_cert_request(group, &key_seed)) {
				printf("request error!\n");
				return false;
			}
		}
		K_seed = EC_KEY_get0_public_key(key_seed);
		k_seed = EC_KEY_get0_private_key(key_seed);

#ifdef MAKE_CERT_DEBUG
		ecqv_print_key(stdout, "P", "d", key_seed, bn_ctx);
#endif 

		if (!make_cert(&info, key_seed, key_seed, &c)) {
			printf("make_exp_cert error!\n");
			goto ERR;
		}
	}
	else { // TYPE_IMPLICIT

		if (!ecqv_cert_generate(key_seed, only_group, &info, &c, &r)) {
			printf("make_imp_cert error!\n");
			goto ERR;
		}
		if (!ecqv_cert_reception(c, NULL, r, k_seed, &key_seed)) {
			printf("ecqv_key_reception error!\n");
			goto ERR;
		}

#ifdef MAKE_CERT_DEBUG2
		ecqv_print_key(stdout, "P", "d", key_seed, bn_ctx);
#endif 

	}

	if (!EC_KEY_check_key(key_seed)) {
		printf("keycheck is failed!\n");
		// not return, continue.
	}
	else {
		printf("keycheck is success!\n");
	}
	
	if (type == TYPE_EXPLICIT) {
		if (!(vk = EVP_PKEY_new()) || !EVP_PKEY_set1_EC_KEY(vk, key_seed)) {
			goto ERR;
		}
		if (!X509_verify(c, vk)) {
			printf("cert self-signed signature verification failed!\n");
		}
		else {
			printf("cert self-signed signature verification success!\n");
		}
	}

	// set return value 
	if (cert) *cert = c;
	if (key) *key = key_seed;

	return true;
ERR:
	if ((!key || !*key) && key_seed) EC_KEY_free(key_seed);
	return false;
}

bool make_user_certificate(int type, const char* name, X509* ca_cert, EC_KEY* ca_key, X509** cert, EC_KEY** key) {
	EC_KEY* key_seed = NULL;
	ECQV_CERT_INFO info;
	X509* c = NULL;
	BIGNUM* r = NULL;
	const EC_POINT* K_seed = NULL;
	const BIGNUM* k_seed = NULL;
	X509_NAME* ca_name = NULL;
	EVP_PKEY* vk = NULL;

	EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if (!group || !ca_key || !ca_cert) {
		goto ERR;
	}

	if (!(ca_name = X509_get_subject_name(ca_cert))) {
		goto ERR;
	}

	if (key && *key) {
		key_seed = *key;
	}

	// set requst info
	info.type = type;
	info.subject_name = name;
	info.issuer = ca_name;
	info.serial = global_serial++;
	info.notBefore = time(NULL);
	info.days = 365;
	info.key_usage = (1 << 5); // CertSign

	if (!ecqv_cert_request(group, &key_seed)) {
		printf("request error!\n");
		return false;
	}
	K_seed = EC_KEY_get0_public_key(key_seed);
	k_seed = EC_KEY_get0_private_key(key_seed);

#ifdef MAKE_CERT_DEBUG2
	ecqv_print_key(stdout, "Ku", "ku", key_seed, bn_ctx);
#endif 

	// generate certificate
	if (type == TYPE_EXPLICIT) {
		// 理应抹掉User临时私钥值，这里未处理
		if (!make_cert(&info, key_seed, ca_key, &c)) {
			printf("make_exp_cert error!\n");
			goto ERR;
		}
	}
	else { // TYPE_IMPLICIT

		if (!ecqv_cert_generate(key_seed, ca_key, &info, &c, &r)) {
			printf("make_imp_cert error!\n");
			goto ERR;
		}
		// 理应抹掉CA公钥，这里未处理
		if (!ecqv_cert_reception(c, ca_key, r, k_seed, &key_seed)) {
			printf("ecqv_key_reception error!\n");
			goto ERR;
		}

#ifdef MAKE_CERT_DEBUG2
		ecqv_print_key(stdout, "P", "d", key_seed, bn_ctx);
#endif 

	}

	if (!EC_KEY_check_key(key_seed)) {
		printf("keycheck is failed!\n");
		// not return, continue.
	}
	else {
		printf("keycheck is success!\n");
	}
	
	if (type == TYPE_EXPLICIT) {
		if (!(vk = EVP_PKEY_new()) || !EVP_PKEY_set1_EC_KEY(vk, ca_key)) {
			goto ERR;
		}
		if (!X509_verify(c, vk)) {
			printf("cert signature verification failed!\n");
		}
		else {
			printf("cert signature verification success!\n");
		}
	}

	// set return value 
	if (cert) *cert = c;
	if (key) *key = key_seed;
	return true;

ERR:
	
	return false;
}

int simple_validate(X509* end_cert, X509* other_cert) {
	int state = VALIDATE_INIT;

	X509_STORE* store = NULL;
	X509_STORE_CTX* csc = NULL;
	
	if (!(csc = X509_STORE_CTX_new())) {
		state = VALIDATE_UNKNOWN;
		goto ERR;
	}
	
	//X509_STORE_CTX_init(csc, ctx, );

ERR:

	return state;
}