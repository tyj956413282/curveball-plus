#include "test.h"
#include "validate_cert.h"
#include "make_cert.h"
#include "encode_wincert.h"
#include "my_ctl_cache.h"
#include "color.h"

bool test31() {
	SET_CUSTUM(0x4e) printf("\nTest 3-1: Validate an explicit certificate with a 2-size chain.\n"); SET_CLEAR
	X509* root_exp_crt = NULL; EC_KEY* root_exp_key = NULL;
	X509* user_exp_crt = NULL; EC_KEY* user_exp_key = NULL;
	MY_STORAGE* store = NULL;
	MY_STORAGE_CTX* ctx = NULL;
	STACK_OF(X509)* uchain = NULL;
	int ret = 0;

	if (!make_root_certificate(TYPE_EXPLICIT, "root_explicit", &root_exp_crt, &root_exp_key)) {
		goto ERR;
	}
	ecqv_print_cert(stdout, "Test 3-1", root_exp_crt);
	if (!make_user_certificate(TYPE_EXPLICIT, "user_explicit", root_exp_crt, root_exp_key, &user_exp_crt, &user_exp_key)) {
		goto ERR;
	}
	ecqv_print_cert(stdout, "Test 3-1", user_exp_crt);

	// 填充信任区
	if (!(store = MY_STORAGE_new()) ||
		!(ctx = MY_STORAGE_CTX_new()) ||
		!(uchain = sk_X509_new_null())
	) {
		goto ERR;
	}
#ifdef MINIMUM_FINAL_KEY
	if (!(MY_STORAGE_add_key(store, root_exp_key, NULL))) {
#else
	if (!(MY_STORAGE_add_cert(store, root_exp_crt))) {
#endif
		goto ERR;
	}

	// 填充非信任区
	if (!sk_X509_push(uchain, root_exp_crt)) {
		goto ERR;
	}

	// 创建CTX结构
	if (!MY_STORAGE_CTX_init(ctx, store, user_exp_crt, uchain)) {
		goto ERR;
	}

	// 测试验证
	if (!validate_cert_like_win(ctx)) {
		SET_CUSTUM(0x0c) printf("validate failed!\n"); SET_CLEAR
		goto ERR;
	}
	else {
		SET_CUSTUM(0x0a) printf("validate success!\n"); SET_CLEAR
	}

#ifndef MINIMUM_CACHE

	// 初始化ctx
	if (!X509_STORE_CTX_init(ctx->normal, store, user_exp_crt, NULL)) {
		goto ERR;
	}
	ret = X509_verify_cert(ctx->normal);
	if (ret == 1) {
		printf("OpenSSL Result: true\n");
	}
	if (ret <= 0) {
		printf("OpenSSL Result Err Msg: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx->normal)));
	}

#endif
	
	if (store) MY_STORAGE_free(store);
	if (ctx) MY_STORAGE_CTX_free(ctx);
	if (uchain) sk_X509_free(uchain);
	return true;
ERR:
	if (store) MY_STORAGE_free(store);
	if (ctx) MY_STORAGE_CTX_free(ctx);
	if (uchain) sk_X509_free(uchain);
	return false;
}

bool test32() {
	SET_CUSTUM(0x4e) printf("\nTest 3-2: Validate an explicit certificate with a 2-size chain.\n"); SET_CLEAR;
	X509* root_exp_crt = NULL; EC_KEY* root_exp_key = NULL; EVP_PKEY* root_exp_pkey = NULL;
	X509* user_exp_crt = NULL; EC_KEY* user_exp_key = NULL; EVP_PKEY* user_exp_pkey = NULL;
	MY_STORAGE* store = NULL;
	MY_STORAGE_CTX* ctx = NULL;
	STACK_OF(X509)* uchain = NULL;
	int ret = 0;

	if (!make_root_certificate(TYPE_EXPLICIT, "root_explicit", &root_exp_crt, &root_exp_key)) {
		goto ERR;
	}
	ecqv_print_cert(stdout, "Test 3-2", root_exp_crt);
	EVP_PKEY_set1_EC_KEY(root_exp_pkey, root_exp_key);
	if (!make_user_certificate(TYPE_EXPLICIT, "user_explicit", root_exp_crt, root_exp_key, &user_exp_crt, &user_exp_key)) {
		goto ERR;
	}
	ecqv_print_cert(stdout, "Test 3-2", user_exp_crt);
	EVP_PKEY_set1_EC_KEY(user_exp_pkey, user_exp_key);
	// 填充信任区
	if (!(store = MY_STORAGE_new()) ||
		!(ctx = MY_STORAGE_CTX_new()) ||
		!(uchain = sk_X509_new_null())
		) {
		goto ERR;
	}
#ifdef MINIMUM_FINAL_KEY
	if (!(MY_STORAGE_add_key(store, root_exp_key, NULL))) {
#else
	if (!(MY_STORAGE_add_cert(store, root_exp_crt))) {
#endif
	
		goto ERR;
	}

	// 填充非信任区
	if (!sk_X509_push(uchain, root_exp_crt)) {
		goto ERR;
	}

	// 创建CTX结构
	if (!MY_STORAGE_CTX_init(ctx, store, user_exp_crt, NULL)) {
		goto ERR;
	}

	// 测试验证
	if (!validate_cert_like_win(ctx)) {
		SET_CUSTUM(0x0c) printf("validate failed!\n"); SET_CLEAR
			goto ERR;
	}
	else {
		SET_CUSTUM(0x0a) printf("validate success!\n"); SET_CLEAR
	}

#ifndef MINIMUM_CACHE
	// 初始化ctx
	if (!X509_STORE_CTX_init(ctx->normal, store, user_exp_crt, NULL)) {
		goto ERR;
	}
	ret = X509_verify_cert(ctx->normal);
	if (ret == 1) {
		printf("OpenSSL Result: true\n");
	}
	if (ret <= 0) {
		printf("OpenSSL Result Err Msg: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx->normal)));
	}
#endif

	if (store) MY_STORAGE_free(store);
	if (ctx) MY_STORAGE_CTX_free(ctx);
	if (uchain) sk_X509_free(uchain);
	return true;
ERR:
	if (store) MY_STORAGE_free(store);
	if (ctx) MY_STORAGE_CTX_free(ctx);
	if (uchain) sk_X509_free(uchain);
	return false;
}

bool test33(int length) {
	SET_CUSTUM(0x4e) printf("\nTest 3-3: Validate an explicit certificate with a 5-size chain.\n"); SET_CLEAR;
	X509* cert[5] = { NULL };
	EC_KEY* key[5] = { NULL };
	EVP_PKEY* pkey[5] = { NULL };
	MY_STORAGE* store = NULL;
	MY_STORAGE_CTX* ctx = NULL;
	STACK_OF(X509)* uchain = NULL;
	bool result_win[6][7] = { false }; // [信任区][非信任区]
#ifndef MINIMUM_CACHE
	bool result_openssl[6][7] = { false }; // [信任区][非信任区]
#endif
	const char* cert_name[7] = { "0", "1", "2", "3", "4", "5", "6"};
	int ret = 0;

	if (length < 0 || length > 7) return false;
	// 初始化
	if (!(store = MY_STORAGE_new()) ||
		!(ctx = MY_STORAGE_CTX_new()) ||
		!(uchain = sk_X509_new_null())
		) {
		goto ERR;
	}
	EVP_PKEY_set1_EC_KEY(pkey[0], key[0]);
	// 签发5个证书
	if (!make_root_certificate(TYPE_EXPLICIT, cert_name[0], 
		&cert[0], &key[0]
	)) {
		goto ERR;
	}
	for (int i = 1; i < length; i++) {
		if (!make_user_certificate(TYPE_EXPLICIT, cert_name[i],
			cert[i - 1], key[i - 1],
			&cert[i], &key[i]
		)) {
			goto ERR;
		}
		EVP_PKEY_set1_EC_KEY(pkey[i], key[i]);
	}

	// 收集结果
	for (int i = 0; i < length - 1; i++) {
		// 填充信任区
#ifdef MINIMUM_FINAL_KEY
		if (!(MY_STORAGE_add_key(store, key[i], i == 0 ? NULL : pkey[i - 1]))) {
#else
		if (!(MY_STORAGE_add_cert(store, cert[i]))) {
#endif
			goto PRINT;
		}
		sk_X509_zero(uchain);
		for (int j = length - 1; j >= 0; j--) {
			SET_CUSTUM(0x5e) printf("\nCase [%d, %d]\n", i, j); SET_CLEAR;
			// 填充非信任区
			if (!sk_X509_push(uchain, cert[j])) {
				goto PRINT;
			}
			// 初始化ctx
			if (!MY_STORAGE_CTX_init(ctx, store, cert[length - 1], uchain)) {
				goto PRINT;
			}
			// 验证证书

			//用clock()来计时  毫秒  
			clock_t  clockBegin, clockEnd;
			clockBegin = clock();
			for (int _ = 0; _ < 99; _++) validate_cert_like_win(ctx);
			if (!validate_cert_like_win(ctx)) {
				clockEnd = clock();
				printf("time = %d ms\n", clockEnd - clockBegin);
				SET_CUSTUM(0x0c) printf("validate failed!\n"); SET_CLEAR;
			}
			else {
				clockEnd = clock();
				printf("time = %d ms\n", clockEnd - clockBegin);
				SET_CUSTUM(0x0a) printf("validate success!\n"); SET_CLEAR;
				result_win[i][j] = true;
			}
#ifndef MINIMUM_CACHE
			// 初始化ctx
			if (!X509_STORE_CTX_init(ctx->normal, store, cert[length - 1], uchain)) {
				goto PRINT;
			}
			clockBegin = clock();
			for (int _ = 0; _ < 99; _++) X509_verify_cert(ctx->normal);
			ret = X509_verify_cert(ctx->normal);
			clockEnd = clock();
			printf("openss time = %d ms\n", clockEnd - clockBegin);
			if (ret == 1) {
				result_openssl[i][j] = true;
				printf("OpenSSL Result: true\n");
			}
			if (ret <= 0) {
				printf("OpenSSL Result Err Msg: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx->normal)));
			}
#endif
		}
	}

PRINT:
	printf("\nWindows-like Result (mode = %s): \n", CACHE_STR);
	printf("scene");
	for (int j = 0; j < length; j++) {
		printf("\tfile%d", j);
	}
	printf("\n");
	for (int i = 0; i < length - 1; i++) {
		printf("S(%d)", i);
		for (int j = 0; j < length; j++) {
			printf("\t  %c", result_win[i][j] == true ? 'T' : 'F');
		}
		printf("\n");
	}
#ifndef MINIMUM_CACHE
	printf("\nOpenSSL's Result: \n");
	printf("scene");
	for (int j = 0; j < length; j++) {
		printf("\tfile%d", j);
	}
	printf("\n");
	for (int i = 0; i < length - 1; i++) {
		printf("S(%d)", i);
		for (int j = 0; j < length; j++) {
			printf("\t  %c", result_openssl[i][j] == true ? 'T' : 'F');
		}
		printf("\n");
	}
#endif
	// clear

	for (int i = 0; i < length; i++) {
		if (cert[i]) {
			X509_free(cert[i]);
			cert[i] = NULL;
		}
		if (key[i]) {
			EC_KEY_free(key[i]);
			key[i] = NULL;
		}
		if (pkey[i]) {
			EVP_PKEY_free(pkey[i]);
			pkey[i] = NULL;
		}
	}
	if (store) MY_STORAGE_free(store);
	if (ctx) MY_STORAGE_CTX_free(ctx);
	if (uchain) sk_X509_free(uchain);
	return true;
ERR:
	for (int i = 0; i < length; i++) {
		if (cert[i]) {
			X509_free(cert[i]);
			cert[i] = NULL;
		}
		if (key[i]) {
			EC_KEY_free(key[i]);
			key[i] = NULL;
		}
		if (pkey[i]) {
			EVP_PKEY_free(pkey[i]);
			pkey[i] = NULL;
		}
	}
	if (store) MY_STORAGE_free(store);
	if (ctx) MY_STORAGE_CTX_free(ctx);
	if (uchain) sk_X509_free(uchain);
	return false;
}

bool test34() {
	SET_CUSTUM(0x4e) printf("\nTest 3-4: Validate an explicit certificate with a 2-size chain at MINI_CACHE.\n"); SET_CLEAR
		X509* root_exp_crt = NULL; EC_KEY* root_exp_key = NULL;
	X509* user_exp_crt = NULL; EC_KEY* user_exp_key = NULL;
	MY_STORAGE* store = NULL;
	MY_STORAGE_CTX* ctx = NULL;
	STACK_OF(X509)* uchain = NULL;
	int ret = 0;

	if (!make_root_certificate(TYPE_EXPLICIT, "root_explicit", &root_exp_crt, &root_exp_key)) {
		goto ERR;
	}
	ecqv_print_cert(stdout, "Test 3-4", root_exp_crt);
	if (!make_user_certificate(TYPE_EXPLICIT, "user_explicit", root_exp_crt, root_exp_key, &user_exp_crt, &user_exp_key)) {
		goto ERR;
	}
	ecqv_print_cert(stdout, "Test 3-4", user_exp_crt);

	// 填充信任区
	if (!(store = MY_STORAGE_new()) ||
		!(ctx = MY_STORAGE_CTX_new()) ||
		!(uchain = sk_X509_new_null())
		) {
		goto ERR;
	}

#ifdef MINIMUM_FINAL_KEY
	if (!(MY_STORAGE_add_key(store, root_exp_key, NULL))) {
#else
	if (!(MY_STORAGE_add_cert(store, root_exp_crt))) {
#endif
		goto ERR;
	}

	// 填充非信任区
	if (!sk_X509_push(uchain, root_exp_crt)) {
		goto ERR;
	}

	// 创建CTX结构
	if (!MY_STORAGE_CTX_init(ctx, store, user_exp_crt, uchain)) {
		goto ERR;
	}

	// 测试验证
	if (!validate_cert_like_win(ctx)) {
		SET_CUSTUM(0x0c) printf("validate failed!\n"); SET_CLEAR
			goto ERR;
	}
	else {
		SET_CUSTUM(0x0a) printf("validate success!\n"); SET_CLEAR
	}

#ifndef MINIMUM_CACHE
	// 初始化ctx
	if (!X509_STORE_CTX_init(ctx->normal, store, user_exp_crt, NULL)) {
		goto ERR;
	}
	ret = X509_verify_cert(ctx->normal);
	if (ret == 1) {
		printf("OpenSSL Result: true\n");
	}
	if (ret <= 0) {
		printf("OpenSSL Result Err Msg: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx->normal)));
	}
#endif

	if (store) MY_STORAGE_free(store);
	if (ctx) MY_STORAGE_CTX_free(ctx);
	if (uchain) sk_X509_free(uchain);
	return true;
ERR:
	if (store) MY_STORAGE_free(store);
	if (ctx) MY_STORAGE_CTX_free(ctx);
	if (uchain) sk_X509_free(uchain);
	return false;
}

bool test35(int length) {
	SET_CUSTUM(0x4e) printf("\nTest 3-5: Validate an explicit certificate with a 5-size pure-implicit chain.\n"); SET_CLEAR;
	X509* cert[7] = { NULL };
	EC_KEY* key[7] = { NULL };
	EVP_PKEY* pkey[7] = { NULL };
	MY_STORAGE* store = NULL;
	MY_STORAGE_CTX* ctx = NULL;
	STACK_OF(X509)* uchain = NULL;
	bool result_win[6][7] = { false }; // [信任区][非信任区]
	EVP_PKEY* vk = NULL;
#ifndef MINIMUM_CACHE
	bool result_openssl[6][7] = { false }; // [信任区][非信任区]
#endif
	const char* cert_name[7] = { "0", "1", "2", "3", "4", "5", "6" };
	int ret = 0;

	if (length < 0 || length > 7) return false;
	// 初始化
	if (!(store = MY_STORAGE_new()) ||
		!(ctx = MY_STORAGE_CTX_new()) ||
		!(uchain = sk_X509_new_null())
		) {
		goto ERR;
	}

	// 签发5个证书
	pkey[0] = EVP_PKEY_new();
	if (!make_root_certificate(TYPE_IMPLICIT, cert_name[0],
		&cert[0], &key[0]
	)) {
		goto ERR;
	}
#ifdef TEST_PRINTKEY
	ecqv_print_key(stdout, "P", "d", key[0], NULL);
#endif
	EVP_PKEY_set1_EC_KEY(pkey[0], key[0]);
	for (int i = 1; i < length; i++) {
		pkey[i] = EVP_PKEY_new();
		if (!make_user_certificate(TYPE_IMPLICIT, cert_name[i],
			cert[i - 1], key[i - 1],
			&cert[i], &key[i]
		)) {
			goto ERR;
		}
#ifdef TEST_PRINTKEY
		ecqv_print_key(stdout, "P", "d", key[i], NULL);
#endif
		EVP_PKEY_set1_EC_KEY(pkey[i], key[i]);
	}

	// 收集结果
	for (int i = 0; i < length - 1; i++) {
		// 填充信任区
#ifdef MINIMUM_FINAL_KEY
		if (!(MY_STORAGE_add_key(store, key[i], i == 0 ? NULL : pkey[i - 1]))) {
#else
		if (!(MY_STORAGE_add_cert(store, cert[i], i == 0 ? NULL : pkey[i]))) {
#endif
			goto PRINT;
		}
		sk_X509_zero(uchain);
		for (int j = length - 1; j >= 0; j--) {
			Sleep(500);
			SET_CUSTUM(0x5e) printf("\nCase [%d, %d]\n", i, j); SET_CLEAR;
			// 填充非信任区
			if (!sk_X509_push(uchain, cert[j])) {
				goto PRINT;
			}
			// 初始化ctx
			if (!MY_STORAGE_CTX_init(ctx, store, cert[length - 1], uchain)) {
				goto PRINT;
			}
			// 验证证书
			//用clock()来计时  毫秒  
			clock_t  clockBegin, clockEnd;
			clockBegin = clock();
			for (int _ = 0; _ < 99; _++) validate_cert_like_win(ctx, &vk);
			if (!validate_cert_like_win(ctx, &vk)) {
				clockEnd = clock();
				printf("time = %d ms\n", clockEnd - clockBegin);
				SET_CUSTUM(0x0c) printf("validate failed!\n"); SET_CLEAR;
			}
			else {
				clockEnd = clock();
				printf("time = %d ms\n", clockEnd - clockBegin);
#ifdef TEST3_DEBUG
				ecqv_print_pkey(stdout, "VK", "none", vk, NULL);
#endif
				ret = cmp_pubkey(key[length - 1], vk);
				SET_CUSTUM(0x0a) printf("validate success! cmp result = %s\n", ret == true ? "true" : "false"); SET_CLEAR;
				result_win[i][j] = ret;
			}
			if (vk) {
				EVP_PKEY_free(vk); vk = NULL;
			}
		}
	}

PRINT:
	printf("\nWindows-like Result (mode = %s): \n", CACHE_STR);
	printf("scene");
	for (int j = 0; j < length; j++) {
		printf("\tfile%d", j);
	}
	printf("\n");
	for (int i = 0; i < length - 1; i++) {
		printf("S(%d)", i);
		for (int j = 0; j < length; j++) {
			printf("\t  %c", result_win[i][j] == true ? 'T' : 'F');
		}
		printf("\n");
	}
	// clear

	for (int i = 0; i < length; i++) {
		if (cert[i]) {
			X509_free(cert[i]);
			cert[i] = NULL;
		}
		if (key[i]) {
			EC_KEY_free(key[i]);
			key[i] = NULL;
		}
		if (pkey[i]) {
			EVP_PKEY_free(pkey[i]);
			pkey[i] = NULL;
		}
	}
	if (store) MY_STORAGE_free(store);
	if (ctx) MY_STORAGE_CTX_free(ctx);
	if (uchain) sk_X509_free(uchain);
	return true;
ERR:
	for (int i = 0; i < length; i++) {
		if (cert[i]) {
			X509_free(cert[i]);
			cert[i] = NULL;
		}
		if (key[i]) {
			EC_KEY_free(key[i]);
			key[i] = NULL;
		}
		if (pkey[i]) {
			EVP_PKEY_free(pkey[i]);
			pkey[i] = NULL;
		}
	}
	if (store) MY_STORAGE_free(store);
	if (ctx) MY_STORAGE_CTX_free(ctx);
	if (uchain) sk_X509_free(uchain);
	return false;
}