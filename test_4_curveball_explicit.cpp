#include "test.h"
#include "curveball.h"
#include "make_cert.h"
#include "validate_cert.h"
#include "color.h"

#ifndef MINIMUM_FINAL_KEY // TODO: 应该消除这个条件

bool test41_curveball_explicit() {
	X509* target = NULL;
	MY_STORAGE* store = NULL;
#ifdef OPENSSL_RESULT
	X509_STORE* ossl_store = NULL;
	X509_STORE_CTX* ossl_ctx = NULL;
#endif
	MY_STORAGE_CTX* ctx = NULL;
	EC_KEY* a_key = NULL;
	X509* user = NULL;
	STACK_OF(X509)* others = NULL;
	int ret = 0;

	EC_KEY* tar_key = NULL;

	// 获得目标证书，不拿私钥
	if (!make_root_certificate(TYPE_EXPLICIT, "target", &target, &tar_key)) {
		return false;
	}
	ecqv_print_key(stdout, "target", "target", tar_key, NULL);
	if (!(store = MY_STORAGE_new()) ||
		!MY_STORAGE_add_cert(store, target)
	) {
		goto ERR;
	}
#ifdef OPENSSL_RESULT
	if (!(ossl_store = X509_STORE_new()) ||
		!X509_STORE_add_cert(store, target)
		) {
		goto ERR;
	}
#endif

	if (!curveball_explicit(target, &a_key, &user, &others) ||
		!a_key || !user || !others
	) {
		goto ERR;
	}

	ecqv_print_cert(stdout, "test", sk_X509_value(others, 0));

	// 创建CTX结构
	if (!(ctx = MY_STORAGE_CTX_new())) {
		goto ERR;
	}
	if (!MY_STORAGE_CTX_init(ctx, store, user, others)) {
		goto ERR;
	}

	// 测试验证
	printf("\nWindows-like Validation: \n");
	if (!validate_cert_like_win(ctx)) {
		SET_CUSTUM(0x0c) printf("Windows-like Result: validate failed! - Curveball is failed\n"); SET_CLEAR
			goto ERR;
	}
	else {
		SET_CUSTUM(0x0a) printf("Windows-like Result: validate success! - Curveball is success\n"); SET_CLEAR
	}

#ifdef OPENSSL_RESULT
	if (!(ossl_ctx = X509_STORE_CTX_new())) {
		goto ERR;
	}
	// 初始化ctx
	if (!X509_STORE_CTX_init(ossl_ctx, ossl_store, user, others)) {
		goto ERR;
	}
	ret = X509_verify_cert(ossl_ctx);
	if (ret == 1) {
		SET_CUSTUM(0x0a) printf("OpenSSL Result: true\n"); SET_CLEAR
	}
	if (ret <= 0) {
		SET_CUSTUM(0x0c) printf("OpenSSL Result Err Msg: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx))); SET_CLEAR
	}
#endif

	if (ctx) MY_STORAGE_CTX_free(ctx);
	if (store) MY_STORAGE_free(store);
#ifdef OPENSSL_RESULT
	if (ossl_ctx) X509_STORE_CTX_free(ossl_ctx);
	if (ossl_store) X509_STORE_free(ossl_store);
#endif
	return true;
ERR:
	if (ctx) MY_STORAGE_CTX_free(ctx);
	if (store) MY_STORAGE_free(store);
#ifdef OPENSSL_RESULT
	if (ossl_ctx) X509_STORE_CTX_free(ossl_ctx);
	if (ossl_store) X509_STORE_free(ossl_store);
#endif
	return false;
}

#endif