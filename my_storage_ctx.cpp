#include "head.h"
#include "my_ctl_cache.h"
#include <openssl/x509.h>

#ifdef NO_CURVEBALL_BUG
// 获取公钥值的参数值
int X509_get_Param_str_of_pubkey(const X509* x, const unsigned char** out) {
	X509_ALGOR* alg = NULL;
	unsigned char* param_str = NULL;
	int param_len = 0;
	if (!x) goto ERR;

	if (!X509_PUBKEY_get0_param(
		NULL,
		NULL,
		NULL,
		&alg,
		X509_get_X509_PUBKEY(x)
	)) goto ERR;
	if (!(param_len = i2d_X509_ALGOR(alg, &param_str))) {
		goto ERR;
	}
	if (out) *out = param_str;
	return param_len;
ERR:
	if (param_str) OPENSSL_free(param_str);
	return -1;
}

int EC_KEY_get_Param_str_of_pubkey(const EC_KEY* key, const unsigned char** out) {
	unsigned char* param_str = NULL;
	int param_len = 0;
	const EC_GROUP* group = NULL;

	if (!key) goto ERR;

	if (!(group = EC_KEY_get0_group(key))) goto ERR;
	param_len = i2d_ECPKParameters(group, &param_str);

	if (out) *out = param_str;
	return param_len;
ERR:
	if (param_str) OPENSSL_free(param_str);
	return -1;
}
#endif

MY_STORAGE_CTX* MY_STORAGE_CTX_new() {
	MY_STORAGE_CTX* ret = (MY_STORAGE_CTX*)OPENSSL_malloc(sizeof(MY_STORAGE_CTX));
	if (ret == 0) return NULL;
#ifdef MINIMUM_CACHE
	ret->mini = MINI_CACHE_CTX_new();
	if (ret->mini == NULL) {
		OPENSSL_free(ret);
		return NULL;
	}
#else 
	ret->normal = X509_STORE_CTX_new();
	if (ret->normal == NULL) {
		OPENSSL_free(ret);
		return NULL;
	}
#endif
	return ret;
}

void MY_STORAGE_CTX_free(MY_STORAGE_CTX *ctx) {
	if (!ctx) return;
#ifdef MINIMUM_CACHE
	if (ctx->mini) MINI_CACHE_CTX_free(ctx->mini);
#else
	if (ctx->normal) X509_STORE_CTX_free(ctx->normal);
#endif
	OPENSSL_free(ctx);
	return;
}

int MY_STORAGE_CTX_init(MY_STORAGE_CTX* ctx, MY_STORAGE* trusted_store, X509* target, STACK_OF(X509)* untrusted) {
#ifdef MINIMUM_CACHE
	if (!ctx || !ctx->mini) return 0;
	ctx->mini->store = trusted_store;
	ctx->mini->cert = target;
	ctx->mini->untrusted = untrusted;
	ctx->mini->chain = NULL;
	ctx->mini->error = X509_V_OK;

	return 1;
#else
	return X509_STORE_CTX_init(ctx->normal, trusted_store, target, untrusted);
#endif
}

MY_STORAGE* MY_STORAGE_CTX_get0_store(MY_STORAGE_CTX* ctx) {
	if (!ctx) return NULL;
#ifdef MINIMUM_CACHE
	if (!ctx->mini) return NULL;
	return ctx->mini->store;
#else
	return X509_STORE_CTX_get0_store(ctx->normal);
#endif
}

STACK_OF(X509)* MY_STORAGE_CTX_get0_chain(MY_STORAGE_CTX* ctx) {
	if (!ctx) return NULL;
#ifdef MINIMUM_CACHE
	if (!ctx->mini) return NULL;
	return ctx->mini->chain;
#else
	return X509_STORE_CTX_get0_chain(ctx->normal);
#endif
}

STACK_OF(X509)* MY_STORAGE_CTX_get0_untrusted(MY_STORAGE_CTX* ctx) {
	if (!ctx) return NULL;
#ifdef MINIMUM_CACHE
	if (!ctx->mini) return NULL;
	return ctx->mini->untrusted;
#else
	return X509_STORE_CTX_get0_untrusted(ctx->normal);
#endif
}

X509* MY_STORAGE_CTX_get0_cert(MY_STORAGE_CTX* ctx) {
	if (!ctx) return NULL;
#ifdef MINIMUM_CACHE
	if (!ctx->mini) return NULL;
	return ctx->mini->cert;
#else
	return X509_STORE_CTX_get0_cert(ctx->normal);
#endif
}

int MY_STORAGE_CTX_is_cert_matched(
	MY_STORAGE_CTX* ctx, 
	X509* cur, 
	STACK_OF(X509)* chain, 
	EVP_PKEY ** cur_key
) {
	if (!ctx) return 0;
#ifdef MINIMUM_CACHE
	return MINI_CACHE_match_by_SHA256_like_Windows(ctx, cur, cur_key);
#else
	return NORMAL_CACHE_match_by_MD5_like_Windows(ctx, cur, chain, cur_key);
#endif
}

void MY_STORAGE_CTX_set_error(MY_STORAGE_CTX* ctx, int error) {
	if (!ctx) return;
#ifdef MINIMUM_CACHE
	ctx->mini->error = error;
	return ;
#else
	return X509_STORE_CTX_set_error(ctx->normal, error);
#endif
}

#ifdef MINIMUM_CACHE

#else

#endif