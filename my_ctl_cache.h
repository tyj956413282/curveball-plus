#ifndef _MY_CERT_STORAGE_H
#define _MY_CERT_STORAGE_H

#include "head.h"
#include <openssl/x509.h>
#include <vector>

#define MY_STORAGE_MATCHED				1
#define MY_STORAGE_UNMATCHED			0
#define MY_STORAGE_NO_RECONSTRUCTION	-2
#define MY_STORAGE_ERROR				-1

struct mini_cache_item_st {
	unsigned char key_hash[SHA256_DIGEST_LENGTH];
#ifdef NO_CURVEBALL_BUG
	const unsigned char* param;		// 存储公钥参数信息
	int param_len;
#endif
#ifdef EXTENDED_MINIMUM
	unsigned char* key_aux;	// 存储辅助计算信息
	int aux_len;
#endif
};

struct mini_cache_st {
	std::vector<mini_cache_item_st> cache;
};

// 简易版CTX
struct mini_cache_ctx_st {
	mini_cache_st* store;
	// The following are set by the caller 
	X509* cert;
	STACK_OF(X509)* untrusted;
	// The following is built up
	STACK_OF(X509)* chain;
	int error;
};

typedef mini_cache_item_st	MINI_CACHE_ITEM;
typedef mini_cache_st		MINI_CACHE;
typedef mini_cache_ctx_st	MINI_CACHE_CTX;

MINI_CACHE* MINI_CACHE_new();
void MINI_CACHE_free(MINI_CACHE* ctx);

#ifdef MINIMUM_FINAL_KEY
bool MINI_CACHE_add_key(MINI_CACHE* ctx, EC_KEY* key, EVP_PKEY* key_aux = NULL);
#else
bool MINI_CACHE_add_cert(MINI_CACHE* ctx, const X509* x, EVP_PKEY *key_aux = NULL);
#endif // MINIMUM_FINAL_KEY

MINI_CACHE_CTX* MINI_CACHE_CTX_new();
void MINI_CACHE_CTX_free(MINI_CACHE_CTX* ctx);

#ifdef MINIMUM_CACHE

#define MY_STORAGE					MINI_CACHE

#define MY_STORAGE_new				MINI_CACHE_new
#define MY_STORAGE_free				MINI_CACHE_free

#ifdef MINIMUM_FINAL_KEY
#define MY_STORAGE_add_key			MINI_CACHE_add_key
#else
#define MY_STORAGE_add_cert			MINI_CACHE_add_cert
#endif MINIMUM_FINAL_KEY

#else 

#define MY_STORAGE				X509_STORE

#define MY_STORAGE_new			X509_STORE_new
#define MY_STORAGE_free			X509_STORE_free
#define MY_STORAGE_add_cert(ctx, x, aux)		X509_STORE_add_cert(ctx, x)

#endif

union my_storage_ctx_st {
	x509_store_ctx_st* normal;
	mini_cache_ctx_st* mini;
};
#ifdef MINIMUM_CACHE
#define  MY_CTX(x) (x)->mini
#else
#define	 MY_CTX(x) (x)->normal
#endif

typedef my_storage_ctx_st	MY_STORAGE_CTX;

MY_STORAGE_CTX* MY_STORAGE_CTX_new();
void MY_STORAGE_CTX_free(MY_STORAGE_CTX *ctx);
int MY_STORAGE_CTX_init(MY_STORAGE_CTX* ctx, MY_STORAGE* trusted_store, X509* target, STACK_OF(X509)* untrusted);

MY_STORAGE* MY_STORAGE_CTX_get0_store(MY_STORAGE_CTX* ctx);
STACK_OF(X509)* MY_STORAGE_CTX_get0_chain(MY_STORAGE_CTX* ctx);
STACK_OF(X509)* MY_STORAGE_CTX_get0_untrusted(MY_STORAGE_CTX* ctx);
X509* MY_STORAGE_CTX_get0_cert(MY_STORAGE_CTX* ctx);
void MY_STORAGE_CTX_set_error(MY_STORAGE_CTX* ctx, int error);
#ifndef MINIMUM_CACHE
#define MY_STORAGE_CTX_get1_cert(ctx, name) X509_STORE_get1_cert((ctx)->normal, name)
#endif

int MY_STORAGE_CTX_is_cert_matched(
	MY_STORAGE_CTX* ctx,
	X509* cur,
	STACK_OF(X509)* chain, 
	EVP_PKEY ** cur_key
);

int MINI_CACHE_match_by_SHA256_like_Windows(
	MY_STORAGE_CTX* ctx,
	X509* cur, 
	EVP_PKEY** cur_key
);

int NORMAL_CACHE_match_by_MD5_like_Windows(
	MY_STORAGE_CTX* ctx,
	X509* cur,
	STACK_OF(X509)* chain, 
	EVP_PKEY** cur_key
);

#ifdef NO_CURVEBALL_BUG
int X509_get_Param_str_of_pubkey(const X509* x, const unsigned char** out);
int EC_KEY_get_Param_str_of_pubkey(const EC_KEY* key, const unsigned char** out);
#endif


#endif