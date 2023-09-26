#include "head.h"

#ifdef MINIMUM_CACHE
#include "my_ctl_cache.h"
#include <openssl/x509.h>
#include <openssl/evp.h>
#include "ecqv.h"
extern BN_CTX* bn_ctx;
struct asn1_object_st {
	const char* sn, * ln;
	int nid;
	int length;
	const unsigned char* data;  /* data remains const after init */
	int flags;                  /* Should we free this one */
};


// 判等，用于查找是否重复，故不对aux信息判断
bool operator==(const mini_cache_item_st& a, const mini_cache_item_st& b) {
	return memcmp(a.key_hash, b.key_hash, SHA256_DIGEST_LENGTH) == 0 
#ifdef NO_CURVEBALL_BUG
		&& a.param_len == b.param_len && memcmp(a.param, b.param, a.param_len) == 0
#endif		
;
}

#ifdef NO_CURVEBALL_BUG
inline bool isRootEntryMatch(const MINI_CACHE_ITEM* cur, const unsigned char* md, const int para_len, const unsigned char* para) {
	return memcmp(cur->key_hash, md, SHA256_DIGEST_LENGTH) == 0
		&& cur->param_len == para_len
		&& memcmp(cur->param, para, para_len) == 0
		;
}
#endif

// 计算公钥值的SHA256（不包括参数）
bool X509_get_SHA256_of_pubkey(const X509* x, unsigned char* out) {
	if (!x || !out) return false;

	ASN1_BIT_STRING* str = X509_get0_pubkey_bitstr(x);
	if (str == NULL) return false;

#ifdef MINIMUM_CACHE_DEBUG1
	printf("PUB_BITSTR(%d): ", str->length);
	for (int i = 0; i < str->length; i++) {
		printf("%02x ", str->data[i]);
	}
	printf("\n");
#endif
	SHA256(str->data, str->length, out);

	return true;
}
#ifdef MINIMUM_FINAL_KEY
// TODO: 目前仅支持ECkey
bool EC_KEY_get_SHA256_of_pubkey(const EC_KEY* key, unsigned char* out) {
	if (!key || !out) return false;
	const EC_POINT* pub = EC_KEY_get0_public_key(key);
	const EC_GROUP* group = EC_KEY_get0_group(key);
	unsigned char* buf = NULL; 
	int buf_len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_COMPRESSED, NULL, 0, bn_ctx);
	buf = (unsigned char *)OPENSSL_malloc(buf_len);
	if (!buf || !EC_POINT_point2oct(group, pub, POINT_CONVERSION_COMPRESSED, buf, buf_len, bn_ctx)) {
		goto ERR;
	}
	SHA256(buf, buf_len, out);
	OPENSSL_free(buf);
	return true;
ERR:
	if (buf) OPENSSL_free(buf);
	return false;
}
#endif // MINIMUM_FINAL_KEY

bool MINI_CACHE_ITEM_print(FILE* logfile, const char *label, const MINI_CACHE_ITEM* pitem) {
	if (!logfile) logfile = stdout;
	fprintf(logfile, "MINI_CACHE_ITEM (%s): ", label ? label : "null");
	if (!pitem) {
		fprintf(logfile, "(NONE)\n");
		return false;
	}
	fprintf(logfile, "\n  PubKeyCache (%d)\n    ", SHA256_DIGEST_LENGTH);
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		fprintf(logfile, "%02x ", pitem->key_hash[i]);
	}
#ifdef NO_CURVEBALL_BUG
	fprintf(logfile, "\n  Parameter (%d)\n    ", pitem->param_len);
	for (int i = 0; i < pitem->param_len; i++) {
		fprintf(logfile, "%02x ", pitem->param[i]);
	}
#endif
#ifdef EXTENDED_MINIMUM
	fprintf(logfile, "\n  Aux (%d)\n    ", pitem->aux_len);
	for (int i = 0; i < pitem->aux_len; i++) {
		fprintf(logfile, "%02x ", pitem->key_aux[i]);
	}
	fprintf(logfile, "\n");
#endif
	return true;
}

// 计算待验证证书x的比对结构*pitem（如果没有curveball漏洞，还会包括参数信息）
bool MINI_CACHE_ITEM_set_from_X509(MINI_CACHE_ITEM* pitem, const X509* x) {
	if (!x || !pitem) return false;
	// 在Windows中，参数信息直接从证书结构读取；而在OpenSSL模拟下只能通过类型转换再生成解决

	// Step 1 获取公钥的哈希值
	if (!X509_get_SHA256_of_pubkey(x, pitem->key_hash)) {
		return false;
	}

#ifdef NO_CURVEBALL_BUG
	// Step 2 获取公钥参数信息
	pitem->param_len = X509_get_Param_str_of_pubkey(x, &pitem->param);
	if (pitem->param_len < 0) {
		return false;
	}
#endif
	return true;
}

#ifdef MINIMUM_FINAL_KEY

// eckey 在隐式证书下表示为最终公钥值
bool MINI_CACHE_ITEM_set_from_EC_KEY(MINI_CACHE_ITEM* pitem, EC_KEY* eckey) {
	if (!eckey || !pitem) return false;

	// Step 1 获取公钥的哈希值
	if (!EC_KEY_get_SHA256_of_pubkey(eckey, pitem->key_hash)) {
		return false;
	}

#ifdef NO_CURVEBALL_BUG
	// Step 2 获取公钥参数信息
	pitem->param_len = EC_KEY_get_Param_str_of_pubkey(eckey, &pitem->param);
	if (pitem->param_len < 0) {
		return false;
	}
#endif
	return true;
}

#endif // MINIMUM_FINAL_KEY


#ifdef EXTENDED_MINIMUM
// 只设置，不检查
bool MINI_CACHE_ITEM_set_key_aux(MINI_CACHE_ITEM* item, EVP_PKEY *key) {
	if (!item) return false;
	item->key_aux = NULL;
	item->aux_len = 0;
	if(key) item->aux_len = i2d_PUBKEY(key, &item->key_aux);
	return item->aux_len > 0 || (!key && item->aux_len == 0);
}

bool MINI_CACHE_ITEM_get_key_aux(MINI_CACHE_ITEM* item, EVP_PKEY** vk) {
	if (!item) return false;
	const unsigned char* aux = item->key_aux;
	if (item->aux_len == 0) {
		if (vk) *vk = NULL;
		return true;
	}
	if (vk) *vk = EVP_PKEY_new();
	bool ret = (d2i_PUBKEY(vk, &aux, item->aux_len) != NULL);
	if (vk && !ret) {
		EVP_PKEY_free(*vk);
		*vk = NULL;
	}
	return ret;
}
#endif

MINI_CACHE* MINI_CACHE_new() {
	MINI_CACHE* ret = NULL;
	ret = (MINI_CACHE *)OPENSSL_malloc(sizeof(MINI_CACHE));
	// if (ret) ret->cache.clear();
	return ret;
}

void MINI_CACHE_free(MINI_CACHE* ctx) {
	OPENSSL_free(ctx);
	return;
}

MINI_CACHE_CTX* MINI_CACHE_CTX_new() {
	return (MINI_CACHE_CTX*)OPENSSL_malloc(sizeof(MINI_CACHE_CTX));
}

void MINI_CACHE_CTX_free(MINI_CACHE_CTX* ctx) {
	if (!ctx) return;
	OPENSSL_free(ctx);
	return;
}

bool MINI_CACHE_add_cert(MINI_CACHE* ctx, const X509* x, EVP_PKEY* key_aux) {
	if (!ctx || !x) return false;
	MINI_CACHE_ITEM item;
	if (!MINI_CACHE_ITEM_set_from_X509(&item, x)) return false;
#ifdef EXTENDED_MINIMUM
	if (!MINI_CACHE_ITEM_set_key_aux(&item, key_aux)) return false;
#endif

#ifdef MINIMUM_CACHE_DEBUG
	MINI_CACHE_ITEM_print(stdout, "item", &item);
#endif

	// if (std::find(ctx->cache.begin(), ctx->cache.end(), item) == ctx->cache.end()) {
		ctx->cache.push_back(item);
	// }
	// else {
		// printf("Add failed! The item is exist!\n");
	// }
	return true;
}

#ifdef MINIMUM_FINAL_KEY
bool MINI_CACHE_add_key(MINI_CACHE* ctx, EC_KEY* key, EVP_PKEY* key_aux) {
	if (!ctx || !key) return false;
	MINI_CACHE_ITEM item;

	// 设置key和参数（如需）
#ifdef MINIMUM_CACHE_DEBUG
	ecqv_print_key(stdout, "add Pkey", "null", key, bn_ctx);
#endif
	if (!MINI_CACHE_ITEM_set_from_EC_KEY(&item, key)) return false;
#ifdef EXTENDED_MINIMUM
	// 设置辅助密钥
	if (!MINI_CACHE_ITEM_set_key_aux(&item, key_aux)) return false;
#endif

#ifdef MINIMUM_CACHE_DEBUG
	MINI_CACHE_ITEM_print(stdout, "item", &item);
#endif

	if (std::find(ctx->cache.begin(), ctx->cache.end(), item) == ctx->cache.end()) {
		ctx->cache.push_back(item);
	}
	else {
#ifdef MINIMUM_CACHE_DEBUG
		printf("Add failed! The item is exist!\n");
#endif
	}
	return true;
}

#endif


int MINI_CACHE_match_by_SHA256_like_Windows(MY_STORAGE_CTX* ctx, X509* cur, EVP_PKEY** cur_key) {
	MINI_CACHE* store = NULL;
	unsigned char key_md[SHA256_DIGEST_LENGTH];
	int cur_type = 0;
#ifdef NO_CURVEBALL_BUG
	int para_len = 0;
	const unsigned char* para = NULL;
#endif

	if (!ctx || !ctx->mini || !(store = ctx->mini->store))
		return MY_STORAGE_ERROR;

	cur_type = get_cert_type(cur);
#ifdef MINIMUM_FINAL_KEY
	// 此时为Vp
	EC_KEY* cur_eckey = NULL;
	EC_POINT* eQ = NULL; // TODO: 此变量未释放
	if (cur_type == TYPE_IMPLICIT) {
		if (!ecqv_cert_pk_extract(cur, NULL, &cur_eckey) || !cur_eckey) {
			return MY_STORAGE_ERROR;
		}
#ifdef EXTENDED_MINIMUM
		// 存在辅助字段，预先获取临时值 e*Q
		if (
			!(eQ = EC_POINT_dup(EC_KEY_get0_public_key(cur_eckey), EC_KEY_get0_group(cur_eckey)))
		) {
			return MY_STORAGE_ERROR;
		}
		//const EC_GROUP* group = EC_KEY_get0_group(cur_eckey);
		//ecqv_print_point(stdout, "eQ", eQ, group, bn_ctx);
#else 
		// 不存在，当作根证书处理
		if (!EC_KEY_get_SHA256_of_pubkey(cur_eckey, key_md)) {
			return MY_STORAGE_ERROR;
		}
#endif // EXTENDED_MINIMUM
	}
	else { // 否则，为显式证书，直接从证书提取
		cur_eckey = EVP_PKEY_get0_EC_KEY(X509_get0_pubkey(cur));
		if (cur_eckey == NULL) return MY_STORAGE_ERROR;
		if (!EC_KEY_get_SHA256_of_pubkey(cur_eckey, key_md)) {
			return MY_STORAGE_ERROR;
		}
#ifdef VALIDATE_DEBUG
#ifdef DEBUG
		ecqv_print_key(stdout, "chk Pkey", "null", cur_eckey, bn_ctx);
#endif
		printf("key_md: ");
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
			printf("%02x ", key_md[i]);
		}
		printf("\n");
#endif // VALIDATE_DEBUG
	}

#else
	// 此时为Vq，直接从证书中获取并计算
#ifdef VALIDATE_DEBUG
	ecqv_print_cert(stdout, "cur", cur);
#endif
	// 计算SHA256值
	if (!X509_get_SHA256_of_pubkey(cur, key_md)) {
		return MY_STORAGE_ERROR;
	}
#ifdef VALIDATE_DEBUG
	printf("key_md: ");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		printf("%02x ", key_md[i]);
	}
	printf("\n");
#endif // VALIDATE_DEBUG
#endif

#ifdef NO_CURVEBALL_BUG
#ifdef MINIMUM_FINAL_KEY
	para_len = EC_KEY_get_Param_str_of_pubkey(cur_eckey, &para);
#else
	para_len = X509_get_Param_str_of_pubkey(cur, &para);
#endif
#ifdef VALIDATE_DEBUG
	printf("cur para: ");
	for (int i = 0; i < para_len; i++) {
		printf("%02x ", para[i]);
	}
	printf("\n");
#endif // VALIDATE_DEBUG
#endif // NO_CURVEBALL_BUG

	// 逐一比较
	for (auto &x : store->cache) {
#ifdef VALIDATE_DEBUG
		MINI_CACHE_ITEM_print(stdout, "x", &x);
#endif

#if defined(MINIMUM_FINAL_KEY) && defined(EXTENDED_MINIMUM)
		// 如果是拓展的Vp，则根据辅助值计算待比较值并做SHA256
		EVP_PKEY* key_aux = NULL;
		EC_KEY* eckey_aux = NULL;
		const EC_POINT* aux = NULL;
		const EC_GROUP* group = NULL;
		EC_POINT* final_key = NULL;
		if (cur_type == TYPE_IMPLICIT) {
			if (!MINI_CACHE_ITEM_get_key_aux(&x, &key_aux)) {
				return MY_STORAGE_ERROR;
			}
			if (key_aux) {
				// item是隐式证书
				if (!(eckey_aux = EVP_PKEY_get0_EC_KEY(key_aux)) ||
					!(aux = EC_KEY_get0_public_key(eckey_aux)) ||
					! (group = EC_KEY_get0_group(eckey_aux))
				) {
					return MY_STORAGE_ERROR;
				}
				if (!(final_key = EC_POINT_new(group))) {
					return MY_STORAGE_ERROR;
					// TODO: 下面的错误没有释放该指针
				}
				if (!EC_POINT_add(group, final_key, eQ, aux, bn_ctx)) {
					return MY_STORAGE_ERROR;
				}
#ifdef VALIDATE_DEBUG
				ecqv_print_point(stdout, "final", final_key, group, bn_ctx);
#endif
				if (!EC_KEY_set_public_key(cur_eckey, final_key)) {
					return MY_STORAGE_ERROR;
				}
			} // 否则，item是显式证书或隐式根证书（已计算）
			if (!EC_KEY_get_SHA256_of_pubkey(cur_eckey, key_md)) {
				return MY_STORAGE_ERROR;
			}
#ifdef VALIDATE_DEBUG
			printf("key_md: ");
			for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
				printf("%02x ", key_md[i]);
			}
			printf("\n");
#endif // VALIDATE_DEBUG
		}
#endif

		// 此处开始比较
#ifdef NO_CURVEBALL_BUG
		if (isRootEntryMatch(&x, key_md, para_len, para)) {
#else // 存在curveball漏洞，直接比较
		if (memcmp(x.key_hash, key_md, SHA256_DIGEST_LENGTH) == 0) {
#endif
#ifdef VALIDATE_PRINT_STEP
			printf("The top-level certificate is trusted!\n");
#endif
			// 提取公钥值
			if (cur_type == TYPE_EXPLICIT) {
				if (cur_key && !(*cur_key = X509_get0_pubkey(cur))) {
					MY_STORAGE_CTX_set_error(ctx, X509_V_ERR_NO_ISSUER_PUBLIC_KEY);
#ifdef VALIDATE_PRINT_STEP
					printf("ERR: Can not get the PubKey of the trust certificate!\n");
#endif
					return MY_STORAGE_ERROR;
				}
			}
			else { // type == TYPE_IMPLICIT
				EC_KEY* vkec = NULL;
				if (cur_key) *cur_key = NULL;
				// 提取最终公钥
#ifdef EXTENDED_MINIMUM
#ifdef MINIMUM_FINAL_KEY
				// 如果使用拓展小量缓存Vp，直接使用cur_eckey
				if (cur_key) {
					*cur_key = EVP_PKEY_new();
					if (!EVP_PKEY_set1_EC_KEY(*cur_key, cur_eckey)) {
						return MY_STORAGE_ERROR;
					}
				}
#else
				// 如果使用拓展小量缓存Vq，则只需从辅助信息获取
				if (!MINI_CACHE_ITEM_get_key_aux(&x, cur_key) || !cur_key) {
					return MY_STORAGE_ERROR;
				};
#endif // MINIMUM_FINAL_KEY			
#endif// EXTENDED_MINIMUM
				// 正常情况，只能按照根证书重构值计算方法计算（因为无法找到辅助计算值或更上层CA
				if (!cur_key || !*cur_key) {
					if (!ecqv_cert_pk_extract(cur, NULL, &vkec)) {
						printf("ERR: Can not reconstruct the EC PubKey of the trust certificate!\n");
						return MY_STORAGE_ERROR;
					}
					if (cur_key && (!(*cur_key = EVP_PKEY_new()) ||   // TODO：没有判断如果原本cur_key有空间
						!EVP_PKEY_set1_EC_KEY(*cur_key, vkec))
						) {
						return MY_STORAGE_ERROR;
					}
				}
			}
			return MY_STORAGE_MATCHED;
		}
	}
#ifdef VALIDATE_PRINT_STEP
	printf("ERR: top-level certificate is untrusted!\n");
#endif
	MY_STORAGE_CTX_set_error(ctx, X509_V_ERR_CERT_UNTRUSTED);
	return MY_STORAGE_UNMATCHED;
}



#endif