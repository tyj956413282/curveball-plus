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


// �еȣ����ڲ����Ƿ��ظ����ʲ���aux��Ϣ�ж�
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

// ���㹫Կֵ��SHA256��������������
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
// TODO: Ŀǰ��֧��ECkey
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

// �������֤֤��x�ıȶԽṹ*pitem�����û��curveball©�����������������Ϣ��
bool MINI_CACHE_ITEM_set_from_X509(MINI_CACHE_ITEM* pitem, const X509* x) {
	if (!x || !pitem) return false;
	// ��Windows�У�������Ϣֱ�Ӵ�֤��ṹ��ȡ������OpenSSLģ����ֻ��ͨ������ת�������ɽ��

	// Step 1 ��ȡ��Կ�Ĺ�ϣֵ
	if (!X509_get_SHA256_of_pubkey(x, pitem->key_hash)) {
		return false;
	}

#ifdef NO_CURVEBALL_BUG
	// Step 2 ��ȡ��Կ������Ϣ
	pitem->param_len = X509_get_Param_str_of_pubkey(x, &pitem->param);
	if (pitem->param_len < 0) {
		return false;
	}
#endif
	return true;
}

#ifdef MINIMUM_FINAL_KEY

// eckey ����ʽ֤���±�ʾΪ���չ�Կֵ
bool MINI_CACHE_ITEM_set_from_EC_KEY(MINI_CACHE_ITEM* pitem, EC_KEY* eckey) {
	if (!eckey || !pitem) return false;

	// Step 1 ��ȡ��Կ�Ĺ�ϣֵ
	if (!EC_KEY_get_SHA256_of_pubkey(eckey, pitem->key_hash)) {
		return false;
	}

#ifdef NO_CURVEBALL_BUG
	// Step 2 ��ȡ��Կ������Ϣ
	pitem->param_len = EC_KEY_get_Param_str_of_pubkey(eckey, &pitem->param);
	if (pitem->param_len < 0) {
		return false;
	}
#endif
	return true;
}

#endif // MINIMUM_FINAL_KEY


#ifdef EXTENDED_MINIMUM
// ֻ���ã������
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

	// ����key�Ͳ��������裩
#ifdef MINIMUM_CACHE_DEBUG
	ecqv_print_key(stdout, "add Pkey", "null", key, bn_ctx);
#endif
	if (!MINI_CACHE_ITEM_set_from_EC_KEY(&item, key)) return false;
#ifdef EXTENDED_MINIMUM
	// ���ø�����Կ
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
	// ��ʱΪVp
	EC_KEY* cur_eckey = NULL;
	EC_POINT* eQ = NULL; // TODO: �˱���δ�ͷ�
	if (cur_type == TYPE_IMPLICIT) {
		if (!ecqv_cert_pk_extract(cur, NULL, &cur_eckey) || !cur_eckey) {
			return MY_STORAGE_ERROR;
		}
#ifdef EXTENDED_MINIMUM
		// ���ڸ����ֶΣ�Ԥ�Ȼ�ȡ��ʱֵ e*Q
		if (
			!(eQ = EC_POINT_dup(EC_KEY_get0_public_key(cur_eckey), EC_KEY_get0_group(cur_eckey)))
		) {
			return MY_STORAGE_ERROR;
		}
		//const EC_GROUP* group = EC_KEY_get0_group(cur_eckey);
		//ecqv_print_point(stdout, "eQ", eQ, group, bn_ctx);
#else 
		// �����ڣ�������֤�鴦��
		if (!EC_KEY_get_SHA256_of_pubkey(cur_eckey, key_md)) {
			return MY_STORAGE_ERROR;
		}
#endif // EXTENDED_MINIMUM
	}
	else { // ����Ϊ��ʽ֤�飬ֱ�Ӵ�֤����ȡ
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
	// ��ʱΪVq��ֱ�Ӵ�֤���л�ȡ������
#ifdef VALIDATE_DEBUG
	ecqv_print_cert(stdout, "cur", cur);
#endif
	// ����SHA256ֵ
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

	// ��һ�Ƚ�
	for (auto &x : store->cache) {
#ifdef VALIDATE_DEBUG
		MINI_CACHE_ITEM_print(stdout, "x", &x);
#endif

#if defined(MINIMUM_FINAL_KEY) && defined(EXTENDED_MINIMUM)
		// �������չ��Vp������ݸ���ֵ������Ƚ�ֵ����SHA256
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
				// item����ʽ֤��
				if (!(eckey_aux = EVP_PKEY_get0_EC_KEY(key_aux)) ||
					!(aux = EC_KEY_get0_public_key(eckey_aux)) ||
					! (group = EC_KEY_get0_group(eckey_aux))
				) {
					return MY_STORAGE_ERROR;
				}
				if (!(final_key = EC_POINT_new(group))) {
					return MY_STORAGE_ERROR;
					// TODO: ����Ĵ���û���ͷŸ�ָ��
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
			} // ����item����ʽ֤�����ʽ��֤�飨�Ѽ��㣩
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

		// �˴���ʼ�Ƚ�
#ifdef NO_CURVEBALL_BUG
		if (isRootEntryMatch(&x, key_md, para_len, para)) {
#else // ����curveball©����ֱ�ӱȽ�
		if (memcmp(x.key_hash, key_md, SHA256_DIGEST_LENGTH) == 0) {
#endif
#ifdef VALIDATE_PRINT_STEP
			printf("The top-level certificate is trusted!\n");
#endif
			// ��ȡ��Կֵ
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
				// ��ȡ���չ�Կ
#ifdef EXTENDED_MINIMUM
#ifdef MINIMUM_FINAL_KEY
				// ���ʹ����չС������Vp��ֱ��ʹ��cur_eckey
				if (cur_key) {
					*cur_key = EVP_PKEY_new();
					if (!EVP_PKEY_set1_EC_KEY(*cur_key, cur_eckey)) {
						return MY_STORAGE_ERROR;
					}
				}
#else
				// ���ʹ����չС������Vq����ֻ��Ӹ�����Ϣ��ȡ
				if (!MINI_CACHE_ITEM_get_key_aux(&x, cur_key) || !cur_key) {
					return MY_STORAGE_ERROR;
				};
#endif // MINIMUM_FINAL_KEY			
#endif// EXTENDED_MINIMUM
				// ���������ֻ�ܰ��ո�֤���ع�ֵ���㷽�����㣨��Ϊ�޷��ҵ���������ֵ����ϲ�CA
				if (!cur_key || !*cur_key) {
					if (!ecqv_cert_pk_extract(cur, NULL, &vkec)) {
						printf("ERR: Can not reconstruct the EC PubKey of the trust certificate!\n");
						return MY_STORAGE_ERROR;
					}
					if (cur_key && (!(*cur_key = EVP_PKEY_new()) ||   // TODO��û���ж����ԭ��cur_key�пռ�
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