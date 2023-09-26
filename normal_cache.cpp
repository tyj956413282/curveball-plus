#include "head.h"

#ifndef MINIMUM_CACHE
#include "my_ctl_cache.h"
#include <openssl/x509.h>
#include <openssl/md5.h>
#include "ecqv.h"

inline bool get_md5_of_public_key(const X509* x, unsigned char* out) {
	ASN1_BIT_STRING* pub = X509_get0_pubkey_bitstr(x);
	if (!pub) return false;
	MD5(pub->data, pub->length, out);
	return true;
}

inline bool compare_md5_of_public_key(const X509* cert1, const X509* cert2) {
	if (!cert1 || !cert2) return false;
	unsigned char pub1_md[MD5_DIGEST_LENGTH], pub2_md[MD5_DIGEST_LENGTH];
	if (!get_md5_of_public_key(cert1, pub1_md)) return false;
	if (!get_md5_of_public_key(cert2, pub2_md)) return false; // Windows中可能会预存该值
#ifdef PRINT_MD5_CMP
	printf("md5-1: ");
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
		printf("%02x ", pub1_md[i]);
	}
	printf("\n");
	printf("md5-2: ");
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
		printf("%02x ", pub2_md[i]);
	}
	printf("\n");
#endif
	return memcmp(pub1_md, pub2_md, MD5_DIGEST_LENGTH) == 0;
}

inline bool is_md5_of_public_key_matched(const X509* cert, const unsigned char* md) {
	if (!cert || !md) return false;
	unsigned char pub_md[MD5_DIGEST_LENGTH];
	if (!get_md5_of_public_key(cert, pub_md)) return false;
#ifdef PRINT_MD5_CMP
	printf("md    : ");
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
		printf("%02x ", md[i]);
	}
	printf("\n");
	printf("pub_md: ");
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
		printf("%02x ", pub_md[i]);
	}
	printf("\n");
#endif
	return memcmp(md, pub_md, MD5_DIGEST_LENGTH) == 0;
}

#ifdef NO_CURVEBALL_BUG
inline bool is_public_key_parameter_matched(const X509* cert, const unsigned char* para, int len) {
	if (!cert || !para || len < 0) return false;
	const unsigned char* cert_para_buf = NULL;
	int cert_para_len = X509_get_Param_str_of_pubkey(cert, &cert_para_buf);
	if (!cert_para_buf || cert_para_len < 0) return false;
	return cert_para_len == len &&
		memcmp(cert_para_buf, para, len) == 0;
}
#endif

// 通过公钥哈希值来判断cur是否在store内
bool X509_STORE_match_by_MD5_like_Windows(X509_STORE* store, X509* cur) {
	STACK_OF(X509_OBJECT)* buf = NULL;
	const X509* x = NULL;
	unsigned int buff_num = 0, i = 0;
	unsigned char cur_md[MD5_DIGEST_LENGTH];
#ifdef NO_CURVEBALL_BUG
	const unsigned char* cur_para = NULL;
	unsigned int cur_para_len = 0;
#endif

	if (!get_md5_of_public_key(cur, cur_md)) goto ERR;
#ifdef NO_CURVEBALL_BUG
	cur_para_len = X509_get_Param_str_of_pubkey(cur, &cur_para);
	if (!cur_para || cur_para_len < 0) goto ERR;
#endif

	if (!(buf = X509_STORE_get0_objects(store))) {
		goto ERR;
	}
	buff_num = sk_X509_OBJECT_num(buf);
	for (i = 0; i < buff_num; i++) {
		x = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(buf, i));
		if (!x) continue;
		if (is_md5_of_public_key_matched(x, cur_md)
#ifdef NO_CURVEBALL_BUG
			&& is_public_key_parameter_matched(x, cur_para, cur_para_len)
#endif
		) {
			return true;
		}
	}
ERR:
	return false;
}

inline bool NORMAL_CACHE_get_issuer(MY_STORAGE_CTX* ctx, X509* cur, X509 **ca) {
	X509_NAME* x_name = X509_get_issuer_name(cur);
	if (x_name == NULL) {
		MY_STORAGE_CTX_set_error(ctx, X509_V_ERR_NO_ISSUER_PUBLIC_KEY);
		return false;
	}
	STACK_OF(X509)* certstmp = MY_STORAGE_CTX_get1_cert(ctx, x_name);
	if (!certstmp || !sk_X509_num(certstmp)) {
		MY_STORAGE_CTX_set_error(ctx, X509_V_ERR_SUBJECT_ISSUER_MISMATCH);
#ifdef VALIDATE_PRINT_STEP
		printf("ERR: The issuer is mismatched!\n");
#endif
		return false;
	}
	if (ca) *ca = sk_X509_value(certstmp, 0); // TODO: 假设只有一个
	return true;
}

int NORMAL_CACHE_match_by_MD5_like_Windows(
	MY_STORAGE_CTX* ctx,
	X509* cur, 
	STACK_OF(X509)* chain, 
	EVP_PKEY **cur_key
) {
	int ret = 0;
	if (!ctx || !ctx->normal || !cur || !chain) return MY_STORAGE_ERROR;
	int cur_type = get_cert_type(cur);
	int cur_mode = get_cert_mode(cur);

	if (sk_X509_num(chain) == 1) { // 此时，需向信任区继续查找一层
		X509* x = NULL;
		if (!NORMAL_CACHE_get_issuer(ctx, cur, &x) || !x) {
			return MY_STORAGE_UNMATCHED;
		}
		sk_X509_push(chain, x);
#ifdef VALIDATE_PRINT_STEP
		X509_NAME *print_sub_name = X509_get_subject_name(x);
		X509_NAME *print_iss_name = X509_get_issuer_name(x);
		printf("Add last cert into the chain (subject = [%s], issuer = [%s])\n",
			X509_NAME_oneline(print_sub_name, NULL, 0),
			X509_NAME_oneline(print_iss_name, NULL, 0));
		printf("Find a trust certificate! End searching...\n");
#endif
		cur = x;
		cur_type = get_cert_type(cur);
		cur_mode = get_cert_mode(cur);
	}
	else { // 此时，向信任区查找顶端证书是否存在
		X509_STORE* trusted = MY_STORAGE_CTX_get0_store(ctx);
		ret = X509_STORE_match_by_MD5_like_Windows(trusted, cur);
		if (ret <= 0) {
			if (ret == 0) {
#ifdef VALIDATE_PRINT_STEP
				printf("ERR: top-level certificate is untrusted!\n");
#endif
				MY_STORAGE_CTX_set_error(ctx, X509_V_ERR_CERT_UNTRUSTED);
			}
			return ret;
		}
#ifdef VALIDATE_PRINT_STEP
		printf("The top-level certificate is trusted!\n");
#endif
	}

	// 提取公钥值

	//  (1) 如果是隐式证书，继续向上查找，直至能做公钥重构（即第一个显式证书或隐式根证书为止）
	X509* cur_ca = NULL;
	while (cur_type == TYPE_IMPLICIT && cur_mode == MODE_USER) {
		if (!NORMAL_CACHE_get_issuer(ctx, cur, &cur_ca) || !cur_ca) {
			return MY_STORAGE_NO_RECONSTRUCTION;
		}
		sk_X509_push(chain, cur_ca);
#ifdef VALIDATE_PRINT_STEP
		X509_NAME* print_sub_name = X509_get_subject_name(cur_ca);
		X509_NAME* print_iss_name = X509_get_issuer_name(cur_ca);
		printf("Add a trust cert into the chain (subject = [%s], issuer = [%s])\n",
			X509_NAME_oneline(print_sub_name, NULL, 0),
			X509_NAME_oneline(print_iss_name, NULL, 0));
#endif
		cur = cur_ca;
		cur_type = get_cert_type(cur);
		cur_mode = get_cert_mode(cur);
	}

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

	return MY_STORAGE_MATCHED;
}
#endif