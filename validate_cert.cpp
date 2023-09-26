#include "validate_cert.h"
#include "my_ctl_cache.h"

#include "ecqv.h"


#include <openssl/md5.h>
#include <cstring>

// #define PRINT_CHECK_ISSUED
// #define PRINT_MD5_CMP
// #define DEBUG_VER_SIG

extern BN_CTX* bn_ctx;

// check if a is issued by b
inline bool check_issued(X509* a, X509* b) {
	if (!a || !b) return false;
	X509_NAME* a_issuer = X509_get_issuer_name(a);
	X509_NAME* b_subject = X509_get_subject_name(b);
#ifdef PRINT_CHECK_ISSUED
	printf("a_issuer = %s, b_subject = %s\n",
		X509_NAME_oneline(a_issuer, NULL, 0), X509_NAME_oneline(b_subject, NULL, 0));
#endif
	return X509_NAME_cmp(a_issuer, b_subject) == 0;
}

inline X509* find_issuer_by_name(STACK_OF(X509)* sk, X509* x) {
	int i;
	X509* issuer = NULL, * rv = NULL;
	
	for (i = 0; i < sk_X509_num(sk); i++) {
		issuer = sk_X509_value(sk, i);
		if (check_issued(x, issuer)) {
			// TODO: check flag and check time
			return issuer;
		}
	}
	return rv;
}


int validate_cert_like_win(MY_STORAGE_CTX* ctx, EVP_PKEY **out_key) {
	int num, ret = 0;
	X509* x = NULL;					// ��ǰ֤��
	int x_type = TYPE_EXPLICIT;		// ��ǰ֤������
	X509* xtmp = NULL;				// ��һ֤��
	int xtmp_type = TYPE_EXPLICIT;	// ��һ֤������

	int i = 0;
	EVP_PKEY* vk = NULL;		// ������֤ǩ���Ĺ�Կ
	EC_KEY* vkec = NULL;

	STACK_OF(X509) *chain = MY_STORAGE_CTX_get0_chain(ctx);
	STACK_OF(X509)* untrusted = MY_STORAGE_CTX_get0_untrusted(ctx);
	X509 *cert = MY_STORAGE_CTX_get0_cert(ctx);		// �ն�ʵ��֤��

	
#ifdef VALIDATE_PRNIT_STEP
	X509_NAME* print_sub_name = NULL;
	X509_NAME* print_iss_name = NULL;
	int print_cnt = 0;
	printf("\n## Step 0: Init.\n");
#endif
	
	if (!(chain = sk_X509_new_null())) {
		goto ERR;
	}

	// ���ն�֤��ѹ��֤������
	if (!sk_X509_push(chain, cert)) {
		goto ERR;
	}

	if (!(num = sk_X509_num(chain))) {
		goto ERR;
	}
#ifdef VALIDATE_PRNIT_STEP
	print_sub_name = X509_get_subject_name(cert);
	print_iss_name = X509_get_issuer_name(cert);
	printf("Add cert(%d) into the chain (subject = [%s], issuer = [%s])\n", ++print_cnt, 
		X509_NAME_oneline(print_sub_name, NULL, 0), 
		X509_NAME_oneline(print_iss_name, NULL, 0));
#endif

	x = sk_X509_value(chain, num - 1);

	// Step 1: ����֤����
#ifdef VALIDATE_PRNIT_STEP
	printf("\n## Step 1: Build the certificate chain.\n");
#endif

	// �ӷ��������������ϲ���֤��

	for (;;) {
		if (get_cert_mode(x) == MODE_ROOT) {
			break;
		}
		if (!untrusted) {
			break;
		}
		if (!(xtmp = find_issuer_by_name(untrusted, x))) {
			break;
		}
		sk_X509_push(chain, xtmp);
#ifdef VALIDATE_PRNIT_STEP
		print_sub_name = X509_get_subject_name(xtmp);
		print_iss_name = X509_get_issuer_name(xtmp);
		printf("Add cert(%d) into the chain (subject = [%s], issuer = [%s])\n", ++print_cnt,
			X509_NAME_oneline(print_sub_name, NULL, 0),
			X509_NAME_oneline(print_iss_name, NULL, 0));
#endif
		x = xtmp;
	}
#ifdef VALIDATE_PRNIT_STEP
	printf("Find %d certs.\n", print_cnt);
#endif

	// Step 2: �ж�����ê
#ifdef VALIDATE_PRNIT_STEP
	printf("\n## Step 2: Check the trust anchor.\n");
#endif

	// �����CA֤�飬ֱ�ӱȽϣ����ֻ���ն�֤�飬����������������CA֤��
	if (!(num = sk_X509_num(chain))) {
		goto ERR;
	}
	x = sk_X509_value(chain, num - 1); // ��ö���֤��
	
	ret = MY_STORAGE_CTX_is_cert_matched(ctx, x, chain, &vk); // ͬʱ��ȡ����֤��Ĺ�Կֵ
	if (ret < 1 || !vk) goto ERR;

	if (get_cert_type(x) == TYPE_IMPLICIT) {
		if (!(vkec = EVP_PKEY_get0_EC_KEY(vk))) {
			goto ERR;
		}
	}

	// step 3: ��֤֤����������ê�Ĳ��ٿ���
#ifdef VALIDATE_PRNIT_STEP
	printf("\n## Step 3: Verifiy the chain's signatures.\n");
#endif
	if (!(num = sk_X509_num(chain))) {
		goto ERR;
	}
	x = sk_X509_value(chain, num - 1);

	for (i = num - 2; i >= 0; i--) {
#ifdef DEBUG_VER_SIG
		ecqv_print_pkey(stdout, "VK", "none", vk, bn_ctx);
		ecqv_print_cert(stdout, "cert", xtmp);
#endif
		xtmp = sk_X509_value(chain, i);
#ifdef VALIDATE_PRNIT_STEP
		printf("Check the signature at cert(%d).\n", i + 1);
#endif
		// ��ȡ�ϲ㹫Կ
		xtmp_type = get_cert_type(xtmp);
		if (xtmp_type == TYPE_EXPLICIT) {
			// ��֤xtmpǩ������ȡ��Կ
			ret = X509_verify(xtmp, vk);
			if (ret == -1) {
				MY_STORAGE_CTX_set_error(ctx, X509_V_ERR_NO_ISSUER_PUBLIC_KEY);
#ifdef VALIDATE_PRNIT_STEP
				printf("ERR: Unknown!\n");
#endif
				goto ERR;
			}
			else if (ret == 0) {
				MY_STORAGE_CTX_set_error(ctx, X509_V_ERR_CERT_SIGNATURE_FAILURE);
#ifdef VALIDATE_PRNIT_STEP
				printf("ERR: The signature cannot be accepted!\n");
#endif
				goto ERR;
			}
			x = xtmp;
			if (!(vk = X509_get0_pubkey(x))) {
				MY_STORAGE_CTX_set_error(ctx, X509_V_ERR_NO_ISSUER_PUBLIC_KEY);
#ifdef VALIDATE_PRNIT_STEP
				printf("ERR: Can not get the PubKey of the %dth certificate!\n", i + 1);
#endif
				goto ERR;
			}
		}
		else { // xtmp_type == TYPE_IMPLICIT

			// �Ƚϻ��㲢��ȡ��Կ
			if (!ecqv_cert_pk_extract(xtmp, vkec, &vkec)) {
				if (ecqv_last_error() == ECQV_ERR_GROUP_INCON) {
					MY_STORAGE_CTX_set_error(ctx, ECQV_ERR_GROUP_INCON);
#ifdef VALIDATE_PRNIT_STEP
					printf("ERR: Implici Cert %d: Group inconsistent!\n", i + 1);
#endif
				}
				goto ERR;
			}
			x = xtmp;
			// ��ʱ vkec��x�Ĺ�Կ
			//if (!EVP_PKEY_set1_EC_KEY(vk, vkec)) {
			//	goto ERR;
			//}
		}
#ifdef DEBUG_VER_SIG
		ecqv_print_pkey(stdout, "VK", "none", vk, bn_ctx);
		ecqv_print_cert(stdout, "cert", xtmp);
#endif
		x_type = xtmp_type;
		
	}
	// ��֤����

#ifdef VALIDATE_PRNIT_STEP
	if (x_type == TYPE_EXPLICIT) {
		printf("\nValidation success, the certificate can be accepted.\n");
	}
	else {
		printf("\nReconstruction success, you need to further verify with the public key.\n");
	}
#endif
#ifdef VALIDATE_PRNIT_STEP
	ecqv_print_pkey(stdout, "VK", "none", vk, bn_ctx);
#endif
	if (out_key) *out_key = vk;

	return x_type == TYPE_EXPLICIT ? 1 : 2;
ERR:
	if (chain) {
		sk_X509_free(chain);
		chain = NULL;
	}
FALSE: 
#ifdef VALIDATE_PRNIT_STEP
	printf("\nValidation failed, the certificate will be rejected.\n");
#endif
	return 0;
}


// TODO: Ŀǰ��֧��EC_KEY
bool cmp_pubkey(EVP_PKEY* key1, EVP_PKEY* key2) {
	if (key1 == key2) return true;
	if (!key1 || !key2) return false;

	return EVP_PKEY_cmp(key1, key2) == 0;
}

bool cmp_pubkey(EC_KEY* ec_key1, EVP_PKEY* key2) {
	if (!ec_key1 || !key2) return false;
	EC_KEY* ec_key2 = EVP_PKEY_get0_EC_KEY(key2);
	const EC_POINT* P1 = EC_KEY_get0_public_key(ec_key1);
	const EC_POINT* P2 = EC_KEY_get0_public_key(ec_key2);
	const EC_GROUP* g1 = EC_KEY_get0_group(ec_key1);
	const EC_GROUP* g2 = EC_KEY_get0_group(ec_key2);

	if (P1 == P2) return true;
	if (!P1 || !P2) return false;
	if (!g1 || !g2 || EC_GROUP_cmp(g1, g2, bn_ctx) != 0) return false;
	int ret = EC_POINT_cmp(g1, P1, P2, bn_ctx);
	
	return ret == 0;
}