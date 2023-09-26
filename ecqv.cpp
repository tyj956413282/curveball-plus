#define _CRT_SECURE_NO_WARNINGS 1
#include "ecqv.h"
#include <openssl/x509v3.h>
#ifdef __cplusplus
extern "C" {
#include <openssl/applink.c>
}
#endif

#define IMP_GEN_PRINT_P

int ecqv_error = ECQV_SUCCESS;
BN_CTX *bn_ctx = NULL;

int ecqv_last_error() {
	return ecqv_error;
}

// �ж���ʽ֤�黹����ʽ֤�飺ͨ������ǩ��ֵ
int get_cert_type(X509* cert) {
	if (!cert) {
		ecqv_error = ECQV_ERR_NULL_POINTER;
		return TYPE_UNKNOWN;
	}
	const ASN1_BIT_STRING* sig = NULL;
	const X509_ALGOR* sigAlg = NULL;
	int ret = X509_get_signature_info(cert, NULL, NULL, NULL, NULL);
	//X509_get0_signature(&sig, &sigAlg, cert);
	if (ret) return TYPE_EXPLICIT;
	return TYPE_IMPLICIT;
}

// // �ж�֤���Ƿ�����ǩ��֤�飺ͨ���Ƚ�������Ϣ��ǩ������Ϣ
int get_cert_mode(const X509* cert) {
	X509_NAME* subject = NULL, * issuer = NULL;
	int ret = 0;
	if (!cert ||
		!(subject = X509_get_subject_name(cert)) ||
		!(issuer = X509_get_issuer_name(cert))
	) {
		ecqv_error = ECQV_ERR_EXTRACT;
		return MODE_UNKNOWN;
	}
	
	ret = X509_NAME_cmp(subject, issuer);
	if (ret == -2) return MODE_UNKNOWN;
	if (ret == 0) return MODE_ROOT;
	return MODE_USER;
	
}

const char* cert_type_str[3] = { "error_type", "explicit", "implicit" };
const char* cert_mode_str[3] = { "error_mode", "user/interCA", "root" };
bool ecqv_print_cert(FILE* logfile, const char* label, X509* cert) {
	int type = 0, mode = 0;
	BIO* b = NULL;

	if (!logfile) logfile = stdout;
	if (!cert) {
		ecqv_error = ECQV_ERR_NULL_POINTER;
		goto ERR;
	}

	type = get_cert_type(cert);
	mode = get_cert_mode(cert);

	fprintf(logfile, "CERT (%s): %s, %s\n", label, cert_type_str[type], cert_mode_str[mode]);

	if (!(b = BIO_new(BIO_s_file()))) {
		ecqv_error = ECQV_ERR_NEW;
		goto ERR;
	}

	if (!BIO_set_fp(b, logfile, BIO_NOCLOSE)) {
		ecqv_error = ECQV_ERR_UNKNOWN;
		goto ERR;
	}

	if (!X509_print(b, cert)) {
		goto ERR;
	}

	// subject
	
	// issuer

	// timeBefore

	// timeAfter

	// pubKey

	// pubKeyRecon

	// signature (if explicit)

	if (b) BIO_free(b);
	return true;
ERR:
	if (b) BIO_free(b);
	return false;
}

void ecqv_print_last_error(const char *msg) {
	if (msg) printf("%s: 0x%08X (", msg, ecqv_error);
	switch (ecqv_error) {
	case ECQV_SUCCESS: 
		printf("SUCCESS!");
		break;
	case ECQV_ERR_NULL_POINTER:
		printf("NULL POINTER ERROR!");
		break;
	default:
		printf("UNKNOWN ERROR!");
		break;
	}
	printf(")\n");
}
bool ecqv_print_bn(FILE* logfile, const char* label, const BIGNUM* bn)
{
	char* str = NULL;

	if (!logfile) logfile = stdout;
	if (!bn) {
		goto ERR;
	}

	str = BN_bn2hex(bn);

	if (!str) {
		return false;
	}

	fprintf(logfile, "BIGNUM   (%s): %s\n", label, str);
	fflush(logfile);
	OPENSSL_free(str);
	return true;
ERR:	
	if (str) OPENSSL_free(str);
	return false;
}
bool ecqv_print_point(FILE* logfile, const char* label, const EC_POINT* point, const EC_GROUP* group, BN_CTX* ctx)
{
	char* str;

	if (!logfile) logfile = stdout;

	str = EC_POINT_point2hex(group, point,
		POINT_CONVERSION_UNCOMPRESSED, ctx);

	if (!str) {
		printf("Log: error converting point to hex.\n");
		return false;
	}

	fprintf(logfile, "EC_POINT (%s): %s\n", label, str);
	fflush(logfile);
	OPENSSL_free(str);
	return true;
}
bool ecqv_print_key(FILE* logfile, const char* label1, const char *label2, const EC_KEY* key, BN_CTX* ctx)
{
	char* str = NULL;
	const EC_POINT* point = NULL;
	const EC_GROUP* group = NULL;
	const BIGNUM* bn = NULL;
	if (!logfile) logfile = stdout;
	if (!key) return false;

	if (point = EC_KEY_get0_public_key(key)) {
		group = EC_KEY_get0_group(key);
		ecqv_print_point(logfile, label1, point, group, ctx);
	}

	if (bn = EC_KEY_get0_private_key(key)) {
		ecqv_print_bn(logfile, label2, bn);
	}
	return true;
}
bool ecqv_print_pkey(FILE* logfile, const char* label1, const char* label2, EVP_PKEY* pkey, BN_CTX* ctx)
{
	char* str = NULL;
	const EC_KEY* key = NULL;
	const EC_POINT* point = NULL;
	const EC_GROUP* group = NULL;
	const BIGNUM* bn = NULL;
	if (!logfile) logfile = stdout;
	if (!pkey) return false;
	if (!(key = EVP_PKEY_get0_EC_KEY(pkey))) return false;

	if (point = EC_KEY_get0_public_key(key)) {
		group = EC_KEY_get0_group(key);
		ecqv_print_point(logfile, label1, point, group, ctx);
	}

	if (bn = EC_KEY_get0_private_key(key)) {
		ecqv_print_bn(logfile, label2, bn);
	}
	return true;
}

bool ecqv_init() {
	bn_ctx = BN_CTX_new();
	
	return true;
}

bool ecqv_uninit() {
	if (bn_ctx) BN_CTX_free(bn_ctx);

	return true;
}

bool make_cert(
	ECQV_CERT_INFO* info,			// ֤������
	EC_KEY* Q,						// �û���Կ�����ع�ֵ��
	EC_KEY* ca_sk,			// CA˽Կ���������ʽ֤������ǩ����
	X509** cert						// ���ɵ�֤��
) {
	X509* c = NULL;
	X509_NAME* name = NULL;
	EVP_PKEY* pub = NULL;			// ֤��洢����Կ
	EVP_PKEY* pri = NULL;			// CA˽Կ
	BASIC_CONSTRAINTS* basic_con = NULL;	// ����Լ��
	ASN1_BIT_STRING* key_usage = NULL;
	X509_EXTENSION* ext = NULL;
	int key_usage_x = 0, i = 0;		// ��ʱ����

	if (!Q || !info) {
		ecqv_error = ECQV_ERR_NULL_POINTER;
		goto ERR;
	}
	if (info->type == TYPE_EXPLICIT && !ca_sk) {
		ecqv_error = ECQV_ERR_NULL_POINTER;
		goto ERR;
	}

	if (!(pub = EVP_PKEY_new())) {
		ecqv_error = ECQV_ERR_NEW;
		goto ERR;
	}
	if (!EVP_PKEY_set1_EC_KEY(pub, Q)) {
		ecqv_error = ECQV_ERR_UNKNOWN;
		goto ERR;
	}
	
	if ((cert == NULL) || (*cert == NULL)) {
		if (!(c = X509_new())) {
			ecqv_error = ECQV_ERR_NEW;
			goto ERR;
		}
	}
	else {
		c = *cert;
	}

	X509_set_version(c, 2); // VERSION 3
	ASN1_INTEGER_set(X509_get_serialNumber(c), info->serial);
	X509_time_adj(X509_get_notBefore(c), 0, &info->notBefore);
	X509_time_adj(X509_get_notAfter(c), info->days * 24 * 3600, &info->notBefore);
	X509_set_pubkey(c, pub);

	if (!(name = X509_get_subject_name(c))) {
		ecqv_error = ECQV_ERR_UNKNOWN;
		goto ERR;
	}
	if (!X509_NAME_add_entry_by_txt(
		name, "CN", MBSTRING_ASC, 
		(unsigned char*)info->subject_name, 
		-1, -1, 0
	)) {
		ecqv_error = ECQV_ERR_UNKNOWN;
		goto ERR;
	}

	if (!X509_set_issuer_name(c, info->issuer ? info->issuer : name)) {
		ecqv_error = ECQV_ERR_UNKNOWN;
		goto ERR;
	}
	if (!(basic_con = BASIC_CONSTRAINTS_new()) || 
		!(key_usage = ASN1_BIT_STRING_new())
	) {
		ecqv_error = ECQV_ERR_NEW;
		goto ERR;
	}

	basic_con->ca = 1; // is CA
	if (!X509_add1_ext_i2d(c, NID_basic_constraints, basic_con, 0, X509V3_ADD_DEFAULT)) {
		ecqv_error = ECQV_ERR_EXT;
		goto ERR;
	}

	key_usage_x = info->key_usage;
	for (i = 0; key_usage_x && i < 32; i++) {
		if (key_usage_x & 1) {
			if (!ASN1_BIT_STRING_set_bit(key_usage, i, 1)) {
				ecqv_error = ECQV_ERR_ASN1_BITSTR;
				goto ERR;
			}
		}
		key_usage_x >>= 1;
	}
	
	if (!X509_add1_ext_i2d(c, NID_key_usage, key_usage, 0, X509V3_ADD_DEFAULT)) {
		ecqv_error = ECQV_ERR_EXT;
		goto ERR;
	}

	if (info->type == TYPE_EXPLICIT) {
		if (!(pri = EVP_PKEY_new())) {
			ecqv_error = ECQV_ERR_NEW;
			goto ERR;
		}
		if (!EVP_PKEY_set1_EC_KEY(pri, ca_sk)) {
			ecqv_error = ECQV_ERR_UNKNOWN;
			goto ERR;
		}
		// ��ʽ֤����Ҫǩ��
		if (!X509_sign(c, pri, EVP_sha256())) {
			ecqv_error = ECQV_ERR_SIG;
			goto ERR;
		}
	}
	if (cert) *cert = c;
	EVP_PKEY_free(pub);
	EVP_PKEY_free(pri);
	ASN1_BIT_STRING_free(key_usage);
	return true;
ERR:
	if (pub) EVP_PKEY_free(pub);
	if (pri) EVP_PKEY_free(pri);
	if (((cert == NULL) || (*cert == NULL)) && c) X509_free(c);
	if (key_usage) ASN1_BIT_STRING_free(key_usage);
	return false;
}

bool ecc_keygen(const EC_GROUP* group, EC_KEY **key) {
	EC_KEY* k = EC_KEY_new();
	
	if (!key || !k) {
		ecqv_error = ECQV_ERR_NULL_POINTER;
		goto ERR;
	}

	if (!EC_KEY_set_group(k, group)) {
		ecqv_error = ECQV_ERR_UNKNOWN;
		goto ERR;
	}
	
	if (!EC_KEY_generate_key(k)) {
		ecqv_error = ECQV_ERR_RAND;
		goto ERR;
	}
	if (key) *key = k;
	return true;
ERR:
	if (k) EC_KEY_free(k);
	return false;
}

bool _ecqv_cert_hash(unsigned char* cert, size_t cert_len, BIGNUM** e) {
	EVP_MD_CTX* md_ctx = NULL;
	unsigned char md_value[EVP_MAX_MD_SIZE]; // ��Ž��
	unsigned int md_len;
	BIGNUM* hash = NULL;

	if (!cert) {
		ecqv_error = ECQV_ERR_NULL_POINTER;
		goto ERR;
	}

	// ���ش�
	if (!e || !*e) {
		if (!(hash = BN_new())) {
			ecqv_error = ECQV_ERR_NEW;
			goto ERR;
		}
	}
	else {
		hash = *e;
	}

	// Hash����
	if (!(md_ctx = EVP_MD_CTX_new())) {
		ecqv_error = ECQV_ERR_NEW;
		goto ERR;
	}
	if (!EVP_DigestInit(md_ctx, EVP_sha256())) {
		ecqv_error = ECQV_ERR_HASH_INIT;
		goto ERR;
	}
	if (!EVP_DigestUpdate(md_ctx, cert, cert_len)) {
		ecqv_error = ECQV_ERR_HASH_UPDATE;
		goto ERR;
	}
	if (!EVP_DigestFinal(md_ctx, md_value, &md_len)) {
		ecqv_error = ECQV_ERR_HASH_FINAL;
		goto ERR;
	}

	if (!BN_bin2bn(md_value, md_len, hash)) {
		ecqv_error = ECQV_ERR_BIN2BN;
		goto ERR;
	}

	if (e) *e = hash;
	return true;
ERR:
	if ((!e || !*e) && hash) BN_free(hash);
	return false;
}

#define DEBUG
bool _ecqv_cert_hash(ECQV_CERT* cert, BIGNUM** e) {


	unsigned char* cert_b = NULL; //������ɵĿͻ�֤��
	int cert_len;


	if (!cert) {
		ecqv_error = ECQV_ERR_NULL_POINTER;
		goto ERR;
	}
#ifdef ECQV_PRINT_CERT
	ecqv_print_cert(stdout, "test", cert);
#endif

	// ��֤��ת��Ϊ�ֽ�����
	if ((cert_len = i2d_X509(cert, &cert_b)) <= 0) {
		ecqv_error = ECQV_EER_I2D;
		goto ERR;
	}
#ifdef ECQV_PRINT_CERT
	for (int i = 0; i < cert_len; i++) {
		printf("%02x ", cert_b[i]);
	}
	printf("\n");
#endif
	return _ecqv_cert_hash(cert_b, cert_len, e);
ERR:
	return false;
}

// �û������ɹ�˽Կ�����ӣ�
bool ecqv_cert_request(
	const EC_GROUP* group, 
	EC_KEY** key
) {
	bool ret;
	if (!group || !key) {
		ecqv_error = ECQV_ERR_NULL_POINTER;
		goto ERR;
	}
	ret = ecc_keygen(group, key);
#ifdef PRINT
	ecqv_print_point(stdout, "Ku", );
#endif
	return ret;
ERR:
#ifdef DEBUG
	ecqv_print_last_error("ecqv_cert_request()");
#endif
	return false;
}

// CA������֤���˽Կ�ع�ֵ
bool ecqv_cert_generate(
	const EC_KEY* req,	  // ��Կ����
	const EC_KEY* ca_key, // CA��˽Կ������group��
	ECQV_CERT_INFO* info,
	ECQV_CERT** cert,     // ֤��
	BIGNUM** pri_recon    // ˽Կ�ع�ֵ
) {
	const EC_POINT* Ku = NULL;		// ��Կ����
	BIGNUM *r = NULL;				// ˽Կ�ع�ֵ
	EC_POINT* Q = NULL;				// ��Կ�ع�ֵ
	EC_KEY* Qec = NULL;				
	EC_KEY *key = NULL;				// CA��ʱ��Կ��
	const EC_POINT* Kca = NULL;		// CA��ʱ��Կ���еĹ�Կ
	const BIGNUM* kca = NULL;		// CA��ʱ��Կ���е�˽Կ
	BIGNUM* e = NULL;				// �û���ʽ֤���ϣֵ
	const EC_GROUP* group = NULL;	// ������ʹ�õ�ECC����������ca_key��
	const BIGNUM* order = NULL;		// ��������˽Կ���õ���ģ��
	const BIGNUM* dca = NULL;		// CA��˽Կ������ca_key��
	int mode = MODE_USER;			// MODE_ROOT: ��ǩ��֤�飻MODE_USER: ����ǩ��֤��
	int ret = 0;

	if (!info || !ca_key) {
		ecqv_error = ECQV_ERR_NULL_POINTER;
		goto ERR;
	}
	// ���û��pub key�����������ǩ��֤���������ʱKu��Ϊ���룩
	if (!EC_KEY_get0_public_key(ca_key)) {
		mode = MODE_ROOT;
	} // else mode = MODE_USER;
	if (mode == MODE_USER && !req) {
		ecqv_error = ECQV_ERR_NULL_POINTER;
		goto ERR;
	}
	if (!(group = EC_KEY_get0_group(ca_key)) ||
		!(order = EC_GROUP_get0_order(group))
	) {
		ecqv_error = ECQV_ERR_NOGROUP;
		goto ERR;
	}
	if (req) {
		if (!(Ku = EC_KEY_get0_public_key(req))) {
			ecqv_error = ECQV_ERR_UNKNOWN;
			goto ERR;
		}
	}
#ifdef ECQV_PRINT_STEP
	printf("Step (CA): generate the certificate and reconstruction value. Mode=[%d]\n", mode);
#endif

	// Kca = k'' * G, key = (k'', Kca)
	if (mode == MODE_ROOT && req) {
		if (!(key = EC_KEY_dup(req))) {
			goto ERR;
		}
	}
	else {
#ifdef ECQV_PRINT_STEP
		printf("- Generate CA's temporary key...\n");
#endif
		if (!ecc_keygen(group, &key) || !key) {
			goto ERR;
		}
	}
#ifdef ECQV_PRINT_STEP
	ecqv_print_key(stdout, "Kca", "kca", key, bn_ctx); 
#endif

	// ��ʼ����Կ�ع�ֵ Q = Kca ( + Ku )
#ifdef ECQV_PRINT_STEP
	printf("- Calculate public reconstrction value...\n");
#endif
	if (!(Kca = EC_KEY_get0_public_key(key))) {
		ecqv_error = ECQV_ERR_EXTRACT;
		goto ERR;
	}
	if (!(Q = EC_POINT_dup(Kca, group))) {
		ecqv_error = ECQV_ERR_DUP;
		goto ERR;
	}
	if (mode == MODE_USER) {
		// User: Q = Kca + Ku
		if (!EC_POINT_add(group, Q, Q, Ku, bn_ctx)) {
			ecqv_error = ECQV_ERR_ADD;
			goto ERR;
		}
	}
	if (!(Qec = EC_KEY_new())) {
		ecqv_error = ECQV_ERR_NEW;
		goto ERR;
	}
	if (!EC_KEY_set_group(Qec, group) || 
		!EC_KEY_set_public_key(Qec, Q)
	) {
		ecqv_error = ECQV_ERR_UNKNOWN;
		goto ERR;
	}
#ifdef ECQV_PRINT_STEP
	ecqv_print_point(stdout, "Qu", Q, group, bn_ctx);
#endif
	
	// ����֤�� cert
#ifdef ECQV_PRINT_STEP
	printf("- Make the implicit certificate...\n");
#endif
	if (!make_cert(info, Qec, NULL, cert)) {
		goto ERR;
	}

	// ���� e = Hash(cert)
#ifdef ECQV_PRINT_STEP
	printf("- Calculate the certificate's digest...\n");
#endif
	if (!_ecqv_cert_hash(*cert, &e)) {
		goto ERR;
	}
#ifdef ECQV_PRINT_STEP
	ecqv_print_bn(stdout, "e", e);
#endif

	// ��ʼ��˽Կ�ع�ֵ r = e * kca ( + dca )
#ifdef ECQV_PRINT_STEP
	printf("- Calculate private reconstruction value...\n");
#endif
	if (!(kca = EC_KEY_get0_private_key(key))) {
		ecqv_error = ECQV_ERR_EXTRACT;
		goto ERR;
	}
	if (!pri_recon || !*pri_recon) {
		if (!(r = BN_new())) {
			ecqv_error = ECQV_ERR_NEW;
			goto ERR;
		}
	}
	else {
		r = *pri_recon;
	}
	if (!BN_mod_mul(r, e, kca, order, bn_ctx)) {
		ecqv_error = ECQV_ERR_MUL;
		goto ERR;
	}
	if (mode == MODE_USER) {
		if (!(dca = EC_KEY_get0_private_key(ca_key))) {
			ecqv_error = ECQV_ERR_NO_PRIV;
			goto ERR;
		}
		if (!BN_mod_add(r, r, dca, order, bn_ctx)) {
			ecqv_error = ECQV_ERR_ADD;
			goto ERR;
		}
	}
#ifdef ECQV_PRINT_STEP
	ecqv_print_bn(stdout, "r", r);
#endif

	if (pri_recon) *pri_recon = r;
	if (Q) EC_POINT_free(Q);
	if (Qec) EC_KEY_free(Qec);
	return true;
ERR:
	if ((!pri_recon || !*pri_recon) && r) BN_free(r);
	if (Qec) EC_KEY_free(Qec);
	if (Q) EC_POINT_free(Q);
#ifdef DEBUG
	ecqv_print_last_error("ecqv_cert_generate()");
#endif
	return false;
}

// �û�����ȡ���չ�˽Կ�����ca_pkΪ��������֤�飩
bool ecqv_cert_reception(
	ECQV_CERT* cert,		// �û�����ʽ֤��
	const EC_KEY* ca_key,		// CA�����չ�Կ
	const BIGNUM* pri_recon,	// �û��յ���˽Կ�ع�ֵ
	const BIGNUM* pri_seed,		// �û����е�˽Կ����
	EC_KEY** final_key
) {
	const EC_POINT* Q = NULL;	// �û��Ĺ�Կ�ع�ֵ
	const EC_POINT* Pca = NULL;		// CA�Ĺ�Կֵ
	EC_POINT* P = NULL;			// �û������չ�Կֵ�������
	BIGNUM* d = NULL;			// �û�������˽Կֵ
	BIGNUM* e = NULL;			// ֤���ϣֵ
	BIGNUM* ek = NULL;			// �м�����ֵ = e * ku
	EVP_PKEY* Qevp = NULL;
	const EC_KEY* Qec = NULL;
	EC_KEY* key_ec = NULL;
	const EC_GROUP* group = NULL;			// ��������߲���
	const EC_GROUP* group_ca = NULL;		// CA֤���ECC����
	const BIGNUM* order = NULL;

	int mode = MODE_USER;
	if (!ca_key && !pri_seed) mode = MODE_ROOT;
	if (!pri_recon || !cert || (mode == MODE_USER && (!ca_key || !pri_seed))) {
		ecqv_error = ECQV_ERR_NULL_POINTER;
		goto ERR;
	}
#ifdef ECQV_PRINT_STEP
	printf("Step (U): retrieve the final key pair. Mode=[%d]\n", mode);
#endif

	// ��֤������ȡ��Կ����Բ���߲���
	if (!(Qevp = X509_get0_pubkey(cert)) ||
		!(Qec = EVP_PKEY_get0_EC_KEY(Qevp)) ||
		!(Q = EC_KEY_get0_public_key(Qec)) ||
		!(group = EC_KEY_get0_group(Qec)) || 
		!(order = EC_GROUP_get0_order(group))
		) {
		ecqv_error = ECQV_ERR_EXTRACT;
		goto ERR;
	}
	
	if (mode == MODE_USER) {
		if (!(group_ca = EC_KEY_get0_group(ca_key))) {
			ecqv_error = ECQV_ERR_EXTRACT;
			goto ERR;
		}
		// �Ƚ�U��CA��ѡ�õ���Բ���߲����Ƿ�һ��
		if (EC_GROUP_cmp(group_ca, group, bn_ctx) != 0) {
			ecqv_error = ECQV_ERR_GROUP_INCON;
			goto ERR;
		}
	}

	// ����֤���ϣֵ
#ifdef ECQV_PRINT_STEP
	printf("- Calculate the certificate's digest...\n");
#endif
	if (!_ecqv_cert_hash(cert, &e)) {
		goto ERR;
	}
#ifdef ECQV_PRINT_STEP
	ecqv_print_bn(stdout, "e", e);
#endif

	// ��������˽Կ d = r + (e * k)
#ifdef ECQV_PRINT_STEP
	printf("- Calculate the final's private key...\n");
#endif
	if (!(d = BN_dup(pri_recon))) {
		ecqv_error = ECQV_ERR_DUP;
		goto ERR;
	}
	if (mode == MODE_USER) {
		if (!(ek = BN_new())) {
			ecqv_error = ECQV_ERR_NEW;
			goto ERR;
		}
		if (!BN_mod_mul(ek, e, pri_seed, order, bn_ctx)) {
			ecqv_error = ECQV_ERR_MUL;
			goto ERR;
		}
		if (!BN_mod_add(d, d, ek, order, bn_ctx)) {
			ecqv_error = ECQV_ERR_ADD;
			goto ERR;
		}
	}

	// �������չ�Կ P = e * Q (+ Qca)
#ifdef ECQV_PRINT_STEP
	printf("- Calculate the final's public key...\n");
#endif
	if (!(P = EC_POINT_new(group))) {
		ecqv_error = ECQV_ERR_NEW;
		goto ERR;
	}
	if (!EC_POINT_mul(group, P, NULL, Q, e, bn_ctx)) {
		ecqv_error = ECQV_ERR_MUL;
		goto ERR;
	}
#ifdef ECQV_DEBUG
	ecqv_print_point(stdout, "eQ", P, group, bn_ctx);
#endif
	if (mode == MODE_USER) {
		if (!(Pca = EC_KEY_get0_public_key(ca_key))) {
			ecqv_error = ECQV_ERR_EXTRACT;
			goto ERR;
		}
		if (!EC_POINT_add(group, P, P, Pca, bn_ctx)) {
			ecqv_error = ECQV_ERR_ADD;
			goto ERR;
		}
	}

	// ��ϳ���Կ��
	if (!final_key || !*final_key) {
		if (!(key_ec = EC_KEY_new())) {
			ecqv_error = ECQV_ERR_NEW;
			goto ERR;
		}
	}
	else {
		key_ec = *final_key;
	}
	if (!EC_KEY_set_group(key_ec, group) || 
		!EC_KEY_set_public_key(key_ec, P) || 
		!EC_KEY_set_private_key(key_ec, d)
	) {
		ecqv_error = ECQV_ERR_UNKNOWN;
		goto ERR;
	}
#ifdef ECQV_PRINT_STEP
	ecqv_print_key(stdout, "P", "d", key_ec, bn_ctx);
	printf("check status: ");
	if (!EC_KEY_check_key(key_seed)) {
		printf("failed!\n");
	}
	else {
		printf("success!\n");
	}
#endif
	
	if (final_key) *final_key = key_ec;

	if (d) BN_free(d);
	if (P) EC_POINT_free(P);
	if (e) BN_free(e);
	if (ek) BN_free(ek);
	return true;
ERR:
	if ((!final_key || !*final_key) && key_ec) EC_KEY_free(key_ec);
	if (d) BN_free(d);
	if (P) EC_POINT_free(P);
	if (e) BN_free(e);
	if (ek) BN_free(ek);
	return false;
}

// ��֤�ߣ���ȡ���չ�Կ
bool ecqv_cert_pk_extract(
	ECQV_CERT* cert,
	const EC_KEY* ca_key,
	EC_KEY** final_pubkey
) {
	const EC_POINT* Q = NULL;	// �û��Ĺ�Կ�ع�ֵ
	const EC_POINT* Pca = NULL;		// CA�Ĺ�Կֵ
	EC_POINT* P = NULL;			// �û������չ�Կֵ�������
	BIGNUM* e = NULL;			// ֤���ϣֵ
	EVP_PKEY* Qevp = NULL;
	const EC_KEY* Qec = NULL;
	EC_KEY* key_ec = NULL;
	const EC_GROUP* group = NULL;			// ��������߲���

	int mode = MODE_USER;
	if (!ca_key) mode = MODE_ROOT;
	if (!cert) {
		ecqv_error = ECQV_ERR_NULL_POINTER;
		goto ERR;
	}

	// ��֤������ȡ��Կ����Բ���߲���
	if (!(Qevp = X509_get0_pubkey(cert)) ||
		!(Qec = EVP_PKEY_get0_EC_KEY(Qevp)) ||
		!(Q = EC_KEY_get0_public_key(Qec)) ||
		!(group = EC_KEY_get0_group(Qec))
		) {
		ecqv_error = ECQV_ERR_EXTRACT;
		goto ERR;
	}

	// ����֤���ϣֵ
	if (!_ecqv_cert_hash(cert, &e)) {
		goto ERR;
	}
#ifdef ECQV_DEBUG
	ecqv_print_bn(stdout, "e", e);
#endif

	// �������չ�Կ P = e * Q (+ Qca)
	if (!(P = EC_POINT_new(group))) {
		ecqv_error = ECQV_ERR_NEW;
		goto ERR;
	}
	if (!EC_POINT_mul(group, P, NULL, Q, e, bn_ctx)) {
		ecqv_error = ECQV_ERR_MUL;
		goto ERR;
	}
#ifdef ECQV_DEBUG
	ecqv_print_point(stdout, "eQ", P, group, bn_ctx);
#endif
	if (mode == MODE_USER) {
		if (!(Pca = EC_KEY_get0_public_key(ca_key))) {
			ecqv_error = ECQV_ERR_EXTRACT;
			goto ERR;
		}
		if (!EC_POINT_add(group, P, P, Pca, bn_ctx)) {
			ecqv_error = ECQV_ERR_ADD;
			goto ERR;
		}
	}

	// ��װ��ec��
	if (!final_pubkey || !*final_pubkey) {
		if (!(key_ec = EC_KEY_new())) {
			ecqv_error = ECQV_ERR_NEW;
			goto ERR;
		}
	}
	else {
		key_ec = *final_pubkey;
	}

	if (!EC_KEY_set_group(key_ec, group) ||
		!EC_KEY_set_public_key(key_ec, P)
	) {
		ecqv_error = ECQV_ERR_UNKNOWN;
		goto ERR;
	}

	if (final_pubkey) *final_pubkey = key_ec;

	if (P) EC_POINT_free(P);
	if (e) BN_free(e);
	return true;
ERR:
	if ((!final_pubkey || !*final_pubkey) && key_ec) EC_KEY_free(key_ec);
	if (P) EC_POINT_free(P);
	if (e) BN_free(e);
	return false;
}