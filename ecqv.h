#ifndef __ECQV_H
#define __ECQV_H

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

/**
*  This file implement the ECQV procedure with CryptoAPI,
*  Note that the certificate is coded as X.509 without signatures in this file
*/

typedef X509 ECQV_CERT;

#define TYPE_EXPLICIT 1
#define TYPE_IMPLICIT 2
#define TYPE_UNKNOWN 0
#define MODE_USER 1
#define MODE_ROOT 2
#define MODE_UNKNOWN 0

// 判断显式证书还是隐式证书：通过有无签名值
int get_cert_type(X509* cert);
// 判断证书是否是自签名证书：通过比较主体信息与签发者信息
int get_cert_mode(const X509* cert);

struct ECQV_CERT_INFO {
	int type;
	const char *subject_name;
	X509_NAME *issuer;
	time_t notBefore;
	long days;
	int serial;
	int key_usage;
	/*KeyUsage :: = BIT STRING{
		   digitalSignature(0),
		   nonRepudiation(1), 
		   keyEncipherment(2),
		   dataEncipherment(3),
		   keyAgreement(4),
		   keyCertSign(5),
		   cRLSign(6),
		   encipherOnly(7),
		   decipherOnly(8) }
	*/
};

bool ecqv_init();
bool ecqv_uninit();

// 用户操作：生成公私钥种子
bool ecqv_cert_request(
	const EC_GROUP* group, 
	EC_KEY** key
);

// CA操作：生成用户隐式证书，获得私钥重构值 （根证书：ca_key仅存储group）
bool ecqv_cert_generate(
	const EC_KEY* req,	  // 公钥种子
	const EC_KEY* ca_key, // CA公私钥（包含group）
	ECQV_CERT_INFO* info,
	ECQV_CERT** cert,     // 证书
	BIGNUM** pri_recon    // 私钥重构值
);

// 用户操作：提取最终公私钥
bool ecqv_cert_reception(
	ECQV_CERT* cert,		// 用户的隐式证书
	const EC_KEY* ca_key,		// CA的最终公钥
	const BIGNUM* pri_recon,	// 用户收到的私钥重构值
	const BIGNUM* pri_seed,		// 用户持有的私钥种子
	EC_KEY** final_key
);

// 验证者操作：提取最终公钥
bool ecqv_cert_pk_extract(
	ECQV_CERT *cert, 
	const EC_KEY* ca_key,
	EC_KEY** final_pubkey
);

bool make_cert(
	ECQV_CERT_INFO *info,		// 证书内容
	EC_KEY*Q,				// 用户公钥（或重构值）
	EC_KEY*ca_sk,			// CA私钥（如果是显式证书则需签名）
	X509 **cert						// 生成的证书
);
bool ecc_keygen(const EC_GROUP* group, EC_KEY** key);

void ecqv_print_last_error(char *msg = nullptr);
bool ecqv_print_key(FILE* logfile, const char* label1l, const char *label2, const EC_KEY* key, BN_CTX* ctx);
bool ecqv_print_pkey(FILE* logfile, const char* label1, const char* label2, EVP_PKEY* pkey, BN_CTX* ctx);
bool ecqv_print_point(FILE* logfile, const char* label, const EC_POINT* point, const EC_GROUP* group, BN_CTX* ctx);
bool ecqv_print_bn(FILE* logfile, const char* label, const BIGNUM* bn);
bool ecqv_print_cert(FILE* logfile, const char* label, X509* cert);

int ecqv_last_error();


#define ECQV_SUCCESS			0x00000000
#define ECQV_ERR_NULL_POINTER	0x00000001
#define ECQV_ERR_RAND			0x00000200
#define ECQV_ERR_ADD			0x00000201
#define ECQV_ERR_MUL			0x00000202
#define ECQV_ERR_NOGROUP		0x00000203
#define ECQV_ERR_DUP			0x00000204
#define ECQV_ERR_EXTRACT		0x00000205
#define ECQV_ERR_NEW			0x00000100
#define ECQV_ERR_SIG			0x00000300
#define ECQV_ERR_HASH			0x00000310
#define ECQV_ERR_HASH_INIT		0x00000311
#define ECQV_ERR_HASH_UPDATE	0x00000312
#define ECQV_ERR_HASH_FINAL		0x00000313
#define ECQV_EER_I2D			0x00000401
#define ECQV_ERR_D2I			0x00000402
#define ECQV_ERR_BIN2BN			0x00000403
#define ECQV_ERR_NO_PRIV		0x00000501
#define ECQV_ERR_NO_PUB			0x00000502
#define ECQV_ERR_GROUP_INCON	0x00000503
#define ECQV_ERR_EXT			0x00000601
#define ECQV_ERR_KEY_USAGE		0x00000602
#define ECQV_ERR_ASN1_BITSTR	0x00000603
#define ECQV_ERR_UNKNOWN		0xFFFFFFFF

#endif