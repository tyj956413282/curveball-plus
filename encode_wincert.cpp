#include "encode_wincert.h"

// Windows Headers
#include <windows.h>
#include <Wincrypt.h>
#include <tchar.h>

// STL Headers
#include <vector>

bool open_system_store(const void* name, HCERTSTORE* phstore) {
	if (!phstore) return false;
	if (!(*phstore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		name
	))) {
		goto ERR;
	}
	return true;
ERR:
	printf("An error occured during opening system store!\n");
	printf("Error code is 0x%08X\n", GetLastError());
	return false;
}

bool close_store(HCERTSTORE phstore) {
	if (phstore == NULL) {
		goto ERR;
	}
	if (!CertCloseStore(phstore, CERT_CLOSE_STORE_CHECK_FLAG)) {
		goto ERR;
	}
	return true;
ERR:	
	printf("An error occured during closing system store!\n");
	printf("Error code is 0x%08X\n", GetLastError());
	return false;
}

bool get_subject_name(PCCERT_CONTEXT cert, LPTSTR* name, DWORD* name_len) {
	if (name == NULL || name_len == NULL) return false;
	LPTSTR _name;
	DWORD _len;
	_len = CertGetNameString(
		cert,
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		0, // subject name
		NULL,
		NULL,
		0
	);
	if (_len == 0) {
		printf("CertGetNameString failed!\n");
		goto ERR;
	}
	_name = new TCHAR[_len];
	if (_name == NULL) {
		printf("new TCHAR failed!\n");
		goto ERR;
	}
	// Get subject name
	if (!(CertGetNameString(
		cert,
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		0,
		NULL,
		_name,
		_len
	))) {
		printf("CertGetNameString failed.\n");
		goto ERR;
	}
	if (name) *name = _name;
	if (name_len) *name_len = _len;
	return true;
ERR:
	if (name) delete name;
	return false;
}

bool print_subject_name(PCCERT_CONTEXT cert) {
	LPTSTR name;
	DWORD name_len;

	get_subject_name(cert, &name, &name_len);

	_tprintf(_T("%s\n"), name);
	delete name;
	return true;
}

const wchar_t* store_name[3] = { L"My", L"CA", L"Root" };
bool addWinLocalCert(X509_STORE* store, int add_whom) {

	HCERTSTORE WinStore = NULL;
	PCCERT_CONTEXT WinCert = NULL;
	X509* cert = NULL;
	std::vector<CERT_CONTEXT> cert_vec;

	if (!store) {
		goto ERR;
	}

	if (!open_system_store(store_name[add_whom], &WinStore)) {
		goto ERR;
	}

	do {
		WinCert = CertFindCertificateInStore(
			WinStore,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			0,
			CERT_FIND_ANY, // 未使用搜索条件
			NULL,
			WinCert
		);
		if (WinCert) {
			// cert_vec.push_back(*cert);
			print_subject_name(WinCert);
			if (!(cert = d2i_X509(
				NULL,
				(const unsigned char**)&WinCert->pbCertEncoded,
				WinCert->cbCertEncoded
			))) {
				goto ERR;
			}

			if (!X509_STORE_add_cert(store, cert)) {
				goto ERR;
			}

		}
	} while (WinCert);

	if (WinStore) close_store(WinStore);
	return true;
ERR:
	if (WinStore) close_store(WinStore);
	return false;
}
