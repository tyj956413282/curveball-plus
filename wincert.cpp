/*
#pragma comment(lib, "crypt32.lib")

#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#include <vector>
#include <tchar.h>
#include <algorithm>
#define DEBUG
/**
*  Build a certificate chain context 
*		starting from an end-entity cert and going back
*		(if possible) to a trusted root certificte.
/
BOOL MyCertGetCertificateChain(
	HCERTCHAINENGINE		hChainEngine,		// 
	PCCERT_CONTEXT			pCertContext,		// the end-entity certificate
	HCERTSTORE				hAdditionalStore,	// additional store to search for supporting certificates
	PCCERT_CHAIN_CONTEXT* ppChainContext		// [out]
) {
	// CCertChainEngine::GetChainContext() function
	return TRUE;
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
		return false;
	}
	_name = new TCHAR[_len];
	if (_name == NULL) {
		printf("new TCHAR failed!\n");
		return false;
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
		delete name;
		return false;
	}
	if (name) *name = _name;
	if (name_len) *name_len = _len;
	return true;
}

bool get_issuer_name(PCCERT_CONTEXT cert, LPTSTR* name, DWORD* name_len) {
	if (name == NULL || name_len == NULL) return false;
	LPTSTR _name;
	DWORD _len;
	_len = CertGetNameString(
		cert,
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		CERT_NAME_ISSUER_FLAG, // issuer name
		NULL,
		NULL,
		0
	);
	if (_len == 0) {
		printf("CertGetNameString failed!\n");
		return false;
	}
	_name = new TCHAR[_len];
	if (_name == NULL) {
		printf("new TCHAR failed!\n");
		return false;
	}
	// Get subject name
	if (!(CertGetNameString(
		cert,
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		CERT_NAME_ISSUER_FLAG,
		NULL,
		_name,
		_len
	))) {
		printf("CertGetNameString failed.\n");
		delete name;
		return false;
	}
	if (name) *name = _name;
	if (name_len) *name_len = _len;
	return true;
}

bool print_subject_name(PCCERT_CONTEXT cert) {
	LPTSTR name;
	DWORD name_len;

	get_subject_name(cert, &name, &name_len);

	_tprintf(_T("%s\n"), name);
	delete name;
	return true;
}

bool print_issuer_name(PCCERT_CONTEXT cert) {
	LPTSTR name;
	DWORD name_len;

	get_issuer_name(cert, &name, &name_len);

	_tprintf(_T("%s\n"), name);
	delete name;
	return true;
}

bool is_self_signed(PCCERT_CONTEXT pc_cert) {
	if (pc_cert == NULL) return false;

	LPTSTR subject_name, issuer_name;
	DWORD subject_len, issuer_len;
	get_subject_name(pc_cert, &subject_name, &subject_len);
	get_issuer_name(pc_cert, &issuer_name, &issuer_len);

	return lstrcmp(
		subject_name, 
		issuer_name
	) == 0;
}


bool build_chain(PCCERT_CONTEXT end, HCERTSTORE store, PCCERT_SIMPLE_CHAIN *pc_chain) {
	if (end == NULL || pc_chain == NULL) return false;
	
	std::vector<CERT_CONTEXT> chain;
	chain.push_back(*end);

	PCCERT_CONTEXT cur = end, next;
	bool isEnd = false;
	while (!is_self_signed(cur)) {
		next = CertFindCertificateInStore(
			store, 
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
			0, 
			CERT_FIND_ISSUER_OF, 
			cur, 
			NULL
		);
		if (next == NULL) {
			printf("not found\n");  break;
		}
		chain.push_back(*next);
		cur = next;
	}

	printf("chain length = %zd\n", chain.size());
	for (int i = 0; i < chain.size(); i++) {
		printf("\t");
		print_subject_name(&chain[i]);
	}
	//return true;
	

	PCERT_SIMPLE_CHAIN p_chain;
	p_chain = new CERT_SIMPLE_CHAIN;

	p_chain->cbSize = sizeof(p_chain);
	*pc_chain = p_chain;
	return true;
ERR:
	delete p_chain;
	return false;
}

// name: maybe "My" or "Root"
bool open_system_store(const void* name, HCERTSTORE *phstore) {
	if (!phstore) return false;
	if (!(*phstore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		name
	))) {
		printf("An error occured during creation of the system store!\n");
		printf("Error code is 0x%08X\n", GetLastError());
		return false;
	}
#ifdef DEBUG
	printf("The system store was created successfully.\n");
#endif
	return true;
}

bool open_collection_store(HCERTSTORE* phstore) {
	if (!phstore) return false;
	if (!(*phstore = CertOpenStore(
		CERT_STORE_PROV_COLLECTION,
		0,
		NULL,
		0,
		NULL
	))) {
		printf("An error occured during creation of the collection store!\n");
		printf("Error code is 0x%08X\n", GetLastError());
		return false;
	}
#ifdef DEBUG
	printf("The collection store was created successfully.\n");
#endif
	return true;
}

bool close_store(HCERTSTORE phstore) {
	if (phstore == NULL) {
		return false;
	}
	CertCloseStore(phstore, CERT_CLOSE_STORE_CHECK_FLAG);
	return true;
}

bool add_store(HCERTSTORE col_store, HCERTSTORE store) {
	if (!CertAddStoreToCollection(
		col_store,
		store,
		CERT_PHYSICAL_STORE_ADD_ENABLE_FLAG,
		1
	)) {
		return false;
	}
#ifdef DEBUG
	printf("add_store success!\n");
#endif
	return true;
}

int oldmain() {
	HCERTSTORE hMySysStore, hCASysStore, hRootSysStore, hColStore;
	if (!open_system_store(L"My", &hMySysStore) ||
		!open_system_store(L"CA", &hCASysStore) ||
		!open_system_store(L"Root", &hRootSysStore) ||
		!open_collection_store(&hColStore)
	) {
		exit(1);
	}
	add_store(hColStore, hCASysStore);
	add_store(hColStore, hRootSysStore);

	std::vector<CERT_CONTEXT> cert_vec;
	PCCERT_CONTEXT cert = NULL;
	// 遍历证书存储结构，查看所有证书内容
	do {
		cert = CertFindCertificateInStore(
			hMySysStore,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
			0, 
			CERT_FIND_ANY, // 未使用搜索条件
			NULL, 
			cert
			);
		if (cert != NULL) {
			cert_vec.push_back(*cert);
			// print_subject_name(cert);
		}
	} while (cert != NULL);
	
	printf("find %d certificates in the system store! (the last code is 0x%08X)\n", 
		cert_vec.size(), GetLastError());

	for (int i = 0; i < cert_vec.size(); i++) {
		printf("Cert No.%d: ", i + 1);
		// Get subject name size
		print_subject_name(&cert_vec[i]);
		PCCERT_SIMPLE_CHAIN pc_chain;
		build_chain(&cert_vec[i], hColStore, &pc_chain);
	}

	close_store(hRootSysStore);
	close_store(hMySysStore);
	
	return 0;
}
*/