#include <stdio.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <tchar.h>
#include "sgx_urts.h"
#include "enclave_u.h"
#define ENCLAVE_FILE _T("enclave.signed.dll")
#define MAX_BUF_LEN 100
#define MAX_STRING 255
#define MAX_USER 255

void my_print(char* v) {
	printf("%s\n", v);
}

int main()
{
	sgx_enclave_id_t eid;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;

	// Create the Enclave with above launch token.
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("App: error %#x, failed to create enclave.\n", ret);
		return -1;
	}
	int add_user_ret = 0;
	user usr = { (char*)"Foo22", (char*)"Baeereddr" };
	ecall_add_user(eid, &add_user_ret , &usr);
	
	switch (add_user_ret) {
	case 0: 
		printf("User added successfully\n");
		break;
	case 1:
		printf("User already exists\n");
		break;
	default:
		printf("An error occured while adding the user\n");
		break;
	}

	printf("Start validating\n");
	int ret_val = 0;
	if (ecall_validate_login(eid, &ret_val, &usr) == SGX_SUCCESS && ret_val == 1) {
		printf("User found");
	}

	//char* hash = (char*)malloc(sizeof(char)*SGX_SHA256_HASH_SIZE+2);
	//ecall_hash_password(eid, &hash, "TEstuser");
	//memset(hash, '1', SGX_SHA256_HASH_SIZE);
	//free(hash);
	//e_call_print_all_user(eid);

	// Destroy the enclave when all Enclave calls finished.
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	return 0;
}