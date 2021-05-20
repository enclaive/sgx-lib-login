#include <cstdlib>
#include <string.h>

#include "enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tprotected_fs.h"

#define USER_FILENAME "secret_file.txt"
#define MAX_STRING 255
#define MAX_FILE_SIZE 4 * 1024

void ecall_add_user(struct user* u) {
	// Open encrypted file
	SGX_FILE* fd = sgx_fopen_auto_key(USER_FILENAME, "a+b");
	if (!fd) {
		my_print("Couldn't open the encrypted file");
		return;
	}

	if (!ecall_validate_login(u)) {
		// Hash the password
		sgx_sha256_hash_t pw_hash;
		sgx_sha256_msg((uint8_t*)u->password, sizeof(u->password), &pw_hash);

		// Allocate memory for the entry
		size_t buff_size = strlen(u->username) + SGX_SHA256_HASH_SIZE + 2;
		char* buff = (char*)std::malloc(buff_size);

		// Concatenate the entry
		strncat(buff, u->username, strlen(u->username));
		strncat(buff, ";", sizeof(char));
		strncat(buff, (char*)pw_hash, SGX_SHA256_HASH_SIZE);
		buff[buff_size - 1] = '\n';

		// Write the entry into the encrypted file
		sgx_fwrite(buff, sizeof(char), buff_size, fd);
		sgx_fclose(fd);
		my_print("User created");
		my_print(buff);
		free(buff);
	}
}

int ecall_validate_login(struct user* u) {
	// Open encrypted file
	SGX_FILE* fd = sgx_fopen_auto_key(USER_FILENAME, "rb");
	if (!fd) {
		my_print("Couldn't open the encrypted file");
		return false;
	}
	// Hash the password
	sgx_sha256_hash_t pw_hash;
	sgx_sha256_msg((uint8_t*)u->password, sizeof(u->password), &pw_hash);

	size_t buff_size = MAX_FILE_SIZE;
	char* buffer = (char*)malloc(sizeof(char) * buff_size);
	char new_line = '\n';
	bool found_user = false;

	while (sgx_fread(buffer, sizeof(char), buff_size, fd) != 0 && !found_user)
		my_print("LOOP");
	char* token = strtok(buffer, "\n");
	while (token && !found_user) {
		my_print("Token:");
		my_print(token);
		size_t token_compare_size = sizeof(char) * (strlen(u->username) + SGX_SHA256_HASH_SIZE + 1);
		char* token_compare = (char*)malloc(token_compare_size);
		strncat(token_compare, u->username, sizeof(char) * strlen(u->username));
		strncat(token_compare, ";", sizeof(char));
		strncat(token_compare, (char*)pw_hash, SGX_SHA256_HASH_SIZE);

		my_print(token_compare);

		if (strcmp(token, token_compare) == 0) {
			found_user = true;
		}
		token = strtok(NULL, "\n");
	}
	free(buffer);
	return found_user;
}

char* ecall_hash_password(const char* password) {
	// Hash the password
	sgx_sha256_hash_t pw_hash;
	sgx_sha256_msg((uint8_t*)password, sizeof(char) * strlen(password), &pw_hash);
	return (char*)pw_hash;
}

void e_call_print_all_user() {
	// Open encrypted file
	SGX_FILE* fd = sgx_fopen_auto_key(USER_FILENAME, "a+");
	if (!fd) {
		my_print("Couldn't open the encrypted file");
		return;
	}
	size_t buff_size = MAX_STRING;
	char* buff = (char*)malloc(buff_size);
	while (sgx_fread(buff, sizeof(char), buff_size, fd) != 0) {
		my_print(buff);
	}
	free(buff);
}