#include <cstdlib>
#include <string.h>

#include "enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tprotected_fs.h"

#define USER_FILENAME "secret_file.csv"
#define MAX_STRING 255

void ecall_add_user(struct user *u) {
	// Open encrypted file
	SGX_FILE* fd = sgx_fopen_auto_key(USER_FILENAME, "a+");
	if (!fd) {
		my_print((uint8_t*)"Couldn't open the encrypted file");
		return;
	}
	// Hash the password
	sgx_sha256_hash_t pw_hash;
	sgx_sha256_msg((uint8_t*)u->password, sizeof(u->password), &pw_hash);

	// Allocate memory for the entry
	char* buff = (char*)std::malloc(sizeof(u->username) + sizeof(pw_hash) + 1);

	// Concatenate the entry
	strncat(buff, u->username, sizeof(u->username));
	strncat(buff, ";", sizeof(char));
	strncat(buff, (char*)pw_hash, sizeof(pw_hash));

	// Write the entry into the encrypted file
	sgx_fwrite(buff, sizeof(char), sizeof(buff)/sizeof(buff[0]), fd);
	sgx_fclose(fd);
	my_print((uint8_t*)"User created");
	my_print((uint8_t*)buff);
	free(buff);
}
void ecall_del_user(struct user *u) {

}
bool ecall_validate_login(struct user *u, size_t len) {

	return true;
}
char* ecall_hash_username(const char* username) {
	return NULL;
}
char* ecall_hash_password(const char* password) {
	return NULL;
}

void e_call_print_all_user() {
	// Open encrypted file
	SGX_FILE* fd = sgx_fopen_auto_key(USER_FILENAME, "a+");
	if (!fd) {
		my_print((uint8_t*)"Couldn't open the encrypted file");
		return;
	}
	char* buff = (char*)malloc(sizeof(char) * MAX_STRING);

	free(buff);
}