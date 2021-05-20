#include <cstdlib>
#include <string.h>

#include "enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tprotected_fs.h"

#define USER_FILENAME "secret_file.txt"
#define MAX_STRING 255
#define MAX_FILE_SIZE 4 * 1024

// Check if user exists
int user_exists(char* username) {
	my_print("Checking if user exists...");
	int ret = 0;

	// Open encrypted file
	SGX_FILE* fd = sgx_fopen_auto_key(USER_FILENAME, "r");
	if (!fd) {
		my_print("Couldn't open the encrypted file");
		return -1;
	}
	char* file_buff = (char*)malloc(MAX_FILE_SIZE);

	while (sgx_fread(file_buff, sizeof(char), MAX_FILE_SIZE, fd) && ret == 0) {
		char* token = strtok(file_buff, "\n");
		while (token && ret == 0) {
			size_t sep_id = strcspn(token, ";");

			// Compare size
			if (sep_id == strlen(username)) {
				if (strncmp(token, username, sep_id) == 0) {
					ret = 1;
				}
			}
			token = strtok(NULL, "\n");
		}
	}
	free(file_buff);
	sgx_fclose(fd);
	return ret;
}

int ecall_add_user(struct user* u) {
	my_print("Try to add user...");
	int ret;

	// Check if the user already exists
	int user_exists_ret = user_exists(u->username);
	if (user_exists_ret != 0) {
		ret = user_exists_ret;
		return user_exists_ret;
	}
	my_print("User do not exists");

	my_print("Hash the users password with sha256...");
	// Hash the password
	sgx_sha256_hash_t pw_hash;
	sgx_sha256_msg((uint8_t*)u->password, sizeof(u->password), &pw_hash);

	my_print("Open encrypted file...");
	// Open encrypted file
	SGX_FILE* fd = sgx_fopen_auto_key(USER_FILENAME, "a+b");
	if (!fd) {
		my_print("Couldn't open the encrypted file1");
		ret = -1;
		return -1;
	}

	my_print("Allocate memory for the file to be read...");
	// Allocate memory for the entry
	size_t buff_size = strlen(u->username) + SGX_SHA256_HASH_SIZE + 2;
	char* buff = (char*)std::malloc(buff_size);

	my_print("Generate user entry...");
	// Concatenate the entry
	strncat(buff, u->username, strlen(u->username));
	strncat(buff, ";", sizeof(char));
	strncat(buff, (char*)pw_hash, SGX_SHA256_HASH_SIZE);
	buff[buff_size - 1] = '\n';

	my_print("Write user entry to file...");
	// Write the entry into the encrypted file
	sgx_fwrite(buff, sizeof(char), buff_size, fd);
	my_print("User successfully created!");
	my_print("Close the filedescriptor...");
	sgx_fclose(fd);
	my_print("Free allocated memory...");
	free(buff);
	return 0;
}

int ecall_validate_login(struct user* u) {
	my_print("Validate user credentials...");
	my_print("Try to open encrypted file...");
	// Open encrypted file
	SGX_FILE* fd = sgx_fopen_auto_key(USER_FILENAME, "rb");
	if (!fd) {
		my_print("Couldn't open the encrypted file");
		return false;
	}

	my_print("Hash the users password...");
	// Hash the password
	sgx_sha256_hash_t pw_hash;
	sgx_sha256_msg((uint8_t*)u->password, sizeof(u->password), &pw_hash);

	my_print("Allocate memory for the encrypted file...");
	size_t buff_size = MAX_FILE_SIZE;
	char* buffer = (char*)malloc(buff_size);
	char new_line = '\n';
	bool found_user = false;

	my_print("Start reading from the encrypted file...");
	while (sgx_fread(buffer, sizeof(char), buff_size, fd) != 0 && !found_user) {
		char* token = strtok(buffer, "\n");
		while (token && !found_user) {
			my_print("Generate a token...");
			size_t token_compare_size = sizeof(char) * (strlen(u->username) + SGX_SHA256_HASH_SIZE + 1);
			char* token_compare = (char*)malloc(token_compare_size);
			strncat(token_compare, u->username, sizeof(char) * strlen(u->username));
			strncat(token_compare, ";", sizeof(char));
			strncat(token_compare, (char*)pw_hash, SGX_SHA256_HASH_SIZE);

			my_print("Compare the generated token with the token from the file...");
			if (strcmp(token, token_compare) == 0) {
				found_user = true;
			}
			//free(token_compare);
			token = strtok(NULL, "\n");
		}
		free(buffer);
		sgx_fclose(fd);
		return found_user;
	}
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
	sgx_fclose(fd);
}