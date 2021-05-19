#include <cstdlib>
#include <fstream>

#include "enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"

void ecall_add_user(struct user *u) {
	sgx_sha256_hash_t hash;
	sgx_sha256_msg((uint8_t*)u->username, sizeof(u->username), &hash);
	my_print(hash);
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

struct user* get_user(char* user) {
	//std::fstream file("userdb.csv", std::ios::in);
}