#include "enclave_t.h"

#include "sgx_trts.h"

void ecall_add_user(struct user *u) {

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