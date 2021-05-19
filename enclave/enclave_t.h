#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tcrypto.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _user
#define _user
typedef struct user {
	char* username;
	char* password;
} user;
#endif

void ecall_add_user(struct user* t);

sgx_status_t SGX_CDECL my_print(uint8_t* v);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
