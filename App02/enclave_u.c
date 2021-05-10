#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_add_user_t {
	struct user* ms_t;
} ms_ecall_add_user_t;

static const struct {
	size_t nr_ocall;
	void * func_addr[1];
} ocall_table_enclave = {
	0,
	{ NULL },
};

sgx_status_t ecall_add_user(sgx_enclave_id_t eid, struct user* t)
{
	sgx_status_t status;
	ms_ecall_add_user_t ms;
	ms.ms_t = t;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	return status;
}

