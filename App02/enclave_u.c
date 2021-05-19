#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_add_user_t {
	struct user* ms_t;
} ms_ecall_add_user_t;

typedef struct ms_my_print_t {
	uint8_t* ms_v;
} ms_my_print_t;

static sgx_status_t SGX_CDECL enclave_my_print(void* pms)
{
	ms_my_print_t* ms = SGX_CAST(ms_my_print_t*, pms);
	my_print(ms->ms_v);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[1];
} ocall_table_enclave = {
	1,
	{
		(void*)(uintptr_t)enclave_my_print,
	}
};

sgx_status_t ecall_add_user(sgx_enclave_id_t eid, struct user* t)
{
	sgx_status_t status;
	ms_ecall_add_user_t ms;
	ms.ms_t = t;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	return status;
}

