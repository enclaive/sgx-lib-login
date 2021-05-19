#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecall_add_user_t {
	struct user* ms_t;
} ms_ecall_add_user_t;

typedef struct ms_my_print_t {
	uint8_t* ms_v;
} ms_my_print_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_ecall_add_user(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_add_user_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_add_user_t* ms = SGX_CAST(ms_ecall_add_user_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	struct user* _tmp_t = ms->ms_t;
	size_t _len_t = sizeof(struct user);
	struct user* _in_t = NULL;

	CHECK_UNIQUE_POINTER(_tmp_t, _len_t);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_t != NULL && _len_t != 0) {
		_in_t = (struct user*)malloc(_len_t);
		if (_in_t == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_t, _len_t, _tmp_t, _len_t)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_add_user(_in_t);

err:
	if (_in_t) free(_in_t);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_ecall_add_user, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][1];
} g_dyn_entry_table = {
	1,
	{
		{0, },
	}
};


sgx_status_t SGX_CDECL my_print(uint8_t* v)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_v = SGX_SHA256_HASH_SIZE * sizeof(uint8_t);

	ms_my_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_my_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(v, _len_v);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (v != NULL) ? _len_v : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_my_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_my_print_t));
	ocalloc_size -= sizeof(ms_my_print_t);

	if (v != NULL) {
		ms->ms_v = (uint8_t*)__tmp;
		if (_len_v % sizeof(*v) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, v, _len_v)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_v);
		ocalloc_size -= _len_v;
	} else {
		ms->ms_v = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
