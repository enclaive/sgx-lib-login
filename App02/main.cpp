#include <stdio.h>
#include <tchar.h>
#include "sgx_urts.h"
#include "enclave_u.h"
#define ENCLAVE_FILE _T("enclave.signed.dll")
#define MAX_BUF_LEN 100

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
    
    // Destroy the enclave when all Enclave calls finished.
    if (SGX_SUCCESS != sgx_destroy_enclave(eid))
        return -1;
    return 0;
}