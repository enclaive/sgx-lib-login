#include <stdio.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <tchar.h>
#include "sgx_urts.h"
#include "enclave_u.h"
#define ENCLAVE_FILE _T("enclave.signed.dll")
#define MAX_BUF_LEN 100
#define MAX_STRING 255
#define MAX_USER 255

void my_print(uint8_t* v) {
    printf("%s", v);
}

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
    /*auto user_list = ocall_read_from_file((char*)"test.txt");
    size_t size = (sizeof(user_list[0]) / sizeof(user_list));

    for (size_t i = 0; i < size; ++i) {
        std::cout << "name: " << user_list[i].username << "\npassword: " << user_list[i].password << std::endl;
    }*/

    user usr = {(char*)"Foo", (char*)"Baeererer"};
    ecall_add_user(eid, &usr);
    
    // Destroy the enclave when all Enclave calls finished.
    if (SGX_SUCCESS != sgx_destroy_enclave(eid))
        return -1;
    return 0;
}