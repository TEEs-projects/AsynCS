// Test: Call ecall_test_simple WITHOUT calling ecall_init first
#include <stdio.h>
#include "sgx_urts.h"
#include "Enclave_u.h"

sgx_enclave_id_t global_eid = 0;

int main() {
    sgx_status_t status;
    sgx_launch_token_t token = {0};
    int updated = 0;
    
    // Create enclave
    status = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (status != SGX_SUCCESS) {
        printf("Failed to create enclave: 0x%04x\n", status);
        return 1;
    }
    printf("Enclave created\n");
    
    // DO NOT call ecall_init - test simple ecall directly
    int test_result = 0;
    status = ecall_test_simple(global_eid, &test_result);
    if (status != SGX_SUCCESS) {
        printf("ecall_test_simple failed: 0x%04x\n", status);
        
        // Now call ecall_init and try again
        printf("Calling ecall_init...\n");
        ecall_init(global_eid);
        printf("ecall_init done. Try simple ecall again...\n");
        
        status = ecall_test_simple(global_eid, &test_result);
        if (status != SGX_SUCCESS) {
            printf("ecall_test_simple STILL failed: 0x%04x\n", status);
        } else {
            printf("ecall_test_simple success after init: %d\n", test_result);
        }
    } else {
        printf("ecall_test_simple success WITHOUT init: %d\n", test_result);
    }
    
    sgx_destroy_enclave(global_eid);
    return 0;
}
