#include <stdio.h>
#include "sgx_urts.h"
#include "sgx_eid.h"
#include "test_u.h"

sgx_enclave_id_t eid = 0;

int main() {
    sgx_status_t ret;
    
    ret = sgx_create_enclave("test.signed.so", SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Failed to create enclave: 0x%04x\n", ret);
        return 1;
    }
    printf("Enclave created\n");
    
    sgx_target_info_t target = {0};
    sgx_report_data_t data = {0};
    sgx_report_t report;
    sgx_status_t retval;
    
    ret = ecall_create_report(eid, &retval, &target, &data, &report);
    printf("ecall ret=0x%04x, retval=0x%04x\n", ret, retval);
    
    sgx_destroy_enclave(eid);
    return 0;
}

#include <stdio.h>
int main2() {
    printf("sizeof(sgx_target_info_t) = %lu\n", sizeof(sgx_target_info_t));
    printf("sizeof(sgx_report_data_t) = %lu\n", sizeof(sgx_report_data_t));
    printf("sizeof(sgx_report_t) = %lu\n", sizeof(sgx_report_t));
    return 0;
}
