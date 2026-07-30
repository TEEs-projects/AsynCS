#include "test_t.h"
#include "sgx_trts.h"
#include "sgx_utils.h"

sgx_status_t ecall_create_report(const sgx_target_info_t* target_info, 
    const sgx_report_data_t* report_data, sgx_report_t* report) {
    return sgx_create_report(target_info, report_data, report);
}
