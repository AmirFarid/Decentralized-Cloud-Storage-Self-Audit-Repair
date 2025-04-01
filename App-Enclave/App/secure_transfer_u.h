#ifndef SECURE_TRANSFER_U_H
#define SECURE_TRANSFER_U_H

#include <stddef.h>
#include <stdint.h>
#include "sgx_urts.h"
#include "secure_transfer_t.h"

// Initialize secure transfer in the enclave
sgx_status_t secure_transfer_init_enclave(sgx_enclave_id_t* eid);

// Request a file from another laptop
sgx_status_t secure_request_file_enclave(sgx_enclave_id_t eid, const char* filename, int source_laptop_id);

// Send a file to another laptop
sgx_status_t secure_send_file_enclave(sgx_enclave_id_t eid, const char* filename, int target_laptop_id);

// Handle incoming file transfer request
sgx_status_t secure_handle_transfer_request_enclave(sgx_enclave_id_t eid, TransferRequest* request);

// Start streaming data to another laptop
sgx_status_t secure_start_stream_enclave(sgx_enclave_id_t eid, int target_laptop_id);

// Send streaming data
sgx_status_t secure_send_stream_data_enclave(sgx_enclave_id_t eid, const void* data, size_t data_len);

// Receive streaming data
sgx_status_t secure_receive_stream_data_enclave(sgx_enclave_id_t eid, void** data, size_t* data_len);

// End streaming session
sgx_status_t secure_end_stream_enclave(sgx_enclave_id_t eid);

// Cleanup secure transfer resources
sgx_status_t secure_transfer_cleanup_enclave(sgx_enclave_id_t eid);

#endif // SECURE_TRANSFER_U_H 