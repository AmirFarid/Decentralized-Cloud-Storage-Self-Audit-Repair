#ifndef SECURE_TRANSFER_T_H
#define SECURE_TRANSFER_T_H

#include <stddef.h>
#include <stdint.h>
#include "sgx_trts.h"

#define MAX_LAPTOPS 10
#define MAX_FILENAME_LEN 256
#define HANDSHAKE_DATA_SIZE 32
#define CHUNK_SIZE 8192

typedef enum {
    TRANSFER_SUCCESS = 0,
    TRANSFER_ERROR_INVALID_PARAMETER = -1,
    TRANSFER_ERROR_NETWORK = -2,
    TRANSFER_ERROR_FILE_IO = -3,
    TRANSFER_ERROR_HANDSHAKE = -4
} TransferStatus;

typedef struct {
    char filename[MAX_FILENAME_LEN];
    uint64_t file_size;
    uint8_t checksum[32];
    uint8_t transfer_type;  // 0 for file transfer, 1 for stream
    uint8_t handshake_data[HANDSHAKE_DATA_SIZE];
} TransferRequest;

typedef struct {
    uint8_t response_data[HANDSHAKE_DATA_SIZE];
    TransferStatus status;
} HandshakeResponse;

// Initialize secure transfer in the enclave
sgx_status_t secure_transfer_init_trusted(void);

// Perform handshake with another enclave
sgx_status_t perform_handshake_trusted(const uint8_t* challenge, uint8_t* response);

// Request a file from another laptop
sgx_status_t secure_request_file_trusted(const char* filename, int source_laptop_id);

// Send a file to another laptop
sgx_status_t secure_send_file_trusted(const char* filename, int target_laptop_id);

// Handle incoming file transfer request
sgx_status_t secure_handle_transfer_request_trusted(TransferRequest* request);

// Start streaming data to another laptop
sgx_status_t secure_start_stream_trusted(int target_laptop_id);

// Send streaming data
sgx_status_t secure_send_stream_data_trusted(const void* data, size_t data_len);

// Receive streaming data
sgx_status_t secure_receive_stream_data_trusted(void** data, size_t* data_len);

// End streaming session
sgx_status_t secure_end_stream_trusted(void);

// Cleanup secure transfer resources
sgx_status_t secure_transfer_cleanup_trusted(void);

#endif // SECURE_TRANSFER_T_H 