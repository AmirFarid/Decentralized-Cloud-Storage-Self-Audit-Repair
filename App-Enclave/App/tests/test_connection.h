#ifndef TEST_CONNECTION_H
#define TEST_CONNECTION_H

#include <stdint.h>
#include <sgx_urts.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define NUM_NODES 10
#define KEY_SIZE 32
#define BLOCK_SIZE 4096

typedef struct {
    char* ip;
    int port;
    int socket_fd;
    int is_ready;
} NodeInfo;

typedef struct {
    uint8_t* sgx_host_pubKey;
    uint8_t* sgx_guest_pubKey;
    uint8_t nodeID;
} ThreadArgs;

typedef struct {
    uint8_t nodeID;
    uint32_t blockID;
    uint8_t* output_buffer;
    size_t* output_len_ptr;
    size_t buf_len;
} TransferThreadArgs;

// Global variables
extern NodeInfo nodes[NUM_NODES];

// Function declarations from App.c that we're testing
void handle_client(sgx_enclave_id_t eid, int client_socket);
int setup_server_socket(void);
void* transfer_chunk_thread_func(void* args);
void ocall_sgx2sgx_connection(uint8_t* sgx_host_pubKey, uint8_t* sgx_guest_pubKey, uint8_t nodeID);
void ocall_request_data_chunk(uint8_t nodeID, uint32_t blockID, uint8_t* output_buffer, size_t* actual_len, size_t buf_len);

// Test function declarations
void test_handle_client(void);
void test_setup_server_socket(void);
void test_transfer_chunk_thread_func(void);
void test_ocall_request_data_chunk(void);

// Helper functions
void setup_test_environment(int port);
void cleanup_test_environment(void);

#endif // TEST_CONNECTION_H 