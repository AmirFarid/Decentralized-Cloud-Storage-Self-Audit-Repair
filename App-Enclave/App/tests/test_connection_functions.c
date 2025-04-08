#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "test_connection.h"

#define BASE_TEST_PORT 9000
#define TEST_IP "127.0.0.1"

// Global variables implementation
NodeInfo nodes[NUM_NODES];

// Mock implementations of functions from App.c
void connection_thread_func(void* args) {
    ThreadArgs* thread_args = (ThreadArgs*)args;
    uint8_t nodeID = thread_args->nodeID;
    
    // Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }
    
    // Connect to server
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(nodes[nodeID].port);
    inet_pton(AF_INET, nodes[nodeID].ip, &servaddr.sin_addr);
    
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        return;
    }
    
    // Send host public key
    if (send(sockfd, thread_args->sgx_host_pubKey, KEY_SIZE, 0) != KEY_SIZE) {
        perror("Send failed");
        close(sockfd);
        return;
    }
    
    // Receive guest public key
    if (recv(sockfd, thread_args->sgx_guest_pubKey, KEY_SIZE, 0) != KEY_SIZE) {
        perror("Receive failed");
        close(sockfd);
        return;
    }
    
    nodes[nodeID].socket_fd = sockfd;
    nodes[nodeID].is_ready = 1;
}

// Mock server implementation
static void* mock_server(void* arg) {
    int port = *(int*)arg;
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Mock server: socket creation failed");
        return NULL;
    }

    // Set SO_REUSEADDR to allow reuse of the port
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Mock server: setsockopt failed");
        close(server_fd);
        return NULL;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(port)
    };
    
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Mock server: bind failed");
        close(server_fd);
        return NULL;
    }

    if (listen(server_fd, 1) < 0) {
        perror("Mock server: listen failed");
        close(server_fd);
        return NULL;
    }
    
    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("Mock server: accept failed");
        close(server_fd);
        return NULL;
    }
    
    // Receive host public key
    uint8_t host_key[KEY_SIZE];
    ssize_t received = recv(client_fd, host_key, KEY_SIZE, 0);
    if (received != KEY_SIZE) {
        printf("Mock server: Failed to receive host key\n");
        close(client_fd);
        close(server_fd);
        return NULL;
    }
    
    // Send guest public key
    uint8_t guest_key[KEY_SIZE];
    memset(guest_key, 0xAA, KEY_SIZE);  // Test pattern
    if (send(client_fd, guest_key, KEY_SIZE, 0) != KEY_SIZE) {
        printf("Mock server: Failed to send guest key\n");
        close(client_fd);
        close(server_fd);
        return NULL;
    }
    
    close(client_fd);
    close(server_fd);
    return NULL;
}

void setup_test_environment(int port) {
    // Initialize test node
    nodes[0].ip = TEST_IP;
    nodes[0].port = port;
    nodes[0].socket_fd = -1;
    nodes[0].is_ready = 0;
}

void cleanup_test_environment(void) {
    if (nodes[0].socket_fd != -1) {
        close(nodes[0].socket_fd);
        nodes[0].socket_fd = -1;
    }
    nodes[0].is_ready = 0;
}

// Wrapper function to match pthread_create signature
static void* handle_client_wrapper(void* arg) {
    sgx_enclave_id_t eid = *(sgx_enclave_id_t*)arg;
    handle_client(eid, -1);  // -1 for socket fd since we're using socketpair
    return NULL;
}

void test_handle_client(void) {
    printf("\n=== Testing handle_client ===\n");
    
    // Create test socket pair
    int sockfd[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd) < 0) {
        perror("socketpair failed");
        return;
    }
    
    // Create test enclave ID (mock)
    sgx_enclave_id_t eid = 1;
    
    // Start client handler in a thread
    pthread_t handler_thread;
    if (pthread_create(&handler_thread, NULL, handle_client_wrapper, &eid) != 0) {
        perror("Failed to create handler thread");
        close(sockfd[0]);
        close(sockfd[1]);
        return;
    }
    
    // Simulate client sending nonce
    uint8_t test_nonce[KEY_SIZE];
    memset(test_nonce, 0xAA, KEY_SIZE);
    write(sockfd[0], test_nonce, KEY_SIZE);
    
    // Simulate client sending public key
    uint8_t test_pubkey[KEY_SIZE];
    memset(test_pubkey, 0xBB, KEY_SIZE);
    write(sockfd[0], test_pubkey, KEY_SIZE);
    
    // Wait for response
    uint8_t response[KEY_SIZE];
    read(sockfd[0], response, KEY_SIZE);
    
    // Verify results
    int success = 1;
    if (memcmp(response, test_pubkey, KEY_SIZE) != 0) {
        printf("FAIL: Public key exchange failed\n");
        success = 0;
    }
    
    // Cleanup
    close(sockfd[0]);
    close(sockfd[1]);
    pthread_join(handler_thread, NULL);
    
    if (success) {
        printf("PASS: handle_client test\n");
    }
}

void test_setup_server_socket(void) {
    printf("\n=== Testing setup_server_socket ===\n");
    
    int server_fd = setup_server_socket();
    
    int success = 1;
    if (server_fd < 0) {
        printf("FAIL: Server socket creation failed\n");
        success = 0;
    } else {
        // Verify socket options
        int opt;
        socklen_t optlen = sizeof(opt);
        getsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, &optlen);
        if (!opt) {
            printf("FAIL: SO_REUSEADDR not set\n");
            success = 0;
        }
        
        // Verify socket is listening
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        getsockname(server_fd, (struct sockaddr*)&addr, &addrlen);
        if (addr.sin_port == 0) {
            printf("FAIL: Socket not bound\n");
            success = 0;
        }
        
        close(server_fd);
    }
    
    if (success) {
        printf("PASS: setup_server_socket test\n");
    }
}

void test_transfer_chunk_thread_func(void) {
    printf("\n=== Testing transfer_chunk_thread_func ===\n");
    
    // Create test socket pair
    int sockfd[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd) < 0) {
        perror("socketpair failed");
        return;
    }
    
    // Prepare test data
    TransferThreadArgs args;
    args.nodeID = 0;
    args.blockID = 123;
    args.output_buffer = malloc(BLOCK_SIZE);
    args.output_len_ptr = malloc(sizeof(size_t));
    args.buf_len = BLOCK_SIZE;
    
    // Set up test node
    nodes[0].socket_fd = sockfd[1];
    nodes[0].is_ready = 1;
    
    // Start transfer thread
    pthread_t transfer_thread;
    if (pthread_create(&transfer_thread, NULL, transfer_chunk_thread_func, &args) != 0) {
        perror("Failed to create transfer thread");
        free(args.output_buffer);
        free(args.output_len_ptr);
        close(sockfd[0]);
        close(sockfd[1]);
        return;
    }
    
    // Simulate server response
    uint8_t test_data[BLOCK_SIZE];
    memset(test_data, 0xCC, BLOCK_SIZE);
    write(sockfd[0], test_data, BLOCK_SIZE);
    
    // Wait for transfer to complete
    pthread_join(transfer_thread, NULL);
    
    // Verify results
    int success = 1;
    if (*args.output_len_ptr != BLOCK_SIZE) {
        printf("FAIL: Incorrect data length received\n");
        success = 0;
    }
    
    if (memcmp(args.output_buffer, test_data, BLOCK_SIZE) != 0) {
        printf("FAIL: Data mismatch\n");
        success = 0;
    }
    
    // Cleanup
    free(args.output_buffer);
    free(args.output_len_ptr);
    close(sockfd[0]);
    close(sockfd[1]);
    nodes[0].socket_fd = -1;
    nodes[0].is_ready = 0;
    
    if (success) {
        printf("PASS: transfer_chunk_thread_func test\n");
    }
}

void test_ocall_request_data_chunk(void) {
    printf("\n=== Testing ocall_request_data_chunk ===\n");
    
    int port = BASE_TEST_PORT + 700;
    setup_test_environment(port);
    
    // Start mock server
    pthread_t server_thread;
    if (pthread_create(&server_thread, NULL, mock_server, &port) != 0) {
        printf("FAIL: Failed to create server thread\n");
        return;
    }
    
    sleep(2);
    
    // Prepare test data
    uint8_t host_key[KEY_SIZE];
    uint8_t guest_key[KEY_SIZE];
    memset(host_key, 0x55, KEY_SIZE);
    
    // Establish connection
    ocall_sgx2sgx_connection(host_key, guest_key, 0);
    sleep(2);
    
    // Test data request
    uint8_t output_buffer[BLOCK_SIZE];
    size_t actual_len = 0;
    uint32_t blockID = 123;
    
    ocall_request_data_chunk(0, blockID, output_buffer, &actual_len, BLOCK_SIZE);
    
    // Verify results
    int success = 1;
    if (actual_len == 0) {
        printf("FAIL: No data received\n");
        success = 0;
    }
    
    // Verify data content
    for (size_t i = 0; i < actual_len; i++) {
        if (output_buffer[i] != 0xAA) {  // Mock server sends 0xAA
            printf("FAIL: Data content mismatch\n");
            success = 0;
            break;
        }
    }
    
    if (success) {
        printf("PASS: ocall_request_data_chunk test\n");
    }
    
    pthread_join(server_thread, NULL);
    cleanup_test_environment();
    sleep(2);
}

int main(void) {
    printf("Starting Connection Function Tests...\n");
    
    test_handle_client();
    test_setup_server_socket();
    test_transfer_chunk_thread_func();
    test_ocall_request_data_chunk();
    
    printf("\nAll tests completed\n");
    return 0;
} 