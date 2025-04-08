#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "test_connection.h"

// Define the global nodes array
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

void ocall_sgx2sgx_connection(uint8_t* sgx_host_pubKey, uint8_t* sgx_guest_pubKey, uint8_t nodeID) {
    if (nodeID >= NUM_NODES) {
        printf("Invalid node ID\n");
        return;
    }
    
    ThreadArgs args;
    args.sgx_host_pubKey = sgx_host_pubKey;
    args.sgx_guest_pubKey = sgx_guest_pubKey;
    args.nodeID = nodeID;
    
    connection_thread_func(&args);
}

#define BASE_TEST_PORT 9000
#define TEST_IP "127.0.0.1"

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

void test_connection_thread_func(void) {
    printf("\n=== Testing connection_thread_func ===\n");
    
    int port = BASE_TEST_PORT;
    setup_test_environment(port);
    
    // Start mock server
    pthread_t server_thread;
    if (pthread_create(&server_thread, NULL, mock_server, &port) != 0) {
        printf("FAIL: Failed to create server thread\n");
        return;
    }
    
    sleep(2);  // Increased wait time
    
    // Prepare test data
    ThreadArgs args;
    uint8_t host_key[KEY_SIZE];
    uint8_t guest_key[KEY_SIZE];
    memset(host_key, 0x55, KEY_SIZE);  // Test pattern
    
    args.sgx_host_pubKey = host_key;
    args.sgx_guest_pubKey = guest_key;
    args.nodeID = 0;
    
    // Run the test
    connection_thread_func(&args);
    
    // Verify results
    int success = 1;
    if (!nodes[0].is_ready) {
        printf("FAIL: Node not marked as ready\n");
        success = 0;
    }
    
    // Verify guest key
    for (int i = 0; i < KEY_SIZE; i++) {
        if (guest_key[i] != 0xAA) {
            printf("FAIL: Guest key not received correctly\n");
            success = 0;
            break;
        }
    }
    
    if (success) {
        printf("PASS: connection_thread_func test\n");
    }
    
    pthread_join(server_thread, NULL);
    cleanup_test_environment();
    sleep(2);  // Increased wait time
}

void test_ocall_sgx2sgx_connection(void) {
    printf("\n=== Testing ocall_sgx2sgx_connection ===\n");
    
    int port = BASE_TEST_PORT + 100;  // Increased port gap
    setup_test_environment(port);
    
    // Start mock server
    pthread_t server_thread;
    if (pthread_create(&server_thread, NULL, mock_server, &port) != 0) {
        printf("FAIL: Failed to create server thread\n");
        return;
    }
    
    sleep(2);  // Increased wait time
    
    // Prepare test data
    uint8_t host_key[KEY_SIZE];
    uint8_t guest_key[KEY_SIZE];
    memset(host_key, 0x55, KEY_SIZE);  // Test pattern
    
    // Run the test
    ocall_sgx2sgx_connection(host_key, guest_key, 0);
    
    // Wait for connection to complete
    sleep(2);
    
    // Verify results
    int success = 1;
    if (!nodes[0].is_ready) {
        printf("FAIL: Node not marked as ready\n");
        success = 0;
    }
    
    // Verify guest key
    for (int i = 0; i < KEY_SIZE; i++) {
        if (guest_key[i] != 0xAA) {
            printf("FAIL: Guest key not received correctly\n");
            success = 0;
            break;
        }
    }
    
    if (success) {
        printf("PASS: ocall_sgx2sgx_connection test\n");
    }
    
    pthread_join(server_thread, NULL);
    cleanup_test_environment();
    sleep(2);  // Increased wait time
}

void test_key_exchange(void) {
    printf("\n=== Testing Key Exchange ===\n");
    
    // Test with different key patterns
    uint8_t patterns[][2] = {
        {0x00, 0xFF},  // All zeros to all ones
        {0x55, 0xAA},  // Alternating patterns
        {0x12, 0x34}   // Random pattern
    };
    
    for (int i = 0; i < 3; i++) {
        int port = BASE_TEST_PORT + 200 + (i * 100);  // Increased port gaps
        setup_test_environment(port);
        
        // Start mock server
        pthread_t server_thread;
        if (pthread_create(&server_thread, NULL, mock_server, &port) != 0) {
            printf("FAIL: Failed to create server thread\n");
            continue;
        }
        
        sleep(2);  // Increased wait time
        
        uint8_t host_key[KEY_SIZE];
        uint8_t guest_key[KEY_SIZE];
        memset(host_key, patterns[i][0], KEY_SIZE);
        
        ocall_sgx2sgx_connection(host_key, guest_key, 0);
        sleep(1);
        
        int success = 1;
        for (int j = 0; j < KEY_SIZE; j++) {
            if (guest_key[j] != 0xAA) {  // Mock server always sends 0xAA
                success = 0;
                break;
            }
        }
        
        printf("Key exchange test %d: %s\n", i+1, success ? "PASS" : "FAIL");
        
        pthread_join(server_thread, NULL);
        cleanup_test_environment();
        sleep(2);  // Increased wait time
    }
}

void test_connection_errors(void) {
    printf("\n=== Testing Connection Errors ===\n");
    
    // Test invalid node ID
    uint8_t host_key[KEY_SIZE];
    uint8_t guest_key[KEY_SIZE];
    ocall_sgx2sgx_connection(host_key, guest_key, NUM_NODES);  // Invalid node ID
    
    // Test with no server running
    int port = BASE_TEST_PORT + 500;  // Increased port gap
    setup_test_environment(port);
    ocall_sgx2sgx_connection(host_key, guest_key, 0);
    
    cleanup_test_environment();
    sleep(2);  // Added wait time
}

int main(void) {
    printf("Starting Connection Tests...\n");
    
    test_connection_thread_func();
    test_ocall_sgx2sgx_connection();
    test_key_exchange();
    test_connection_errors();
    
    printf("\nAll tests completed\n");
    return 0;
} 