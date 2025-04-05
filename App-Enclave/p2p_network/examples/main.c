#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "../include/p2p_network.h"

// Global node pointer for cleanup in signal handler
static Node* g_node = NULL;

// Message callback function
void message_callback(const Message* msg, void* user_data) {
    (void)user_data; // Mark as intentionally unused
    printf("Received message from %s:\n", msg->sender_id);
    printf("Type: %d\n", msg->type);
    printf("Data length: %u\n", msg->data_length);
    printf("Data: %.*s\n", (int)msg->data_length, (char*)msg->data);
    printf("-------------------\n");
}

// Signal handler for graceful shutdown
void signal_handler(int signum) {
    (void)signum; // Mark as intentionally unused
    if (g_node) {
        printf("\nShutting down node...\n");
        p2p_node_cleanup(g_node);
    }
    exit(0);
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Usage: %s <node_id> <listen_port> <peer_port>\n", argv[0]);
        return 1;
    }
    
    const char* node_id = argv[1];
    uint16_t listen_port = (uint16_t)atoi(argv[2]);
    uint16_t peer_port = (uint16_t)atoi(argv[3]);
    
    // Set up signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize node configuration
    NodeConfig config = {
        .node_id = "",
        .listen_port = listen_port,
        .enable_logging = true,
        .message_callback = message_callback,
        .user_data = NULL
    };
    strncpy(config.node_id, node_id, MAX_PEER_ID_LENGTH - 1);
    
    // Initialize and start node
    g_node = p2p_node_init(&config);
    if (!g_node) {
        printf("Failed to initialize node\n");
        return 1;
    }
    
    if (p2p_node_start(g_node) != 0) {
        printf("Failed to start node\n");
        p2p_node_cleanup(g_node);
        return 1;
    }
    
    // Connect to peer if peer port is specified
    if (peer_port > 0) {
        if (p2p_connect_to_peer(g_node, "127.0.0.1", peer_port) != 0) {
            printf("Failed to connect to peer\n");
            p2p_node_cleanup(g_node);
            return 1;
        }
    }
    
    printf("Node %s is running. Press Ctrl+C to exit.\n", node_id);
    printf("Enter messages in format: <peer_id> <message>\n");
    
    // Main loop for sending messages
    char input[1024];
    char peer_id[MAX_PEER_ID_LENGTH];
    char message[MAX_MESSAGE_SIZE];
    
    while (fgets(input, sizeof(input), stdin)) {
        if (sscanf(input, "%s %[^\n]", peer_id, message) == 2) {
            Message msg = {
                .type = MSG_TYPE_DATA,
                .data_length = strlen(message)
            };
            strncpy(msg.sender_id, node_id, MAX_PEER_ID_LENGTH - 1);
            memcpy(msg.data, message, msg.data_length);
            
            if (p2p_send_to_peer(g_node, peer_id, &msg) != 0) {
                printf("Failed to send message to %s\n", peer_id);
            }
        }
    }
    
    return 0;
} 