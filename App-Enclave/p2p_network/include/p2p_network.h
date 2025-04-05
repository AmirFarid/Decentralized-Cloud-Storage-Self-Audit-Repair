#ifndef P2P_NETWORK_H
#define P2P_NETWORK_H

#include <stdint.h>
#include <stdbool.h>

// Maximum number of simultaneous connections
#define MAX_CONNECTIONS 16
#define MAX_MESSAGE_SIZE 1024
#define MAX_PEER_ID_LENGTH 32

// Message types
typedef enum {
    MSG_TYPE_DATA = 0,
    MSG_TYPE_HEARTBEAT = 1,
    MSG_TYPE_DISCONNECT = 2
} MessageType;

// Message structure
typedef struct {
    MessageType type;
    char sender_id[MAX_PEER_ID_LENGTH];
    uint32_t data_length;
    uint8_t data[MAX_MESSAGE_SIZE];
} Message;

// Connection status
typedef enum {
    CONN_STATUS_DISCONNECTED = 0,
    CONN_STATUS_CONNECTING = 1,
    CONN_STATUS_CONNECTED = 2
} ConnectionStatus;

// Peer connection structure
typedef struct {
    char peer_id[MAX_PEER_ID_LENGTH];
    char ip_address[16];
    uint16_t port;
    int socket_fd;
    ConnectionStatus status;
    bool is_active;
} PeerConnection;

// Node configuration
typedef struct {
    char node_id[MAX_PEER_ID_LENGTH];
    uint16_t listen_port;
    bool enable_logging;
    void (*message_callback)(const Message* msg, void* user_data);
    void* user_data;
} NodeConfig;

// Node structure
typedef struct {
    NodeConfig config;
    PeerConnection peers[MAX_CONNECTIONS];
    int server_socket;
    bool is_running;
    pthread_t accept_thread;
    pthread_t* peer_threads[MAX_CONNECTIONS];
    pthread_mutex_t peers_mutex;
} Node;

// Initialize a new node with the given configuration
Node* p2p_node_init(const NodeConfig* config);

// Start the node (starts listening for incoming connections)
int p2p_node_start(Node* node);

// Stop the node and cleanup resources
void p2p_node_stop(Node* node);

// Connect to a peer node
int p2p_connect_to_peer(Node* node, const char* ip_address, uint16_t port);

// Send a message to a specific peer
int p2p_send_to_peer(Node* node, const char* peer_id, const Message* message);

// Broadcast a message to all connected peers
int p2p_broadcast(Node* node, const Message* message);

// Get the number of connected peers
int p2p_get_peer_count(const Node* node);

// Get information about a specific peer
PeerConnection* p2p_get_peer_info(Node* node, const char* peer_id);

// Disconnect from a specific peer
int p2p_disconnect_peer(Node* node, const char* peer_id);

// Enable or disable logging
void p2p_set_logging(Node* node, bool enable);

// Cleanup and free node resources
void p2p_node_cleanup(Node* node);

#endif // P2P_NETWORK_H 