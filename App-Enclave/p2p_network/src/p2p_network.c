#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <stddef.h>
#include "../include/p2p_network.h"

// Forward declaration of handle_peer_thread
static void* handle_peer_thread(void* arg);

// Internal logging function
static void log_message(Node* node, const char* format, ...) {
    if (!node->config.enable_logging) return;
    
    va_list args;
    va_start(args, format);
    printf("[P2P Node %s] ", node->config.node_id);
    vprintf(format, args);
    printf("\n");
    va_end(args);
}

// Thread function to handle incoming connections
static void* accept_connections_thread(void* arg) {
    Node* node = (Node*)arg;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    while (node->is_running) {
        int client_socket = accept(node->server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            if (node->is_running) {
                log_message(node, "Error accepting connection: %s", strerror(errno));
            }
            continue;
        }
        
        // Find free peer slot
        pthread_mutex_lock(&node->peers_mutex);
        int peer_index = -1;
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (!node->peers[i].is_active) {
                peer_index = i;
                break;
            }
        }
        
        if (peer_index == -1) {
            log_message(node, "No free peer slots available");
            close(client_socket);
            pthread_mutex_unlock(&node->peers_mutex);
            continue;
        }
        
        // Initialize peer connection
        PeerConnection* peer = &node->peers[peer_index];
        peer->is_active = true;
        peer->socket_fd = client_socket;
        peer->status = CONN_STATUS_CONNECTED;
        strncpy(peer->ip_address, inet_ntoa(client_addr.sin_addr), sizeof(peer->ip_address));
        peer->port = ntohs(client_addr.sin_port);
        
        // Exchange node IDs
        // First, receive the peer's node ID
        Message peer_id_msg;
        ssize_t bytes_received = recv(client_socket, &peer_id_msg, sizeof(Message), 0);
        if (bytes_received <= 0) {
            log_message(node, "Failed to receive peer's node ID: %s", strerror(errno));
            close(client_socket);
            peer->is_active = false;
            pthread_mutex_unlock(&node->peers_mutex);
            continue;
        }
        
        // Store peer's node ID
        strncpy(peer->peer_id, peer_id_msg.sender_id, MAX_PEER_ID_LENGTH - 1);
        
        // Send our node ID to the peer
        Message id_msg = {
            .type = MSG_TYPE_DATA,
            .data_length = strlen(node->config.node_id)
        };
        strncpy(id_msg.sender_id, node->config.node_id, MAX_PEER_ID_LENGTH - 1);
        memcpy(id_msg.data, node->config.node_id, id_msg.data_length);
        
        if (send(client_socket, &id_msg, sizeof(Message), 0) < 0) {
            log_message(node, "Failed to send node ID to peer: %s", strerror(errno));
            close(client_socket);
            peer->is_active = false;
            pthread_mutex_unlock(&node->peers_mutex);
            continue;
        }
        
        log_message(node, "Accepted connection from peer %s at %s:%d", 
                   peer->peer_id, peer->ip_address, peer->port);
        
        // Create thread for handling peer communication
        pthread_t* peer_thread = malloc(sizeof(pthread_t));
        node->peer_threads[peer_index] = peer_thread;
        
        pthread_mutex_unlock(&node->peers_mutex);
        
        // Start peer handling thread
        if (pthread_create(peer_thread, NULL, handle_peer_thread, (void*)peer) != 0) {
            log_message(node, "Failed to create peer thread");
            close(client_socket);
            peer->is_active = false;
            free(peer_thread);
        }
    }
    
    return NULL;
}

// Thread function to handle communication with a specific peer
static void* handle_peer_thread(void* arg) {
    PeerConnection* peer = (PeerConnection*)arg;
    Node* node = (Node*)((char*)peer - offsetof(Node, peers));
    
    while (peer->is_active) {
        Message msg;
        ssize_t bytes_read = recv(peer->socket_fd, &msg, sizeof(Message), 0);
        
        if (bytes_read <= 0) {
            if (bytes_read == 0) {
                log_message(node, "Peer %s disconnected", peer->peer_id);
            } else {
                log_message(node, "Error receiving from peer %s: %s", peer->peer_id, strerror(errno));
            }
            break;
        }
        
        // Handle message
        if (node->config.message_callback) {
            node->config.message_callback(&msg, node->config.user_data);
        }
    }
    
    // Cleanup
    pthread_mutex_lock(&node->peers_mutex);
    close(peer->socket_fd);
    peer->is_active = false;
    peer->status = CONN_STATUS_DISCONNECTED;
    pthread_mutex_unlock(&node->peers_mutex);
    
    return NULL;
}

Node* p2p_node_init(const NodeConfig* config) {
    Node* node = (Node*)calloc(1, sizeof(Node));
    if (!node) return NULL;
    
    // Copy configuration
    memcpy(&node->config, config, sizeof(NodeConfig));
    
    // Initialize mutex
    if (pthread_mutex_init(&node->peers_mutex, NULL) != 0) {
        free(node);
        return NULL;
    }
    
    return node;
}

int p2p_node_start(Node* node) {
    // Create server socket
    node->server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (node->server_socket < 0) {
        log_message(node, "Failed to create server socket: %s", strerror(errno));
        return -1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(node->server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_message(node, "Failed to set socket options: %s", strerror(errno));
        close(node->server_socket);
        return -1;
    }
    
    // Bind to port
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(node->config.listen_port)
    };
    
    if (bind(node->server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        log_message(node, "Failed to bind to port %d: %s", node->config.listen_port, strerror(errno));
        close(node->server_socket);
        return -1;
    }
    
    // Start listening
    if (listen(node->server_socket, MAX_CONNECTIONS) < 0) {
        log_message(node, "Failed to listen: %s", strerror(errno));
        close(node->server_socket);
        return -1;
    }
    
    node->is_running = true;
    
    // Start accept thread
    if (pthread_create(&node->accept_thread, NULL, accept_connections_thread, node) != 0) {
        log_message(node, "Failed to create accept thread: %s", strerror(errno));
        close(node->server_socket);
        return -1;
    }
    
    log_message(node, "Node started and listening on port %d", node->config.listen_port);
    return 0;
}

void p2p_node_stop(Node* node) {
    if (!node) return;
    
    node->is_running = false;
    
    // Close server socket
    if (node->server_socket >= 0) {
        close(node->server_socket);
    }
    
    // Close all peer connections
    pthread_mutex_lock(&node->peers_mutex);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (node->peers[i].is_active) {
            close(node->peers[i].socket_fd);
            node->peers[i].is_active = false;
        }
    }
    pthread_mutex_unlock(&node->peers_mutex);
    
    // Wait for accept thread to finish
    pthread_join(node->accept_thread, NULL);
    
    log_message(node, "Node stopped");
}

int p2p_connect_to_peer(Node* node, const char* ip_address, uint16_t port) {
    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_message(node, "Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    // Connect to peer
    struct sockaddr_in peer_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port)
    };
    
    if (inet_pton(AF_INET, ip_address, &peer_addr.sin_addr) <= 0) {
        log_message(node, "Invalid address: %s", ip_address);
        close(sock);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        log_message(node, "Failed to connect to %s:%d: %s", ip_address, port, strerror(errno));
        close(sock);
        return -1;
    }
    
    // Find free peer slot
    pthread_mutex_lock(&node->peers_mutex);
    int peer_index = -1;
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (!node->peers[i].is_active) {
            peer_index = i;
            break;
        }
    }
    
    if (peer_index == -1) {
        log_message(node, "No free peer slots available");
        close(sock);
        pthread_mutex_unlock(&node->peers_mutex);
        return -1;
    }
    
    // Initialize peer connection
    PeerConnection* peer = &node->peers[peer_index];
    peer->is_active = true;
    peer->socket_fd = sock;
    peer->status = CONN_STATUS_CONNECTED;
    strncpy(peer->ip_address, ip_address, sizeof(peer->ip_address));
    peer->port = port;
    
    // Exchange node IDs
    Message id_msg = {
        .type = MSG_TYPE_DATA,
        .data_length = strlen(node->config.node_id)
    };
    strncpy(id_msg.sender_id, node->config.node_id, MAX_PEER_ID_LENGTH - 1);
    memcpy(id_msg.data, node->config.node_id, id_msg.data_length);
    
    // Send our node ID to the peer
    if (send(sock, &id_msg, sizeof(Message), 0) < 0) {
        log_message(node, "Failed to send node ID to peer: %s", strerror(errno));
        close(sock);
        peer->is_active = false;
        pthread_mutex_unlock(&node->peers_mutex);
        return -1;
    }
    
    // Receive peer's node ID
    Message peer_id_msg;
    ssize_t bytes_received = recv(sock, &peer_id_msg, sizeof(Message), 0);
    if (bytes_received <= 0) {
        log_message(node, "Failed to receive peer's node ID: %s", strerror(errno));
        close(sock);
        peer->is_active = false;
        pthread_mutex_unlock(&node->peers_mutex);
        return -1;
    }
    
    // Store peer's node ID
    strncpy(peer->peer_id, peer_id_msg.sender_id, MAX_PEER_ID_LENGTH - 1);
    log_message(node, "Connected to peer %s at %s:%d", peer->peer_id, ip_address, port);
    
    // Create thread for handling peer communication
    pthread_t* peer_thread = malloc(sizeof(pthread_t));
    node->peer_threads[peer_index] = peer_thread;
    
    pthread_mutex_unlock(&node->peers_mutex);
    
    // Start peer handling thread
    if (pthread_create(peer_thread, NULL, handle_peer_thread, (void*)peer) != 0) {
        log_message(node, "Failed to create peer thread");
        close(sock);
        peer->is_active = false;
        free(peer_thread);
        return -1;
    }
    
    return 0;
}

int p2p_send_to_peer(Node* node, const char* peer_id, const Message* message) {
    pthread_mutex_lock(&node->peers_mutex);
    
    // Find peer
    PeerConnection* peer = NULL;
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (node->peers[i].is_active && strcmp(node->peers[i].peer_id, peer_id) == 0) {
            peer = &node->peers[i];
            break;
        }
    }
    
    if (!peer) {
        pthread_mutex_unlock(&node->peers_mutex);
        log_message(node, "Peer %s not found", peer_id);
        return -1;
    }
    
    // Send message
    ssize_t bytes_sent = send(peer->socket_fd, message, sizeof(Message), 0);
    pthread_mutex_unlock(&node->peers_mutex);
    
    if (bytes_sent < 0) {
        log_message(node, "Failed to send message to %s: %s", peer_id, strerror(errno));
        return -1;
    }
    
    return 0;
}

int p2p_broadcast(Node* node, const Message* message) {
    pthread_mutex_lock(&node->peers_mutex);
    
    int success_count = 0;
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (node->peers[i].is_active) {
            if (send(node->peers[i].socket_fd, message, sizeof(Message), 0) >= 0) {
                success_count++;
            }
        }
    }
    
    pthread_mutex_unlock(&node->peers_mutex);
    return success_count;
}

int p2p_get_peer_count(const Node* node) {
    int count = 0;
    pthread_mutex_lock((pthread_mutex_t*)&node->peers_mutex);
    
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (node->peers[i].is_active) {
            count++;
        }
    }
    
    pthread_mutex_unlock((pthread_mutex_t*)&node->peers_mutex);
    return count;
}

PeerConnection* p2p_get_peer_info(Node* node, const char* peer_id) {
    pthread_mutex_lock(&node->peers_mutex);
    
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (node->peers[i].is_active && strcmp(node->peers[i].peer_id, peer_id) == 0) {
            pthread_mutex_unlock(&node->peers_mutex);
            return &node->peers[i];
        }
    }
    
    pthread_mutex_unlock(&node->peers_mutex);
    return NULL;
}

int p2p_disconnect_peer(Node* node, const char* peer_id) {
    pthread_mutex_lock(&node->peers_mutex);
    
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (node->peers[i].is_active && strcmp(node->peers[i].peer_id, peer_id) == 0) {
            close(node->peers[i].socket_fd);
            node->peers[i].is_active = false;
            node->peers[i].status = CONN_STATUS_DISCONNECTED;
            
            if (node->peer_threads[i]) {
                free(node->peer_threads[i]);
                node->peer_threads[i] = NULL;
            }
            
            pthread_mutex_unlock(&node->peers_mutex);
            log_message(node, "Disconnected from peer %s", peer_id);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&node->peers_mutex);
    log_message(node, "Peer %s not found", peer_id);
    return -1;
}

void p2p_set_logging(Node* node, bool enable) {
    node->config.enable_logging = enable;
}

void p2p_node_cleanup(Node* node) {
    if (!node) return;
    
    p2p_node_stop(node);
    pthread_mutex_destroy(&node->peers_mutex);
    free(node);
} 