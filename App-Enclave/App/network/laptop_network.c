#include "laptop_network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

static LaptopNetworkConfig g_config;
static int g_server_fd = -1;
static int g_client_fd = -1;
static int g_connected_clients[MAX_LAPTOPS] = {-1};

void laptop_network_error(const char* msg) {
    perror(msg);
    laptop_network_cleanup();
    exit(EXIT_FAILURE);
}

int laptop_network_init(LaptopNetworkConfig* config) {
    if (!config) {
        return -1;
    }
    
    memcpy(&g_config, config, sizeof(LaptopNetworkConfig));
    
    // Validate configuration
    if (g_config.laptop_id < 0 || g_config.laptop_id >= MAX_LAPTOPS) {
        printf("Invalid laptop ID: %d\n", g_config.laptop_id);
        return -1;
    }
    
    return 0;
}

int laptop_start_server(void) {
    if (g_config.role != ROLE_SERVER) {
        printf("Not configured as server\n");
        return -1;
    }
    
    struct sockaddr_in address;
    
    // Create socket
    if ((g_server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        laptop_network_error("Socket creation failed");
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(g_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        laptop_network_error("Setsockopt failed");
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(g_config.server_port);
    
    // Bind socket
    if (bind(g_server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        laptop_network_error("Bind failed");
    }
    
    // Listen for connections
    if (listen(g_server_fd, MAX_LAPTOPS) < 0) {
        laptop_network_error("Listen failed");
    }
    
    printf("Server listening on port %d\n", g_config.server_port);
    return 0;
}

int laptop_accept_connections(void) {
    if (g_config.role != ROLE_SERVER) {
        printf("Not configured as server\n");
        return -1;
    }
    
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    for (int i = 0; i < MAX_LAPTOPS; i++) {
        if (g_connected_clients[i] == -1) {
            int new_socket = accept(g_server_fd, (struct sockaddr*)&client_addr, &client_len);
            if (new_socket < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // No more connections available
                    break;
                }
                laptop_network_error("Accept failed");
            }
            
            g_connected_clients[i] = new_socket;
            printf("New connection accepted from laptop %d\n", i);
        }
    }
    
    return 0;
}

int laptop_connect_to_server(void) {
    if (g_config.role != ROLE_CLIENT) {
        printf("Not configured as client\n");
        return -1;
    }
    
    struct sockaddr_in serv_addr;
    
    // Create socket
    if ((g_client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        laptop_network_error("Socket creation failed");
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(g_config.server_port);
    
    if (inet_pton(AF_INET, g_config.server_ip, &serv_addr.sin_addr) <= 0) {
        laptop_network_error("Invalid address");
    }
    
    // Connect to server
    if (connect(g_client_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        laptop_network_error("Connection failed");
    }
    
    printf("Connected to server at %s:%d\n", g_config.server_ip, g_config.server_port);
    return 0;
}

int laptop_send_data(void* data, size_t data_len) {
    if (!data) {
        return -1;
    }
    
    int fd = (g_config.role == ROLE_SERVER) ? g_server_fd : g_client_fd;
    if (fd < 0) {
        printf("Not connected\n");
        return -1;
    }
    
    ssize_t total_sent = 0;
    while (total_sent < data_len) {
        ssize_t sent = write(fd, data + total_sent, data_len - total_sent);
        if (sent == -1) {
            laptop_network_error("Send failed");
        }
        total_sent += sent;
    }
    
    return 0;
}

void* laptop_receive_data(size_t data_len) {
    int fd = (g_config.role == ROLE_SERVER) ? g_server_fd : g_client_fd;
    if (fd < 0) {
        printf("Not connected\n");
        return NULL;
    }
    
    void* data = malloc(data_len);
    if (!data) {
        laptop_network_error("Memory allocation failed");
    }
    
    ssize_t total_received = 0;
    while (total_received < data_len) {
        ssize_t received = read(fd, data + total_received, data_len - total_received);
        if (received == -1) {
            free(data);
            laptop_network_error("Receive failed");
        } else if (received == 0) {
            free(data);
            printf("Connection closed by peer\n");
            return NULL;
        }
        total_received += received;
    }
    
    return data;
}

void laptop_close_server(void) {
    // Close all client connections
    for (int i = 0; i < MAX_LAPTOPS; i++) {
        if (g_connected_clients[i] != -1) {
            close(g_connected_clients[i]);
            g_connected_clients[i] = -1;
        }
    }
    
    // Close server socket
    if (g_server_fd != -1) {
        close(g_server_fd);
        g_server_fd = -1;
    }
}

void laptop_close_client(void) {
    if (g_client_fd != -1) {
        close(g_client_fd);
        g_client_fd = -1;
    }
}

void laptop_network_cleanup(void) {
    if (g_config.role == ROLE_SERVER) {
        laptop_close_server();
    } else {
        laptop_close_client();
    }
} 