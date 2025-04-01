#ifndef LAPTOP_NETWORK_H
#define LAPTOP_NETWORK_H

#include <stddef.h>
#include <stdint.h>

#define MAX_LAPTOPS 4
#define DEFAULT_PORT 49200
#define BUFFER_SIZE 1024

// Laptop role
typedef enum {
    ROLE_SERVER,
    ROLE_CLIENT
} LaptopRole;

// Network configuration
typedef struct {
    char server_ip[16];
    int server_port;
    LaptopRole role;
    int laptop_id;  // Unique ID for each laptop (0-3)
} LaptopNetworkConfig;

// Initialize network with configuration
int laptop_network_init(LaptopNetworkConfig* config);

// Server functions
int laptop_start_server(void);
int laptop_accept_connections(void);
void laptop_close_server(void);

// Client functions
int laptop_connect_to_server(void);
void laptop_close_client(void);

// Data transfer functions
int laptop_send_data(void* data, size_t data_len);
void* laptop_receive_data(size_t data_len);

// Error handling
void laptop_network_error(const char* msg);

// Cleanup
void laptop_network_cleanup(void);

#endif // LAPTOP_NETWORK_H 