#ifndef ENDEFS_H
#define ENDEFS_H
#include <stdint.h>
#include <openssl/bn.h>
#include "sharedTypes.h"

#define AUDIT_INDICATOR  "AUDITX"
#define ENCODE_INDICATOR "ENCODE"
#define PARITY_INDICATOR "PARITY"
#define MAX_NODES 4
#define MAX_DATA_SIZE 4096  // 4096 bits as per your requirement
#define ECC_PUB_KEY_SIZE 64
#define K 4


// Node status enum
typedef enum {
    NODE_ONLINE = 0,
    NODE_OFFLINE = 1,
    NODE_BUSY = 2
} NodeStatus;

// Node structure
typedef struct {
    int node_id;                     // Unique identifier for the node
    char ip_addr[16];                 // IPv4 address
    uint16_t port;                    // Port number
    NodeStatus status;  // Current status of the node, defaults to ONLINE
    uint8_t public_key[ECC_PUB_KEY_SIZE]; // Node's public key for secure communication
    uint8_t shared_secret[32];         // Shared secret key for encryption
    int is_authenticated;              // Authentication status (0 = false, 1 = true)
    int socket;                        // Add socket descriptor
} Node;

// Data request structure
typedef struct {
    int type;                        // Type of request (e.g., REQUEST_BLOCK)
    int block_num;              // Physical block number in storage
    int data_num;               // Data block number in erasure coding scheme
    int request_id;                  // Unique request identifier
    int source_node_id;              // ID of the requesting node
    int target_node_id;              // ID of the target node
    uint8_t data_number;             // 8-bit data number as per your requirement
    int is_valid;                    // Validity flag (0 = false, 1 = true)
    uint8_t data[MAX_DATA_SIZE/8];   // The actual data (4096 bits)
    size_t data_len;                 // Length of the data
    uint8_t signature[64];           // Digital signature for verification
} DataRequest;

// Global node management
extern Node nodes[MAX_NODES];
extern int current_node_id;          // ID of the current node
extern int connected_nodes;          // Number of currently connected nodes

typedef struct PorSK {
	uint8_t encKey[KEY_SIZE];
	uint8_t macKey[MAC_SIZE];
} PorSK;

// n and k are the erasure code parameters for an (n, k) erasure code.
typedef struct File {
	int inUse;
	int numBlocks;
	int numGroups;
	int n;
	int k;
	char fileName[FILE_NAME_LEN];
	uint8_t prime[PRIME_LENGTH / 8];
	uint8_t sortKey[KEY_SIZE]; // I never define this. I should randomly generate it in file_init.
} File;

typedef struct {
    char ip[16];   // Store IPv4 address
    int port;      // Port number
	uint8_t cIndex; // Chunk Number
} IP;

extern File files[MAX_FILES];
extern PorSK porSK;
extern uint8_t dh_sharedKey[64];

// Thread data structure for data retrieval
typedef struct {
    int thread_id;                   // Unique identifier for the thread
    int target_node_id;              // Node to retrieve data from
    int target_block_num;            // Block number to retrieve
    int success;                     // Success flag for the thread
    pthread_mutex_t* mutex;          // Mutex for thread synchronization
    int* responses_received;         // Counter for received responses
    uint8_t** ordered_blocks;        // Array of pointers to ordered blocks
    DataRequest* request;            // Pointer to the data request for this thread
} ThreadData;

#endif
