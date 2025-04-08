#ifndef SHARED_TYPES_H
#define SHARED_TYPES_H


#define KEY_SIZE 16
#define MAC_SIZE 20
#define PRIME_LENGTH 80
#define SHA_DIGEST_LENGTH 20

#define BLOCK_SIZE 4096 // Note: these depend on the storage device being used.
#define PAGE_SIZE 2048
#define SEGMENT_SIZE 512
#define PAGE_PER_BLOCK (BLOCK_SIZE / PAGE_SIZE)
#define SEGMENT_PER_BLOCK (BLOCK_SIZE / SEGMENT_SIZE)
#define SEGMENT_PER_PAGE (PAGE_SIZE / SEGMENT_SIZE)

#define FILE_NAME_LEN 512
#define MAX_FILES 10

#define NUM_CHAL_BLOCKS 5
#define NUM_ORIGINAL_SYMBOLS 2 // Erasure code parameters. Maybe should be part of File struct
#define NUM_TOTAL_SYMBOLS 3

#define SECRET_LENGTH ((PAGE_SIZE * 8) / 256) // One bit in secret message every 512 bits.
#define PARITY_START 5000 // Start address for parity data.

#define NUM_NODES 3 // Number of nodes in the network.

typedef struct Tag {
    int n;
    uint8_t prfKey[KEY_SIZE];
	uint8_t alpha[SEGMENT_PER_BLOCK][PRIME_LENGTH / 8];
	uint8_t MAC[MAC_SIZE];
} Tag;

typedef struct {
    const char* ip;
    int port;
    int socket_fd;
    int is_ready;
} NodeInfo;

// Hardcoded node information for 3 nodes
NodeInfo nodes[NUM_NODES] = {
    {"192.168.1.1", 8080, -1, 0},  // Node 0
    {"192.168.1.2", 8081, -1, 0},  // Node 1
    {"192.168.1.3", 8082, -1, 0}   // Node 2
};

typedef struct {
    uint8_t *sgx_host_pubKey;
    uint8_t *sgx_guest_pubKey;
    uint8_t nodeID;
} ThreadArgs;

typedef struct {
    uint8_t nodeID;
    uint32_t blockID;
    uint8_t *output_buffer;
    size_t *output_len_ptr;
    size_t buf_len;
} TransferThreadArgs;

#endif