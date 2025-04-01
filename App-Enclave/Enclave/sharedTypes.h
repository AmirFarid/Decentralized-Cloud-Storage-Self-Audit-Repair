#ifndef SHARED_TYPES_H
#define SHARED_TYPES_H

#include <stdint.h>

// Security parameters
#define KEY_SIZE 16
#define MAC_SIZE 20
#define PRIME_LENGTH 80
#define SHA_DIGEST_LENGTH 20

// Erasure coding parameters
#define K 4                           // Number of data blocks
#define M 2                           // Number of parity blocks
#define N (K + M)                     // Total number of blocks (data + parity)

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

#define Max_PEER 5

#define SECRET_LENGTH ((PAGE_SIZE * 8) / 256) // One bit in secret message every 512 bits.
#define PARITY_START 5000 // Start address for parity data.

// Message types
#define MSG_REQUEST 1
#define MSG_RESPONSE 2

#define MAX_BLOCKS 10

// Request types
#define REQUEST_BLOCK 1
#define REQUEST_HANDSHAKE 2

// Response status
#define RESPONSE_SUCCESS 0
#define RESPONSE_ERROR 1

typedef struct Tag {
    int n;
    uint8_t prfKey[KEY_SIZE];
    uint8_t alpha[SEGMENT_PER_BLOCK][PRIME_LENGTH / 8];
    uint8_t MAC[MAC_SIZE];
} Tag;

// Data request/response structure
typedef struct {
    int type;                    // Type of request (e.g., REQUEST_BLOCK)
    int block_num;              // Physical block number in storage
    int data_num;               // Data block number in erasure coding scheme
    int source_node_id;         // ID of the requesting node
    int target_node_id;         // ID of the target node
    int is_valid;               // Whether the request is valid
    int data_len;               // Length of data (for responses)
    uint8_t data[BLOCK_SIZE];   // Data payload
    uint8_t hmac[KEY_SIZE];     // HMAC for data integrity
} DataRequest;

// Structure to hold file segments for recovery
typedef struct {
    struct {
        uint8_t data[BLOCK_SIZE];  // The actual block data
        int is_valid;              // Flag indicating if this block is valid
    } segments[MAX_BLOCKS];        // Array of segments, one for each block
    int total_blocks;              // Total number of blocks in the file
    int recovered_blocks;          // Number of blocks successfully recovered
} FileSegments;

// Data response structure
typedef struct {
    int status;                     // RESPONSE_SUCCESS or RESPONSE_ERROR
    int block_num;                  // Physical block number in storage
    int data_num;                   // Data block number in erasure coding scheme
    uint8_t data[BLOCK_SIZE];       // The actual data
    uint8_t hmac[KEY_SIZE];         // HMAC for data integrity verification
} DataResponse;

#endif // SHARED_TYPES_H
