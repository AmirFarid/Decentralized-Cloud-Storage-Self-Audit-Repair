#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "rscoding.h"
#include <unistd.h> 

#define FIELD_SIZE 256  // Galois Field (GF 2^8)
#define PRIM_POLY 0x11D // x^8 + x^4 + x^3 + x^2 + 1

uint8_t gf_exp[FIELD_SIZE]; // Exponentiation table
uint8_t gf_log[FIELD_SIZE]; // Logarithm table


int N, K, chunk_size;
uint8_t **data_chunks = NULL;
uint8_t *parity = NULL;
uint8_t galois_mult_table[FIELD_SIZE][FIELD_SIZE];

// Galois Field initialization
void gf_init() {
    int x = 1;
    for (int i = 0; i < FIELD_SIZE - 1; i++) {
        gf_exp[i] = x;
        gf_log[x] = i;
        x = (x << 1) ^ (x & 0x80 ? PRIM_POLY : 0);
    }
    gf_exp[FIELD_SIZE - 1] = 1; // Loop back
}

// Galois Field multiplication
int gf_mul(int a, int b) {
    return (a && b) ? gf_exp[(gf_log[a] + gf_log[b]) % 255] : 0;
}

// Galois Field division
int gf_div(int a, int b) {
    return (a && b) ? gf_exp[(gf_log[a] + 255 - gf_log[b]) % 255] : 0;
}

// Galois Field inverse
int gf_inv(int a) {
    return gf_exp[255 - gf_log[a]];
}

// Generate Vandermonde matrix for encoding
void generate_vandermonde(uint8_t *matrix, int k, int n) {
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < k; j++) {
            matrix[i * k + j] = gf_exp[(i * j) % 255]; // Vandermonde formula
        }
    }
}

//------------------------------------------------------------

// Initialize Galois Field multiplication table
void init_galois() {
    for (int i = 0; i < FIELD_SIZE; i++) {
        for (int j = 0; j < FIELD_SIZE; j++) {
            uint8_t a = i, b = j, p = 0;
            for (int k = 0; k < 8; k++) {
                if (b & 1) p ^= a;
                uint8_t carry = a & 0x80;
                a <<= 1;
                if (carry) a ^= 0x1d;
                b >>= 1;
            }
            galois_mult_table[i][j] = p;
        }
    }
}

// Galois Field multiplication
uint8_t gf_mult(uint8_t a, uint8_t b) {
    return galois_mult_table[a][b];
}

// ------------------------------------------------------------

// Function to set (N, K) and allocate memory
void set_params(int n, int k) {
    N = n;
    K = k;

    if (K >= N || K <= 0 || N <= 0) {
        printf("Error: Invalid N and K values.\n");
        exit(1);
    }
}

// Read file and split it into K equal chunks
void read_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Could not open file %s\n", filename);
        exit(1);
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    // Calculate chunk size
    chunk_size = (file_size + K - 1) / K;  // Ensure rounding up
    printf("File size: %ld bytes, Chunk size: %d bytes\n", file_size, chunk_size);

    // Allocate memory for data chunks
    data_chunks = (uint8_t **)malloc(K * sizeof(uint8_t *));
    parity = (uint8_t *)malloc((N - K) * chunk_size);

    if (!data_chunks || !parity) {
        printf("Error: Memory allocation failed!\n");
        exit(1);
    }

    for (int i = 0; i < K; i++) {
        data_chunks[i] = (uint8_t *)malloc(chunk_size);
        if (!data_chunks[i]) {
            printf("Error: Memory allocation failed!\n");
            exit(1);
        }
        fread(data_chunks[i], 1, chunk_size, file);
    }

    fclose(file);
}

// Encoding: Generate parity chunks
void rs_encode() {
    printf("Encoding file...\n");
    for (int i = 0; i < (N - K); i++) {
        memset(parity + (i * chunk_size), 0, chunk_size);
        for (int j = 0; j < K; j++) {
            for (int b = 0; b < chunk_size; b++) {
                parity[i * chunk_size + b] ^= gf_mult(data_chunks[j][b], (i + 1));
            }
        }
    }
}

// Write encoded chunks to files
void write_chunks() {
    for (int i = 0; i < K; i++) {
        char filename[20];
        sprintf(filename, "data_%d.dat", i);
        FILE *file = fopen(filename, "wb");
        fwrite(data_chunks[i], 1, chunk_size, file);
        fclose(file);
    }

    for (int i = 0; i < (N - K); i++) {
        char filename[20];
        sprintf(filename, "parity_%d.dat", i);
        FILE *file = fopen(filename, "wb");
        fwrite(parity + (i * chunk_size), 1, chunk_size, file);
        fclose(file);
    }
}

// Function to check if a file exists
int file_exists(const char *filename) {
    return access(filename, F_OK) == 0;
}

// Function to remove a file if it exists
void remove_file(const char *filename) {
    if (file_exists(filename)) {
        unlink(filename);
        printf("Missing file detected: %s (Removed from repository)\n", filename);
    }
}

// Recover lost chunks to files
void rs_recover(int missing_index) {
    printf("Decoding...\n");

    // Check if index is valid
    if (missing_index < 0 || missing_index >= N) {
        printf(" Error: Invalid missing index!\n");
        return;
    }

    char filename[20];

    // Determine if it's a data chunk or a parity chunk
    if (missing_index < K) {
        sprintf(filename, "data_%d.dat", missing_index);
    } else {
        sprintf(filename, "parity_%d.dat", missing_index - K);
    }

    // Check if the file is actually missing
    if (!file_exists(filename)) {
        remove_file(filename);
    } else {
        printf("File %s exists, no need to recover.\n", filename);
        return;
    }

    // Allocate memory for the recovered chunk
    uint8_t *recovered = (uint8_t *)malloc(chunk_size);
    if (!recovered) {
        printf("Memory allocation failed!\n");
        return;
    }
    memset(recovered, 0, chunk_size);

    // Recover the missing chunk using the remaining data
    if (missing_index < K) {
        // Recovering a **data chunk** using parity
        for (int i = 0; i < (N - K); i++) {
            for (int b = 0; b < chunk_size; b++) {
                recovered[b] ^= gf_mult(parity[i * chunk_size + b], (missing_index + 1));
            }
        }
    } else {
        // Recovering a **parity chunk** using the data
        int parity_idx = missing_index - K;
        for (int i = 0; i < K; i++) {
            for (int b = 0; b < chunk_size; b++) {
                recovered[b] ^= gf_mult(data_chunks[i][b], (parity_idx + 1));
            }
        }
    }

    // Save the recovered file back to the repository
    FILE *file = fopen(filename, "wb");
    if (!file) {
        printf("Error: Could not write recovered file %s\n", filename);
        free(recovered);
        return;
    }
    fwrite(recovered, 1, chunk_size, file);
    fclose(file);

    printf("Successfully recovered and saved: %s\n", filename);

    // Clean up memory
    free(recovered);
}

void rs_decode() {
    printf("Decoding process started...\n");

    // Recover any missing chunks
    for (int i = 0; i < N; i++) {
        char filename[20];

        // Determine filename for data or parity chunks
        if (i < K) {
            sprintf(filename, "data_%d.dat", i);
        } else {
            sprintf(filename, "parity_%d.dat", i - K);
        }

        // If the chunk is missing, attempt recovery
        if (!file_exists(filename)) {
            printf("Missing chunk detected: %s\n", filename);
            rs_recover(i);
        }
    }

    // Open the output file to store the reconstructed data
    FILE *output_file = fopen("decoded_file.dat", "wb");
    if (!output_file) {
        printf("Error: Could not open output file for writing.\n");
        return;
    }

    // Read the recovered chunks and write them to the output file in order
    for (int i = 0; i < K; i++) {
        char filename[20];
        sprintf(filename, "data_%d.dat", i);
        FILE *file = fopen(filename, "rb");

        if (!file) {
            printf("Error: Could not open chunk %s for reading.\n", filename);
            fclose(output_file);
            return;
        }

        // Allocate buffer to read each chunk
        uint8_t *buffer = (uint8_t *)malloc(chunk_size);
        if (!buffer) {
            printf("Error: Memory allocation failed!\n");
            fclose(file);
            fclose(output_file);
            return;
        }

        // Read and write chunk data
        fread(buffer, 1, chunk_size, file);
        fwrite(buffer, 1, chunk_size, output_file);

        // Clean up
        free(buffer);
        fclose(file);
    }

    fclose(output_file);
    printf("Decoding complete. Original file reconstructed as 'decoded_file.dat'.\n");
}

// Cleanup function
void cleanup() {
    for (int i = 0; i < K; i++) {
        free(data_chunks[i]);
    }
    free(data_chunks);
    free(parity);
}
