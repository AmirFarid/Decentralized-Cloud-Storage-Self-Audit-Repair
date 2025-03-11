// #include <stdio.h>
// #include <stdlib.h>
// #include <stdint.h>
// #include <string.h>
// #include "rscoding.h"
// #include <unistd.h> 

// #define FIELD_SIZE 256  // Galois Field (GF 2^8)
// #define PRIM_POLY 0x11D // x^8 + x^4 + x^3 + x^2 + 1

// uint8_t gf_exp[FIELD_SIZE]; // Exponentiation table
// uint8_t gf_log[FIELD_SIZE]; // Logarithm table


// int N, K, chunk_size;
// uint8_t **data_chunks = NULL;
// uint8_t *parity = NULL;
// uint8_t galois_mult_table[FIELD_SIZE][FIELD_SIZE];

// // Galois Field initialization
// void gf_init() {
//     int x = 1;
//     for (int i = 0; i < FIELD_SIZE - 1; i++) {
//         gf_exp[i] = x;
//         gf_log[x] = i;
//         x = (x << 1) ^ (x & 0x80 ? PRIM_POLY : 0);
//     }
//     gf_exp[FIELD_SIZE - 1] = 1; // Loop back
// }

// // Galois Field multiplication
// int gf_mul(int a, int b) {
//     return (a && b) ? gf_exp[(gf_log[a] + gf_log[b]) % 255] : 0;
// }

// // Galois Field division
// int gf_div(int a, int b) {
//     return (a && b) ? gf_exp[(gf_log[a] + 255 - gf_log[b]) % 255] : 0;
// }

// // Galois Field inverse
// int gf_inv(int a) {
//     return gf_exp[255 - gf_log[a]];
// }

// // Generate Vandermonde matrix for encoding
// void generate_vandermonde(uint8_t *matrix, int k, int n) {
//     for (int i = 0; i < n; i++) {
//         for (int j = 0; j < k; j++) {
//             matrix[i * k + j] = gf_exp[(i * j) % 255]; // Vandermonde formula
//         }
//     }
// }

// //------------------------------------------------------------

// // Initialize Galois Field multiplication table
// void init_galois() {
//     for (int i = 0; i < FIELD_SIZE; i++) {
//         for (int j = 0; j < FIELD_SIZE; j++) {
//             uint8_t a = i, b = j, p = 0;
//             for (int k = 0; k < 8; k++) {
//                 if (b & 1) p ^= a;
//                 uint8_t carry = a & 0x80;
//                 a <<= 1;
//                 if (carry) a ^= 0x1d;
//                 b >>= 1;
//             }
//             galois_mult_table[i][j] = p;
//         }
//     }
// }

// // Galois Field multiplication
// uint8_t gf_mult(uint8_t a, uint8_t b) {
//     return galois_mult_table[a][b];
// }

// // ------------------------------------------------------------

// // Function to set (N, K) and allocate memory
// void set_params(int n, int k) {
//     N = n;
//     K = k;

//     if (K >= N || K <= 0 || N <= 0) {
//         printf("Error: Invalid N and K values.\n");
//         exit(1);
//     }
// }

// // Read file and split it into K equal chunks
// void read_file(const char *filename) {
//     FILE *file = fopen(filename, "rb");
//     if (!file) {
//         printf("Error: Could not open file %s\n", filename);
//         exit(1);
//     }

//     // Get file size
//     fseek(file, 0, SEEK_END);
//     long file_size = ftell(file);
//     rewind(file);

//     // Calculate chunk size
//     chunk_size = (file_size + K - 1) / K;  // Rounds up
//     int padding_size = (K * chunk_size) - file_size;  // Computes exact padding needed
//     printf("File size: %ld bytes, Chunk size: %d bytes\n", file_size, chunk_size);

//     // Allocate memory for data chunks
//     data_chunks = (uint8_t **)malloc(K * sizeof(uint8_t *));
//     parity = (uint8_t *)malloc((N - K) * chunk_size);

//     if (!data_chunks || !parity) {
//         printf("Error: Memory allocation failed!\n");
//         exit(1);
//     }

//     for (int i = 0; i < K; i++) {
//         data_chunks[i] = (uint8_t *)malloc(chunk_size);
//         if (!data_chunks[i]) {
//             printf("Error: Memory allocation failed!\n");
//             exit(1);
//         }
//          size_t bytes_read = fread(data_chunks[i], 1, chunk_size, file);

//         if (i == K - 1 && padding_size > 0) {
//             memset(data_chunks[i] + bytes_read, 0, padding_size);
//         }
//     }

//     fclose(file);
// }

// // Encoding: Generate parity chunks
// void rs_encode() {
//     printf("Encoding file...\n");
//     for (int i = 0; i < (N - K); i++) {
//         memset(parity + (i * chunk_size), 0, chunk_size);
//         for (int j = 0; j < K; j++) {
//             for (int b = 0; b < chunk_size; b++) {
//                 parity[i * chunk_size + b] ^= gf_mult(data_chunks[j][b], (i + 1));
//             }
//         }
//     }
// }

// // Write encoded chunks to files
// void write_chunks() {
//     for (int i = 0; i < K; i++) {
//         char filename[20];
//         sprintf(filename, "data_%d.dat", i);
//         FILE *file = fopen(filename, "wb");
//         fwrite(data_chunks[i], 1, chunk_size, file);
//         fclose(file);
//     }

//     for (int i = 0; i < (N - K); i++) {
//         char filename[20];
//         sprintf(filename, "parity_%d.dat", i);
//         FILE *file = fopen(filename, "wb");
//         fwrite(parity + (i * chunk_size), 1, chunk_size, file);
//         fclose(file);
//     }
// }

// // Function to check if a file exists
// int file_exists(const char *filename) {
//     return access(filename, F_OK) == 0;
// }

// // Function to remove a file if it exists
// void remove_file(const char *filename) {
//     if (file_exists(filename)) {
//         unlink(filename);
//         printf("Missing file detected: %s (Removed from repository)\n", filename);
//     }
// }

// // Recover lost chunks to files
// void rs_recover(int missing_index) {
//     printf("Decoding...\n");

//     // Check if index is valid
//     if (missing_index < 0 || missing_index >= N) {
//         printf(" Error: Invalid missing index!\n");
//         return;
//     }

//     char filename[20];

//     // Determine if it's a data chunk or a parity chunk
//     if (missing_index < K) {
//         sprintf(filename, "data_%d.dat", missing_index);
//     } else {
//         sprintf(filename, "parity_%d.dat", missing_index - K);
//     }

//     // Check if the file is actually missing
//     if (!file_exists(filename)) {
//         remove_file(filename);
//     } else {
//         printf("File %s exists, no need to recover.\n", filename);
//         return;
//     }

//     // Allocate memory for the recovered chunk
//     uint8_t *recovered = (uint8_t *)malloc(chunk_size);
//     if (!recovered) {
//         printf("Memory allocation failed!\n");
//         return;
//     }
//     memset(recovered, 0, chunk_size);

//     // Recover the missing chunk using the remaining data
//     if (missing_index < K) {
//         // Recovering a **data chunk** using parity
//         for (int i = 0; i < (N - K); i++) {
//             for (int b = 0; b < chunk_size; b++) {
//                 recovered[b] ^= gf_mult(parity[i * chunk_size + b], (missing_index + 1));
//             }
//         }
//     } else {
//         // Recovering a **parity chunk** using the data
//         int parity_idx = missing_index - K;
//         for (int i = 0; i < K; i++) {
//             for (int b = 0; b < chunk_size; b++) {
//                 recovered[b] ^= gf_mult(data_chunks[i][b], (parity_idx + 1));
//             }
//         }
//     }

//     // Save the recovered file back to the repository
//     FILE *file = fopen(filename, "wb");
//     if (!file) {
//         printf("Error: Could not write recovered file %s\n", filename);
//         free(recovered);
//         return;
//     }
//     fwrite(recovered, 1, chunk_size, file);
//     fclose(file);

//     printf("Successfully recovered and saved: %s\n", filename);

//     // Clean up memory
//     free(recovered);
// }

// void rs_decode() {
//     printf("Decoding process started...\n");

//     // Recover any missing chunks
//     for (int i = 0; i < N; i++) {
//         char filename[20];

//         // Determine filename for data or parity chunks
//         if (i < K) {
//             sprintf(filename, "data_%d.dat", i);
//         } else {
//             sprintf(filename, "parity_%d.dat", i - K);
//         }

//         // If the chunk is missing, attempt recovery
//         if (!file_exists(filename)) {
//             printf("Missing chunk detected: %s\n", filename);
//             rs_recover(i);
//         }
//     }

//     // Open the output file to store the reconstructed data
//     FILE *output_file = fopen("decoded_file.dat", "wb");
//     if (!output_file) {
//         printf("Error: Could not open output file for writing.\n");
//         return;
//     }

//     // Read the recovered chunks and write them to the output file in order
//     for (int i = 0; i < K; i++) {
//         char filename[20];
//         sprintf(filename, "data_%d.dat", i);
//         FILE *file = fopen(filename, "rb");

//         if (!file) {
//             printf("Error: Could not open chunk %s for reading.\n", filename);
//             fclose(output_file);
//             return;
//         }

//         // Allocate buffer to read each chunk
//         uint8_t *buffer = (uint8_t *)malloc(chunk_size);
//         if (!buffer) {
//             printf("Error: Memory allocation failed!\n");
//             fclose(file);
//             fclose(output_file);
//             return;
//         }

//         // Read and write chunk data
//         fread(buffer, 1, chunk_size, file);
//         fwrite(buffer, 1, chunk_size, output_file);

//         // Clean up
//         free(buffer);
//         fclose(file);
//     }

//     fclose(output_file);
//     printf("Decoding complete. Original file reconstructed as 'decoded_file.dat'.\n");
// }

// // Cleanup function
// void cleanup() {
//     for (int i = 0; i < K; i++) {
//         free(data_chunks[i]);
//     }
//     free(data_chunks);
//     free(parity);
// }
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
// #include "rscoding.h"
#include <unistd.h> 

#define FIELD_SIZE 65536  // Galois Field (GF 2^16)
#define PRIM_POLY 0x8809 // x^16 + x^12 + x^3 + x + 1,


int N, K, chunk_size;
uint16_t **data_chunks = NULL;
uint16_t *parity = NULL;
uint16_t galois_mult_table[FIELD_SIZE][FIELD_SIZE];
static long file_size;
uint16_t **buffer;

uint8_t *missing_data = NULL;
uint8_t *missing_parity = NULL;


uint16_t gf_mult(uint16_t a, uint16_t b) {
    uint16_t result = 0;

    while (b) {
        if (b & 1) {
            result ^= a;  // XOR if the lowest bit of b is set
        }
        b >>= 1;  // Shift b right
        a <<= 1;  // Shift a left (multiply by x)

        // If a overflows (goes beyond 16 bits), reduce using the primitive polynomial
        if (a & 0x10000) {
            a ^= PRIM_POLY;
        }
    }
    return result;
}

uint16_t gf_inverse(uint16_t a) {
    uint16_t u = a, v = PRIM_POLY, g1 = 1, g2 = 0;

    while (u != 1) {
        int j = __builtin_clz(u) - __builtin_clz(v);
        if (j < 0) {
            u ^= v;
            g1 ^= g2;
        } else {
            u ^= v << j;
            g1 ^= g2 << j;
        }
    }
    return g1;
}

// GF(2^16) Exponentiation using Repeated Squaring
uint16_t gf_pow(uint16_t base, uint16_t exp) {
    uint16_t result = 1;
    while (exp) {
        if (exp & 1) result = gf_mult(result, base); // Multiply if the bit is set
        base = gf_mult(base, base); // Square the base
        exp >>= 1; // Shift exponent
    }
    return result;
}

uint16_t gf_sub(uint16_t a, uint16_t b) {
    return a ^ b;  // In GF(2^m), subtraction is identical to addition.
}

void swap_rows(uint16_t A[][K], int i, int k) {
    for (int j = 0; j < K; j++) {
        uint16_t temp = A[i][j];
        A[i][j] = A[k][j];
        A[k][j] = temp;
    }
}

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
    file_size = ftell(file);
    rewind(file);

    // Calculate chunk size
    chunk_size = (((file_size + K - 1) / K + 2) & ~1) / sizeof(uint16_t); // even 
    int padding_size = (K * chunk_size *padding_size) - file_size;  // Computes exact padding needed
    printf("File size: %ld bytes, Chunk size: %d bytes\n", file_size, chunk_size);

    // Allocate memory for data chunks
    data_chunks = (uint16_t **)malloc(K * sizeof(uint16_t *));
    parity = (uint16_t *)malloc((N - K) * chunk_size * sizeof(uint16_t));

    if (!data_chunks || !parity) {
        printf("Error: Memory allocation failed!\n");
        exit(1);
    }

    for (int i = 0; i < K; i++) {
        data_chunks[i] = (uint16_t *)malloc(chunk_size * sizeof(uint16_t));
        if (!data_chunks[i]) {
            printf("Error: Memory allocation failed!\n");
            exit(1);
        }
         size_t read_bytes = fread(data_chunks[i], 1, chunk_size, file);

        if (i == K - 1 && padding_size > 0) {
            memset((uint8_t*)data_chunks[i] + read_bytes, 0, padding_size);
        }
    }

    fclose(file);
}



// Encoding: Generate parity chunks
void rs_encode() {
    printf("Encoding file...\n");
    for (int i = 0; i < (N - K); i++) {
        uint16_t x_i = gf_pow(2, i); // Choose evaluation point
        memset(parity + (i * chunk_size), 0, chunk_size * sizeof(uint16_t));
        for (int j = 0; j < K; j++) {
            for (int b = 0; b < chunk_size; b++) {
                parity[i * chunk_size + b] ^= gf_mult(data_chunks[j][b], gf_pow(x_i, j));             
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
        fwrite(data_chunks[i], sizeof(uint16_t), chunk_size, file);
        fclose(file);
    }

    for (int i = 0; i < (N - K); i++) {
        char filename[20];
        sprintf(filename, "parity_%d.dat", i);
        FILE *file = fopen(filename, "wb");
        fwrite(parity + (i * chunk_size), sizeof(uint16_t), chunk_size, file);
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

void check_existed_chunks(){

    
    
    printf("Recovering 0-1\n");

    missing_data = (uint8_t *)malloc(K * sizeof(uint8_t));
    
    missing_parity = (uint8_t *)malloc((N - K) * sizeof(uint8_t));



    printf("Recovering 0-1-1\n");

    

    memset(missing_data, 0, K *sizeof(uint8_t) );
    memset(missing_parity, 0, (N-K) *sizeof(uint8_t));

    printf("Recovering 0-1-2\n");

    // int padding_size = (K * chunk_size) - file_size;
    // printf("Padding size: %d \n",padding_size);
    // Read the recovered chunks and write them to the output file in order
    buffer = (uint16_t **)malloc(N * sizeof(uint16_t *));

    printf("Recovering 0-2\n");

    for (int i = 0; i < N; i++) {

        buffer[i] = (uint16_t *)malloc(chunk_size * sizeof(uint16_t));
        if (!buffer[i]) {
            printf("Memory allocation failed for row %d!\n", i);
            return;
        }
    printf("Recovering...0-3-%d\n",i);

        char filename[20];
        
        if (i < K){
        sprintf(filename, "data_%d.dat", i);
        missing_data[i] = file_exists(filename)?0:1;
        }else{
        sprintf(filename, "parity_%d.dat", i - K);
        missing_parity[i - K] = file_exists(filename)?0:1;
        }

        FILE *file = fopen(filename, "rb");
        if (!file) {
            printf("Error: chunk %s not found.\n", filename);
            continue;
        }
    printf("Recovering...0-3-%d-2\n",i);
        
        // Read and write chunk data
        fread(buffer[i], 1, chunk_size, file);

        // Clean up
        fclose(file);
        
    }

}

// Parity recovery
void rs_recover_parity(){

    printf("Encoding recovered parity file...\n");

    for (int i = 0; i < (N - K); i++) {
        if(missing_parity[i]){
            // memset(parity + (i * chunk_size), 0, chunk_size * sizeof(uint16_t));
            memset(buffer[K + i], 0, chunk_size * sizeof(uint16_t));
            uint16_t x_i = gf_pow(2, i);
            for (int j = 0; j < K; j++) {
                for (int b = 0; b < chunk_size; b++) {
                    buffer[K + i][b] ^= gf_mult(buffer[j][b], x_i);
                }
            }
        }

        char filename[20];
        sprintf(filename, "parity_%d.dat", i);
        FILE *file = fopen(filename, "wb");
        fwrite(buffer[K+i], sizeof(uint16_t), chunk_size, file);
        fclose(file);

    }

}

// Data rcovery

// void gaussian_elimination(uint16_t matrix[K][K], uint16_t inverse[K][K]) {
//     for (int i = 0; i < K; i++) {
//         uint16_t inv = gf_inverse(matrix[i][i]);  // Compute inverse in GF(2^16)
//         for (int j = 0; j < K; j++) {
//             matrix[i][j] = gf_mult(matrix[i][j], inv);
//             inverse[i][j] = (i == j) ? inv : 0;
//         }
//     }

//     for (int i = 0; i < K; i++) {
//         for (int j = 0; j < K; j++) {
//             if (i != j) {
//                 uint16_t factor = matrix[j][i];
//                 for (int k = 0; k < K; k++) {
//                     matrix[j][k] ^= gf_mult(factor, matrix[i][k]);
//                     inverse[j][k] ^= gf_mult(factor, inverse[i][k]);
//                 }
//             }
//         }
//     }
// }

void invert_matrix(uint16_t A[K][K], uint16_t A_inv[K][K], int n) {
    // Initialize A_inv as the identity matrix
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            A_inv[i][j] = (i == j) ? 1 : 0;
        }
    }
    printf("Recovering3.....21\n");    

    // Forward elimination
    for (int i = 0; i < n; i++) {
        // Find pivot and swap rows if necessary
        if (A[i][i] == 0) {
            for (int k = i + 1; k < n; k++) {
                if (A[k][i] != 0) {
                    // Swap rows i and k in A and A_inv
                    swap_rows(A, i, k);
                    swap_rows(A_inv, i, k);
                    break;
                }
            }
        }
    printf("Recovering3.....2-%d\n",i);    

        // Normalize pivot row
        uint16_t pivot = A[i][i];
        uint16_t pivot_inv = gf_inverse(pivot);
        for (int j = 0; j < n; j++) {
            A[i][j] = gf_mult(A[i][j], pivot_inv);
            A_inv[i][j] = gf_mult(A_inv[i][j], pivot_inv);
        }
    printf("Recovering3.....2-%d....1\n",i);    

        // Eliminate below the pivot
        for (int k = i + 1; k < n; k++) {
            uint16_t factor = A[k][i];
            for (int j = 0; j < n; j++) {
                A[k][j] = gf_sub(A[k][j], gf_mult(factor, A[i][j]));
                A_inv[k][j] = gf_sub(A_inv[k][j], gf_mult(factor, A_inv[i][j]));
            }
        }
    printf("Recovering3.....2-%d....2\n",i);    

    }
    
    // Backward elimination
    for (int i = n - 1; i >= 0; i--) {
        for (int k = i - 1; k >= 0; k--) {
            uint16_t factor = A[k][i];
            for (int j = 0; j < n; j++) {
                A[k][j] = gf_sub(A[k][j], gf_mult(factor, A[i][j]));
                A_inv[k][j] = gf_sub(A_inv[k][j], gf_mult(factor, A_inv[i][j]));
            }
        }
    }
    
    // After these operations, A should be the identity matrix and A_inv is the inverse.
}


void construct_encoding_matrix(uint16_t matrix[K][K]) {
    
    int *existing_indices = malloc(K * sizeof(int));
    if (!existing_indices) {
        perror("malloc");
        exit(1);
    }
    int idx = 0;
    for (int j = 0; j < N; j++) {
        if (!missing_data[j]) {
            existing_indices[idx++] = j;
            if (idx == (K)) break;
        } else if (j >= K && !missing_parity[j - K])
        {
            existing_indices[idx++] = j;
            if (idx == (K)) break;
        }
        
    }
    

    for (int i = 0; i < idx; i++) {
        uint16_t x = gf_pow(2, i);
        int counter = 0;
        for (int j = 0; j < idx; j++) {
            if (existing_indices[i] < K)
            {
                if (i == j){
                    matrix[i][i] = 1;
                }else{
                    matrix[i][j] = 0;
                }
            } else {
                matrix[i][j] = gf_pow(x, counter);
                counter++;
            }
            
        }
    }
    
    free(existing_indices);
}

void rs_recover_data() {
    
    uint16_t *recovered[K]; 
    uint16_t encoding_matrix[K][K]; 
    uint16_t inverse[K][K];

    // Allocate memory for full chunk size
    for (int i = 0; i < K; i++) {
        recovered[i] = (uint16_t *)malloc(chunk_size * sizeof(uint16_t));
        if (!recovered[i]) {
            printf("Memory allocation failed for recovered chunk %d\n", i);
            exit(1);
        }
    }

    printf("Recovering3.....1\n");    

    // Step 1: Construct K x K encoding matrix
    construct_encoding_matrix(encoding_matrix);
    printf("Recovering3.....2\n");    

    // Step 2: Invert the matrix using Gaussian elimination
    invert_matrix(encoding_matrix, inverse, K);
    printf("Recovering3.....3\n");    

    // Step 3: Initialize the recovered data to 0 (Move memset out of the loop)
    for (int i = 0; i < K; i++) {
        memset(recovered[i], 0, chunk_size * sizeof(uint16_t));
    }

    // Step 4: Multiply inverse matrix with parity to solve for missing data
    for (int i = 0; i < K; i++) {
         int col = 0; 
        for (int j = 0; j < N; j++) {
            if ((j < K && missing_data[j]) || (j >= K && missing_parity[j-K])) {
            continue;
            }

            if (j < K)
            {
               for (int b = 0; b < chunk_size; b++) {
                    recovered[i][b] ^= gf_mult(inverse[i][col], data_chunks[j][b]);
                }
                col++;
            }else
            {
               for (int b = 0; b < chunk_size; b++) {
                    recovered[i][b] ^= gf_mult(inverse[i][col], parity[(j-K) * chunk_size + b]);
                }
                col++;
            }
            if (col == K)
            {
                break;
            }
            
        } 
    }

        for (int i = 0; i < K; i++) {
        if(missing_data[i]){
            char filename[20];
            sprintf(filename, "data_%d.dat", i);
            FILE *file = fopen(filename, "wb");
            fwrite(recovered[i], sizeof(uint16_t), chunk_size, file);
            fclose(file);
            missing_data[i] = 0;
        }
    }


    // Step 5: Free allocated memory
    for (int i = 0; i < K; i++) {
        free(recovered[i]);
    }
}



// Recover lost chunks to files
void rs_recover() {
    printf("Recovering...\n");

    check_existed_chunks();

    printf("Recovering2...\n");

    int d_counter = 0;
    int p_counter = 0;

    for (int i = 0; i < N; i++)
    {
    printf("Recovering2...%d\n",i);

        if(i< K){
            d_counter += missing_data[i];
        }else{
            p_counter += missing_parity[i-K];
        }
    }

    printf("Recovering3...\n");    

    if ( p_counter > 0 && d_counter>0){


    }else if (p_counter != 0)
    {
    printf("Recovering3...enter\n");    

        rs_recover_parity();
    printf("Recovering3...end\n");    


    }else{
    printf("Recovering32...enter\n");    

        rs_recover_data();

    printf("Recovering32...end\n");    

    }
    printf("Recovering4...\n");    


}

void rs_decode() {
    printf("Decoding process started...\n");

    // Request data from other peers
    // Recover any missing chunks

    rs_recover();

    // Open the output file to store the reconstructed data
    FILE *output_file = fopen("decoded_file.dat", "wb");
    if (!output_file) {
        printf("Error: Could not open output file for writing.\n");
        return;
    }

    int padding_size = (K * chunk_size) - file_size;
    // printf("Padding size: %d \n",padding_size);


    // Read the recovered chunks and write them to the output file in order
    for (int i = 0; i < K; i++) {
        char filename[20];
        sprintf(filename, "data_%d.dat", i);
        FILE *file = fopen(filename, "rb");

        // printf("I am in rs_recover");

        if (!file) {
            printf("Error: Could not open chunk %s for reading.\n", filename);
            fclose(output_file);
            return;
        }

        // Allocate buffer to read each chunk
        uint16_t *buffer = (uint16_t *)malloc(chunk_size);
        if (!buffer) {
            printf("Error: Memory allocation failed!\n");
            fclose(file);
            fclose(output_file);
            return;
        }

        // Read and write chunk data
        fread(buffer, 1, chunk_size, file);
         if (i == K - 1) {
            fwrite(buffer, sizeof(uint16_t), chunk_size - padding_size, output_file);
        } else {
            fwrite(buffer, sizeof(uint16_t), chunk_size, output_file);
        }


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
    free(missing_data);
    free(missing_parity);
}

int main(){
    printf("Start");
    set_params(5,3);
    read_file("/home/amoghad1/project/jsosh/Decentralized-Cloud-Storage-Self-Audit-Repair/App-Enclave/testFile");
    rs_encode();
    printf("writing chunks down\n");
    write_chunks();
    printf("Removing files\n");
    remove_file("./data_2.dat");
    // remove_file("./data_1.dat");
    rs_decode();

    return 0;
}