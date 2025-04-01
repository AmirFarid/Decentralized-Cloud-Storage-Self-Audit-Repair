





// void recover_data_chunk(uint8_t *recovered, int missing_data_index) {
//     for (int b = 0; b < chunk_size; b++) {
//         recovered[b] = gf_div(
//             parity[chunk_size + b] ^ gf_mult(data_chunks[0][b], 1) ^ gf_mult(data_chunks[2][b], 3),
//             2
//         );
//     }
// }

// void recompute_parity_chunk(uint8_t *recovered_parity) {
//     for (int b = 0; b < chunk_size; b++) {
//         recovered_parity[b] = gf_mult(data_chunks[0][b], 1) ^ gf_mult(data_chunks[1][b], 2) ^ gf_mult(data_chunks[2][b], 3);
//     }
// }


// void identify_parity_chunks(uint8_t *recovered_chunks[], int missing_indices[], int num_missing) {
//     for (int i = 0; i < num_missing; i++) {
//         if (missing_indices[i] < K) {
//             printf("✅ Recovered Data Chunk: data_%d\n", missing_indices[i]);
//         } else {
//             printf("🟠 Recovered Parity Chunk: parity_%d\n", missing_indices[i] - K);
//         }
//     }
// }


void recover_missing_chunks(uint8_t *recovered_chunks[], int missing_indices[], int num_missing) {
    uint8_t vandermonde[K][K];  // Vandermonde matrix
    uint8_t inverted[K][K];     // Inverted matrix for decoding
    uint8_t rhs[K][chunk_size]; // Right-hand side (known values)
    
    // Step 1: Build the Vandermonde matrix
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < K; j++) {
            vandermonde[i][j] = gf_mult(i + 1, j);  // Example coefficient
        }
    }

    // Step 2: Invert the matrix in GF(256)
    invert_matrix_GF256(vandermonde, inverted, K);

    // Step 3: Build RHS (right-hand side) using available chunks
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < chunk_size; j++) {
            rhs[i][j] = available_chunks[i][j]; // Fill with known data/parity
        }
    }

    // Step 4: Solve for missing chunks using matrix multiplication
    for (int i = 0; i < num_missing; i++) {
        int idx = missing_indices[i];
        for (int j = 0; j < chunk_size; j++) {
            recovered_chunks[i][j] = 0;
            for (int k = 0; k < K; k++) {
                recovered_chunks[i][j] ^= gf_mult(inverted[i][k], rhs[k][j]);
            }
        }
    }

    printf("✅ Successfully recovered all missing chunks!\n");
}






/**
 * Applies (n, k) erasure coding inside an SGX enclave.
 *
 * @param fileNum - Index of the file in the `files` array.
 * @param encoded_chunks - Pointer to an enclave-allocated array storing `n` encoded chunks.
 *
 * @return 0 on success, -1 on failure.
 */
int encode_with_erasure_coding(int fileNum, uint8_t **encoded_chunks) {
    if (fileNum < 0 || fileNum >= MAX_FILES || !files[fileNum].inUse) {
        ocall_print("Error: Invalid file index\n");
        return -1;
    }

    // Retrieve file metadata
    int k = files[fileNum].k;       // Data chunks
    int n = files[fileNum].n;       // Total chunks (data + parity)
    int numBlocks = files[fileNum].numBlocks;  // Total number of blocks

    // Calculate correct chunk size
    int chunk_size = (numBlocks * BLOCK_SIZE) / k;  // Divide actual data into k chunks

    uint8_t *data_chunks[k];
    uint8_t *parity_chunks[n - k];

    // Allocate enclave memory for data and parity chunks
    for (int i = 0; i < k; i++) {
        data_chunks[i] = (uint8_t *)malloc(chunk_size);
        if (!data_chunks[i]) {
            ocall_print("Error: Memory allocation failed for data_chunks\n");
            return -1;
        }
    }

    for (int i = 0; i < (n - k); i++) {
        parity_chunks[i] = (uint8_t *)malloc(chunk_size);
        if (!parity_chunks[i]) {
            ocall_print("Error: Memory allocation failed for parity_chunks\n");
            return -1;
        }
        memset(parity_chunks[i], 0, chunk_size);  // Initialize parity data
    }

    // Generate Reed-Solomon coding matrix
    int *matrix = reed_sol_vandermonde_coding_matrix(k, n, 8);
    if (!matrix) {
        ocall_print("Error: Failed to generate coding matrix\n");
        return -1;
    }

    // Encode data using Jerasure
    jerasure_matrix_encode(k, n, 8, matrix, (char **)data_chunks, (char **)parity_chunks, chunk_size);

    // Store encoded chunks inside the enclave memory
    for (int i = 0; i < k; i++) {
        encoded_chunks[i] = data_chunks[i];
    }
    for (int i = 0; i < (n - k); i++) {
        encoded_chunks[k + i] = parity_chunks[i];
    }

    // Free matrix memory
    free(matrix);

    ocall_print("Erasure coding completed successfully!\n");
    return 0; // Success
}

