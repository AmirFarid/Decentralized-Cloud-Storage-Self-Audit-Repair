#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gf_rand.h>
#include "jerasure.h"
#include "jerasure/reed_sol.h"
#include <math.h>
#include <assert.h>

#include "galois.h"
#include "prgshuffle/prgshuffle.h"
#include <unistd.h>
#include <limits.h>
#define BLOCK_SIZE 4096


// I may not use these 
#define PAGE_SIZE 2048
#define SEGMENT_SIZE 512
#define PAGE_PER_BLOCK (BLOCK_SIZE / PAGE_SIZE)
#define SEGMENT_PER_BLOCK (BLOCK_SIZE / SEGMENT_SIZE)
#define SEGMENT_PER_PAGE (PAGE_SIZE / SEGMENT_SIZE)

#define talloc(type, num) ((type *) malloc((num) * sizeof(type)))

static double total_memcpy_bytes = 0;
static double total_xor_bytes = 0;
static double total_gf_bytes = 0;
long fileSize;
int rs_K;
int rs_N;

void get_file_size(FILE *file){
    fseek(file, 0 ,SEEK_END);
    long size = ftell(file);
    rewind(file);
    fileSize = size;

}

void write_file(uint16_t *chunks, int n, int chunk_size, int mode){

    //     char cwd[200];

    // if (getcwd(cwd, sizeof(cwd)) != NULL) {
    //     printf("Current working directory: %s\n", cwd);
    // } else {
    //     perror("getcwd() error");
    //     return 1;
    // }

        for (int i = 0; i < n; i++) {
        char filename[100];
        if (mode == 2){
            snprintf(filename, sizeof(filename), "App/decentralize/chunks/data_%d.dat", i);
        }else if (mode == 1){
            snprintf(filename, sizeof(filename), "App/decentralize/NF/data_%d.dat", i);
        }

        FILE *file = fopen(filename, "wb");
         if (!file) {
        perror("fopen failed");
        exit(EXIT_FAILURE);
    }
        // fwrite(&chunks[i *chunk_size], sizeof(uint16_t), chunk_size, file);
        if (fwrite(&chunks[i * chunk_size], sizeof(uint16_t), chunk_size, file) != chunk_size) {
        perror("fwrite failed");
        fclose(file);
        exit(EXIT_FAILURE);
    }
        fclose(file);
    }
}


void recover(int chunk_size, int padding_size) {
    FILE *output_file = fopen("recovered.dat", "wb");
    if (output_file == NULL) {
        fprintf(stderr, "Failed to open output file\n");
        return;
    }

    size_t total_written = 0;
    size_t target_size = fileSize;  // Use the global fileSize to know when to stop

    for (int i = 0; i < rs_K; i++) {
        uint16_t *buffer = (uint16_t *)malloc(chunk_size * sizeof(uint16_t));
        if (buffer == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            fclose(output_file);
            return;
        }

        char filename[20];
        sprintf(filename, "data_%d.dat", i);
        FILE *file = fopen(filename, "rb");
        if (file == NULL) {
            fprintf(stderr, "Failed to open %s\n", filename);
            free(buffer);
            continue;
        }

        size_t read_bytes = fread(buffer, sizeof(uint16_t), chunk_size, file);
        
        // Calculate how many bytes to write
        size_t bytes_to_write;
        if (i == rs_K - 1) {
            // For the last chunk, only write what's needed to reach the original file size
            bytes_to_write = (target_size - total_written) / sizeof(uint16_t);
            if (bytes_to_write > chunk_size) {
                bytes_to_write = chunk_size;
            }
        } else {
            bytes_to_write = chunk_size;
        }

        fwrite(buffer, sizeof(uint16_t), bytes_to_write, output_file);
        total_written += bytes_to_write * sizeof(uint16_t);

        fclose(file);
        free(buffer);
    }

    fclose(output_file);
}

// void encode(uint16_t *chunks, int n, int chunk_size) {
//     int symSize = 16;
//     int *matrix = reed_sol_vandermonde_coding_matrix(rs_K, rs_N-rs_K, symSize);
//     if (matrix == NULL) {
//         fprintf(stderr, "Failed to create coding matrix\n");
//         return;
//     }
//     for (int s = 0; s < chunk_size; s++) {
//         char **data_ptrs = malloc(sizeof(char *) * rs_K);
//         char **coding_ptrs = malloc(sizeof(char *) * (rs_N-rs_K));

//         // Allocate and initialize data pointers
//         for (int i = 0; i < rs_K; i++) {
//             data_ptrs[i] = malloc(sizeof(uint16_t));
//             // instead of chunk_size use 2048 
//             *((uint16_t *)data_ptrs[i]) = chunks[i * chunk_size + s];
//         }
//         // Allocate coding pointers
//         for (int i = 0; i < rs_N-rs_K; i++) {
//             coding_ptrs[i] = malloc(sizeof(uint16_t));
//             memset(coding_ptrs[i], 0, sizeof(uint16_t));
//         }
//         // Encode
//         jerasure_matrix_encode(rs_K, rs_N - rs_K, symSize, matrix, data_ptrs, coding_ptrs, sizeof(uint16_t));
//         // printf("rs encode symbol %d\n", s);
//         // Store results
//         for (int i = rs_K; i < rs_N; i++) {
//             chunks[i * chunk_size + s] = *((uint16_t *)coding_ptrs[i-rs_K]);
//         }
//         // Cleanup
//         for (int i = 0; i < rs_K; i++) free(data_ptrs[i]);
//         for (int i = 0; i < rs_N-rs_K; i++) free(coding_ptrs[i]);
//         free(data_ptrs);
//         free(coding_ptrs);
//     }
//     // only write the parity chunks
//     write_file(chunks, rs_N, chunk_size);
//     free(matrix);
// }


void encode(uint16_t *chunks, int n, int chunk_size, int mode) {
    int symSize = 16;
    int *matrix = reed_sol_vandermonde_coding_matrix(rs_K, rs_N-rs_K, symSize);
    if (matrix == NULL) {
        fprintf(stderr, "Failed to create coding matrix\n");
        return;
    }

    // number of blocks in the file
    int num_blocks = chunk_size / 2048;
    int counter = 0;
    for (size_t j = 0; j < num_blocks; j++)
    {
    
    for (int s = 0; s < 2048; s++) {
        char **data_ptrs = malloc(sizeof(char *) * rs_K);
        char **coding_ptrs = malloc(sizeof(char *) * (rs_N-rs_K));

        // Allocate and initialize data pointers
        for (int i = 0; i < rs_K; i++) {
            data_ptrs[i] = malloc(sizeof(uint16_t));
            // instead of chunk_size use 2048 
            *((uint16_t *)data_ptrs[i]) = chunks[(j * 2048 * rs_K) + (i * 2048) + s];
        }
        // Allocate coding pointers
        for (int i = 0; i < rs_N-rs_K; i++) {
            coding_ptrs[i] = malloc(sizeof(uint16_t));
            memset(coding_ptrs[i], 0, sizeof(uint16_t));
        }
        // Encode
        jerasure_matrix_encode(rs_K, rs_N-rs_K, symSize, matrix, data_ptrs, coding_ptrs, sizeof(uint16_t));
        // printf("rs encode symbol %d\n", s);
        // Store results
        for (int i = rs_K; i < rs_N; i++) {
          // I am pretty sure tomorrow I will regret this
            chunks[(num_blocks * 2048 * rs_K) + (j *2048) + ((i-rs_K) * num_blocks * 2048) + s] = *((uint16_t *)coding_ptrs[i-rs_K]);

            // chunks[(num_blocks * 2048 * rs_K) + ((i-rs_K) * num_blocks * 2048) + s] = *((uint16_t *)coding_ptrs[i-rs_K]);
        }
        // Cleanup
        for (int i = 0; i < rs_K; i++) free(data_ptrs[i]);
        for (int i = 0; i < rs_N-rs_K; i++) free(coding_ptrs[i]);
        free(data_ptrs);
        free(coding_ptrs);
    }
    }
    // only write the parity chunks
    write_file(chunks, rs_N, chunk_size, mode);
    free(matrix);
}


void test_rs(char *data, int k, int n, int *matrix){

  
    char **data_ptrs = malloc(sizeof(char *) * rs_K);
    char **coding_ptrs = malloc(sizeof(char *) * (rs_N-rs_K));



    for (int i = 0; i < rs_K; i++) {
        data_ptrs[i] = malloc(sizeof(char));
        memcpy(data_ptrs[i], &data[i], sizeof(char));
    }
    for (int i = 0; i < rs_N-rs_K; i++) {
        coding_ptrs[i] = malloc(sizeof(char));
        memset(coding_ptrs[i], 0, sizeof(char));
        // *((uint16_t *)coding_ptrs[i]) = *((uint16_t *)data[i+k]);
    }
    // int *matrix = reed_sol_vandermonde_coding_matrix(rs_K, rs_N-rs_K, 8);
    printf("matrix: %d\n", matrix[0]);
    printf("matrix: %d\n", matrix[1]);
    printf("matrix: %d\n", matrix[2]);
    printf("matrix: %d\n", matrix[3]);

    printf("data_ptrs: %X\n", data_ptrs);
    printf("coding_ptrs: %X\n", coding_ptrs);
    jerasure_matrix_encode(rs_K, rs_N-rs_K, 8, matrix, data_ptrs, coding_ptrs, sizeof(char));
    printf("encoded\n");



    for (int i = 0 ; i < rs_N - rs_K; i++) {
            memcpy(&data[(rs_K + i)], coding_ptrs[i], sizeof(char));
        }

}








int *erasures_to_erased(int k, int m, int *erasures)
{
  int td;
  int t_non_erased;
  int *erased;
  int i;

  td = k+m;
  erased = talloc(int, td);
  if (erased == NULL) return NULL;
  t_non_erased = td;

  for (i = 0; i < td; i++) erased[i] = 0;

  for (i = 0; erasures[i] != -1; i++) {
    // If the drive is erased, set it to 1
    if (erased[erasures[i]] == 0) {
      erased[erasures[i]] = 1;
      t_non_erased--;
      // If there are less than k non-erased drives, return NULL
      if (t_non_erased < k) {
        free(erased);
        return NULL;
      }
    }
  }
  return erased;
}



int invert_matrix(int *mat, int *inv, int rows, int w)
{
  int cols, i, j, k, x, rs2;
  int row_start, tmp, inverse;
 
  cols = rows;

  k = 0;
  for (i = 0; i < rows; i++) {
    for (j = 0; j < cols; j++) {
      inv[k] = (i == j) ? 1 : 0;
      k++;
    }
  }

  /* First -- convert into upper triangular  */
  for (i = 0; i < cols; i++) {
    row_start = cols*i;

    /* Swap rows if we ave a zero i,i element.  If we can't swap, then the 
       matrix was not invertible  */

    if (mat[row_start+i] == 0) { 
      for (j = i+1; j < rows && mat[cols*j+i] == 0; j++) ;
      if (j == rows) return -1;
      rs2 = j*cols;
      for (k = 0; k < cols; k++) {
        tmp = mat[row_start+k];
        mat[row_start+k] = mat[rs2+k];
        mat[rs2+k] = tmp;
        tmp = inv[row_start+k];
        inv[row_start+k] = inv[rs2+k];
        inv[rs2+k] = tmp;
      }
    }
 
    /* Multiply the row by 1/element i,i  */
    tmp = mat[row_start+i];
    if (tmp != 1) {
      inverse = galois_single_divide(1, tmp, w);
      for (j = 0; j < cols; j++) { 
        mat[row_start+j] = galois_single_multiply(mat[row_start+j], inverse, w);
        inv[row_start+j] = galois_single_multiply(inv[row_start+j], inverse, w);
      }
    }

    /* Now for each j>i, add A_ji*Ai to Aj  */
    k = row_start+i;
    for (j = i+1; j != cols; j++) {
      k += cols;
      if (mat[k] != 0) {
        if (mat[k] == 1) {
          rs2 = cols*j;
          for (x = 0; x < cols; x++) {
            mat[rs2+x] ^= mat[row_start+x];
            inv[rs2+x] ^= inv[row_start+x];
          }
        } else {
          tmp = mat[k];
          rs2 = cols*j;
          for (x = 0; x < cols; x++) {
            mat[rs2+x] ^= galois_single_multiply(tmp, mat[row_start+x], w);
            inv[rs2+x] ^= galois_single_multiply(tmp, inv[row_start+x], w);
          }
        }
      }
    }
  }

  /* Now the matrix is upper triangular.  Start at the top and multiply down  */

  for (i = rows-1; i >= 0; i--) {
    row_start = i*cols;
    for (j = 0; j < i; j++) {
      rs2 = j*cols;
      if (mat[rs2+i] != 0) {
        tmp = mat[rs2+i];
        mat[rs2+i] = 0; 
        for (k = 0; k < cols; k++) {
          inv[rs2+k] ^= galois_single_multiply(tmp, inv[row_start+k], w);
        }
      }
    }
  }
  return 0;
}

int make_decoding_matrix(int k, int m, int w, int *matrix, int *erased, int *decoding_matrix, int *dm_ids)
{
  int i, j, *tmpmat;

  j = 0;
  for (i = 0; j < k; i++) {
    if (erased[i] == 0) {
      dm_ids[j] = i;
      j++;
    }
  }

  tmpmat = talloc(int, k*k);
  if (tmpmat == NULL) { return -1; }
  for (i = 0; i < k; i++) {
    if (dm_ids[i] < k) {
      for (j = 0; j < k; j++) tmpmat[i*k+j] = 0;
      tmpmat[i*k+dm_ids[i]] = 1;
    } else {
      for (j = 0; j < k; j++) {
        tmpmat[i*k+j] = matrix[(dm_ids[i]-k)*k+j];
      }
    }
  }

  i = invert_matrix(tmpmat, decoding_matrix, k, w);
  free(tmpmat);
  return i;
}



void matrix_dotprod(int k, int w, int *matrix_row,
                          int *src_ids, int dest_id,
                          char **data_ptrs, char **coding_ptrs, int size)
{
  int init;
  char *dptr, *sptr;
  int i;

  if (w != 1 && w != 8 && w != 16 && w != 32) {
    fprintf(stderr, "ERROR: jerasure_matrix_dotprod() called and w is not 1, 8, 16 or 32\n");
    assert(0);
  }

  init = 0;

  dptr = (dest_id < k) ? data_ptrs[dest_id] : coding_ptrs[dest_id-k];

  /* First copy or xor any data that does not need to be multiplied by a factor */

  for (i = 0; i < k; i++) {
    if (matrix_row[i] == 1) {
      if (src_ids == NULL) {
        sptr = data_ptrs[i];
      } else if (src_ids[i] < k) {
        sptr = data_ptrs[src_ids[i]];
      } else {
        sptr = coding_ptrs[src_ids[i]-k];
      }
      if (init == 0) {
        memcpy(dptr, sptr, size);
        total_memcpy_bytes += size;
        init = 1;
      } else {
        galois_region_xor(sptr, dptr, size);
        total_xor_bytes += size;
      }
    }
  }

  /* Now do the data that needs to be multiplied by a factor */

  for (i = 0; i < k; i++) {
    if (matrix_row[i] != 0 && matrix_row[i] != 1) {
      if (src_ids == NULL) {
        sptr = data_ptrs[i];
      } else if (src_ids[i] < k) {
        sptr = data_ptrs[src_ids[i]];
      } else {
        sptr = coding_ptrs[src_ids[i]-k];
      }
      switch (w) {
        case 8:  galois_w08_region_multiply(sptr, matrix_row[i], size, dptr, init); break;
        case 16: galois_w16_region_multiply(sptr, matrix_row[i], size, dptr, init); break;
        case 32: galois_w32_region_multiply(sptr, matrix_row[i], size, dptr, init); break;
      }
      total_gf_bytes += size;
      init = 1;
    }
  }
}

/**
 * @brief Decode the data using the coding matrix erasures
 * 
 * @param k the number of data chunks
 * @param m the number of coding chunks
 * @param w the size of the field
 * @param matrix the coding matrix
 * @param erasures the erasures
 * @param data_ptrs the data pointers
 * @param coding_ptrs the coding pointers
 * @param size the size of the symbol
 * @return int | 0 if success, -1 if failed
 */
int matrix_decode(int k, int m, int w, int *matrix, int *erasures, int *data_ptrs, int *coding_ptrs, int size) {
    int i, edd, lastdrive;
    int *tmpids;
    int *erased, *decoding_matrix, *dm_ids;
    int row_k_ones = 1;

    if (w != 8 && w != 16 && w != 32) return -1;

    erased = erasures_to_erased(k, m, erasures);
    if (erased == NULL) return -1;

    /* Find the number of data drives failed */

    lastdrive = k;

    edd = 0;
    for (i = 0; i < k; i++) {
      if (erased[i]) {
        edd++;
            lastdrive = i;
          }
        }
    if (!row_k_ones || erased[k]) lastdrive = k;

      dm_ids = NULL;
      decoding_matrix = NULL;

      if (edd > 1 || (edd > 0 && (!row_k_ones || erased[k]))) {
        dm_ids = talloc(int, k);
        if (dm_ids == NULL) {
          free(erased);
          return -1;
        }

        decoding_matrix = talloc(int, k*k);
        if (decoding_matrix == NULL) {
          free(erased);
          free(dm_ids);
          return -1;
        }

        if (make_decoding_matrix(k, m, w, matrix, erased, decoding_matrix, dm_ids) < 0) {
          free(erased);
          free(dm_ids);
          free(decoding_matrix);
          return -1;
        }
      }

      /* Decode the data drives.  
         If row_k_ones is true and coding device 0 is intact, then only decode edd-1 drives.
         This is done by stopping at lastdrive.
         We test whether edd > 0 so that we can exit the loop early if we're done.
       */

      for (i = 0; edd > 0 && i < lastdrive; i++) {
        if (erased[i]) {
          matrix_dotprod(k, w, decoding_matrix+(i*k), dm_ids, i, data_ptrs, coding_ptrs, size);
          edd--;
        }
      }

      /* Then if necessary, decode drive lastdrive */

      if (edd > 0) {
        tmpids = talloc(int, k);
        if (!tmpids) {
          free(erased);
          free(dm_ids);
          free(decoding_matrix);
          return -1;
        }
        for (i = 0; i < k; i++) {
          tmpids[i] = (i < lastdrive) ? i : i+1;
        }
        matrix_dotprod(k, w, matrix, tmpids, lastdrive, data_ptrs, coding_ptrs, size);
        free(tmpids);
      }
    
      /* Finally, re-encode any erased coding devices */

      for (i = 0; i < m; i++) {
        if (erased[k+i]) {
          matrix_dotprod(k, w, matrix+(i*k), NULL, i+k, data_ptrs, coding_ptrs, size);
        }
      }

      free(erased);
      if (dm_ids != NULL) free(dm_ids);
      if (decoding_matrix != NULL) free(decoding_matrix);

      return 0;
}







void decode(int chunk_size, int *erasures) {
    
    int symSize = 16;
    
    // Create the original coding matrix
    int *matrix = reed_sol_vandermonde_coding_matrix(rs_K, rs_N-rs_K, symSize);
    
    // Allocate and read data from files
    char **data_ptrs = (char **)malloc(sizeof(char *) * rs_K);
    char **coding_ptrs = (char **)malloc(sizeof(char *) * (rs_N-rs_K));
    
    // Allocate memory for each data and coding pointer
    for (int i = 0; i < rs_K; i++) {
        data_ptrs[i] = (char *)malloc(sizeof(uint16_t));
    }
    for (int i = 0; i < rs_N-rs_K; i++) {
        coding_ptrs[i] = (char *)malloc(sizeof(uint16_t));
    }

    // Process each symbol
    for (int s = 0; s < chunk_size; s++) {
        // Read available chunks
        for (int i = 0; i < rs_N; i++) {
            char filename[20];
            sprintf(filename, "data_%d.dat", i);
            
            // Skip if this chunk is in erasures
            int is_erased = 0;
            for (int j = 0; erasures[j] != -1; j++) {
                if (erasures[j] == i) {
                    is_erased = 1;
                    break;
                }
            }
            
            if (!is_erased) {
                FILE *file = fopen(filename, "rb");
                if (file == NULL) continue;
                
                uint16_t value;
                fseek(file, s * sizeof(uint16_t), SEEK_SET);
                fread(&value, sizeof(uint16_t), 1, file);
                fclose(file);
                
                if (i < rs_K) {
                    *((uint16_t *)data_ptrs[i]) = value;
                } else {
                    *((uint16_t *)coding_ptrs[i-rs_K]) = value;
                } 
            }
        }

        // Decode
        int ret = jerasure_matrix_decode(rs_K, rs_N-rs_K, symSize, matrix, 1, erasures, 
                                       data_ptrs, coding_ptrs, sizeof(uint16_t));
        
        if (ret == 0) {
            // Write recovered data
            for (int i = 0; erasures[i] != -1; i++) {
                int idx = erasures[i];
                char filename[20];
                sprintf(filename, "data_%d.dat", idx);
                FILE *file = fopen(filename, "r+b");
                if (file == NULL) {
                    file = fopen(filename, "wb");
                }
                
                uint16_t value;
                if (idx < rs_K) {
                    value = *((uint16_t *)data_ptrs[idx]);
                } else {
                    value = *((uint16_t *)coding_ptrs[idx-rs_K]);
                }
                
                fseek(file, s * sizeof(uint16_t), SEEK_SET);
                fwrite(&value, sizeof(uint16_t), 1, file);
                fclose(file);
            }
        } else {
            fprintf(stderr, "Decoding failed for symbol %d\n", s);
        }
    }

    // Cleanup
    for (int i = 0; i < rs_K; i++) {
        free(data_ptrs[i]);
    }
    for (int i = 0; i < rs_N-rs_K; i++) {
        free(coding_ptrs[i]);
    }
    free(data_ptrs);
    free(coding_ptrs);
    free(matrix);
}

void read_file(const char *filename, uint16_t **chunks, int *chunk_size, int *padding_size, uint8_t *Shuffle_key, int mode) {
    
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open input file\n");
        return;
    }

    get_file_size(file);

    // Calculate chunk size
    int temp = (((fileSize + rs_K - 1) / rs_K + 2) & ~1) / sizeof(uint16_t);
    *chunk_size = ((temp + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
    
    // Calculate padding
    *padding_size = (rs_K * (*chunk_size) * sizeof(uint16_t)) - fileSize;
    if (*padding_size == (*chunk_size) * sizeof(uint16_t)) {
        *padding_size = 0;
    }

    // Allocate memory
    *chunks = (uint16_t *)calloc(rs_N * (*chunk_size), sizeof(uint16_t));
    if (*chunks == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return;
    }

    // Read data
    for (int i = 0; i < rs_K; i++) {
        size_t read_bytes = fread(&(*chunks)[i * (*chunk_size)], sizeof(uint16_t), *chunk_size, file);
        
        // Handle padding for last chunk
        if (i == rs_K - 1 && *padding_size > 0) {
            memset((uint8_t *)&(*chunks)[i * (*chunk_size)] + read_bytes * sizeof(uint16_t), 
                   0, *padding_size);
        }
    }

    // // calculate the number of block=4096 in the file
    int num_blocks = (*chunk_size / 2048) * rs_K;
    int numBits = (int)ceil(log2(num_blocks));

    // printf("N: %d\n", rs_N);
    // printf("K: %d\n", rs_K);

    // printf("num_blocks: %d\n", num_blocks);
    // printf("numBits: %d\n", numBits);
    // printf("chunk_size: %d\n", *chunk_size);


    // printf("enter to continue\n");
    // getchar();
    // printf("size %d\n", rs_K * (*chunk_size));
    // // sleep(10);
        // printf("chunks[%d]: %d\n", i, (*chunks)[i]);
    // for (int i = 0; i < rs_K * (*chunk_size); i++) {
    // for (int i = 0; i < (*chunk_size) * rs_K; i++) {
      // printf("fffffff");
        // printf("chunks[%d]: %d\n", i, (*chunks)[i]);
        // printf("chunks[%d]: %d\n", i, (int *)(*chunks)[i]);

    // }

    // uint16_t *chunks_shuffled = (uint16_t *)calloc(rs_N * (*chunk_size), sizeof(uint16_t));

    int permuted_index;

    for (int i = 0; i < num_blocks; i++) {
        permuted_index = feistel_network_prp(Shuffle_key, i, numBits);
        // printf("i: %d, permuted_index: %d\n", i, permuted_index);

      while (permuted_index >= num_blocks) {
        permuted_index = feistel_network_prp(Shuffle_key, permuted_index, numBits);
      }
        // permuted_index = feistel_prp(i, num_blocks, Shuffle_key, 31);
        // if (permuted_index < num_blocks) {
        //   break;
        // }
        // int permuted_index = feistel_prp(i, num_blocks, Shuffle_key, 31);
        // printf("i: %d, permuted_index: %d\n", i, permuted_index);
        // for (int j = 0; j < 4096; j++) {
        //     printf("j ==> %d\n", j);
        //     printf("chunks_shuffled[i * 4096]: %d\n", &(*chunks)[permuted_index * 4096 + j]);
        // }
        // memcpy(&chunks_shuffled[i * 4096], &(*chunks)[permuted_index * 4096], 4096 * sizeof(uint16_t));
        // for (int j = 0; j < 2049; j++) {
        //     chunks_shuffled[i * 2049 + j] = (*chunks)[permuted_index * 2049 + j];
        //     printf("chunks_shuffled[%d]: %hd | %hd\n", i * 2049 + j, chunks_shuffled[i * 2049 + j], (*chunks)[permuted_index * 2049 + j]);
        //   }
        // printf("=======================\n");
        // printf("before: chunks[%d]: %d\n", permuted_index * 2048 + 1, (*chunks)[permuted_index * 2048 + 1]);
        // printf("before chunks[%d]: %d\n", i * 2048 + 1, (*chunks)[i * 2048 + 1]);
        for (int j = 0; j < 2048; j++) {
          if (i <= permuted_index) {
            continue;
          }
          uint16_t temp = (*chunks)[permuted_index * 2048 + j];
          (*chunks)[permuted_index * 2048 + j] = (*chunks)[i * 2048 + j];
          (*chunks)[i * 2048 + j] = temp;
          // printf("index: %d\n", i );
            // chunks_shuffled[i * 4096 + j] = (*chunks)[permuted_index * 4096 + j];
            // printf("chunks_shuffled[%d]: %d\n", i * 2048 + j, (*chunks)[permuted_index * 2048 + j]);
          }
        // printf("---------------------------------\n");
        // printf("after: chunks[%d]: %d\n", permuted_index * 2048 + 1, (*chunks)[permuted_index * 2048 + 1]);
        // printf("after chunks[%d]: %d\n", i * 2048 + 1, (*chunks)[i * 2048 + 1]);
        // printf("=======================\n");
            // printf("chunks_shuffled[%d]: %d\n", 110000, (*chunks)[110000]);
            // (*chunks)[110000] = 100;

        // chunks_shuffled[i] = (*chunks)[permuted_index];
        // for (int j = 0; j < 4096; j++) {
        // }
    }

  
	// ----------------------------------- test -----------------------------------
	// int total_blocks = 4 * rs_K;
	// int blockNumInFile = (4 * 1) + 2;
  // int numBits2 = (int)ceil(log2(total_blocks));


	// // int permuted_index2 = feistel_network_prp(Shuffle_key, blockNumInFile, numBits2);
  // //       // printf("i: %d, permuted_index: %d\n", i, permuted_index);

  // //   while (permuted_index2 >= total_blocks) {
  // //     permuted_index2 = feistel_network_prp(Shuffle_key, permuted_index2, numBits2);
  // //   }
	
	// int *recoverable_block_indicies = (int *)malloc(sizeof(int) * total_blocks);
	// memset(recoverable_block_indicies, -1, total_blocks * sizeof(int));
	
	// int count = 0;

	// for (int i = 0; i < total_blocks; i++) {
	// 	if (i % rs_K == 0 && i != 0){
	// 		count++;
	// 	}
	// 	int tmp_index = feistel_network_prp(Shuffle_key, i, numBits2);
	// 	while (tmp_index >= total_blocks) {
	// 		tmp_index = feistel_network_prp(Shuffle_key, tmp_index, numBits2);
	// 	}
	// 	if (tmp_index == blockNumInFile) {
	// 		recoverable_block_indicies[tmp_index] = 1;
	// 		break;
	// 	}
	// }

	// int code_word_index = 0;
	// for (int i = 0; i < rs_K; i++) {
  //   printf("count: %d\n", count);
	// 	code_word_index = count * rs_K + i;
	// 	int tmp_index = feistel_network_prp(Shuffle_key, code_word_index, numBits);
	// 	while (tmp_index >= total_blocks) {
	// 		tmp_index = feistel_network_prp(Shuffle_key, tmp_index, numBits);
	// 	}
	// 	recoverable_block_indicies[tmp_index] = 1;
  //   printf("i: %d, permuted_index: %d\n", i, tmp_index);

	// }

  // printf("---------------------------------\n");

  // for (int i = 0; i < total_blocks; i++) {
  //   if (recoverable_block_indicies[i] == 1) {
  //     int internal_block_index = i % 4;
	//     int node_index = (i - internal_block_index) / 4;
  //     printf("recoverable_block_indicies[%d]: %d\n", i, recoverable_block_indicies[i]);
  //     printf("internal_block_index: %d\n", internal_block_index);
  //     printf("node_index: %d\n", node_index);
  //   }
  // }



    // printf("enter to continue\n");

    // getchar();
    encode(*chunks, rs_N, *chunk_size, mode);
    fclose(file);
}

void remove_file(int index) {
    char filename[20];
    sprintf(filename, "data_%d.dat", index);
    
    if (remove(filename) == 0) {
        printf("File %s successfully removed\n", filename);
    } else {
        fprintf(stderr, "Error removing file %s\n", filename);
    }
}

// And a function to remove multiple files:
void remove_files(int *indices) {
    for (int i = 0; indices[i] != -1; i++) {
        remove_file(indices[i]);
    }
}

int compare_files(const char *file1, const char *file2) {
    FILE *f1 = fopen(file1, "rb");
    FILE *f2 = fopen(file2, "rb");
    
    if (f1 == NULL || f2 == NULL) {
        fprintf(stderr, "Error opening files for comparison\n");
        if (f1) fclose(f1);
        if (f2) fclose(f2);
        return -1;
    }

    int result = 0;
    size_t bytes_read1, bytes_read2;
    unsigned char buf1[4096], buf2[4096];
    size_t position = 0;

    while (1) {
        bytes_read1 = fread(buf1, 1, sizeof(buf1), f1);
        bytes_read2 = fread(buf2, 1, sizeof(buf2), f2);

        if (bytes_read1 != bytes_read2) {
            printf("Files have different sizes\n");
            result = -1;
            break;
        }

        if (bytes_read1 == 0) {
            break;  // Reached end of both files
        }

        for (size_t i = 0; i < bytes_read1; i++) {
            if (buf1[i] != buf2[i]) {
                printf("Files differ at position %zu: %02X != %02X\n", 
                       position + i, buf1[i], buf2[i]);
                result = -1;
                goto end;  // Exit both loops
            }
        }
        position += bytes_read1;
    }
 end:
    fclose(f1);
    fclose(f2);
    
    if (result == 0) {
        printf("Files are identical\n");
    }
    return result;
}   


int initiate_rs(const char *original_file, int k, int n, uint8_t *Shuffle_key, int mode){
    // printf("N: %d, K: %d\n", n, k);
    rs_N = n;
    rs_K = k;
    // printf("rs_N: %d, rs_K: %d\n", rs_N, rs_K);
    uint16_t *chunks;
    int padding_size;
    int chunk_size;
    printf("original_file: %s\n", original_file);
    read_file(original_file, &chunks, &chunk_size, &padding_size, Shuffle_key, mode);
    free(chunks);
    return chunk_size/4096;
}


// int main(){
//     N = 5;
//     K = 3;
//     uint16_t *chunks;
//     int padding_size;
//     int chunk_size;
//     const char *original_file = "/home/amoghad1/project/all-decentralized/my-code/Decentralized-Cloud-Storage-Self-Audit-Repair/App-Enclave/testFile2";

//     printf("it's OK\n");
//     read_file(original_file, &chunks, &chunk_size, &padding_size);
//     // printf("padding_size %d \n", *chunks);
//     // write_file(chunks,K,chunk_size);
    
//     int erasures[] = {0, 2, -1};  // -1 marks the end of the array
//     remove_files(erasures);

//     // char command[256];
//     // snprintf(command, sizeof(command), "cp data_1.dat data_0.dat");
//     // system(command);

//     // int erasures2[] = {2, -1};  // -1 marks the end of the array
    

//     decode(chunk_size, erasures);

//     recover(chunk_size,padding_size);


//     printf("Comparing original and recovered files...\n");
//     if (compare_files(original_file, "recovered.dat") == 0) {
//         printf("Recovery successful!\n");
//     } else {
//         printf("Recovery failed - files are different\n");
//     }

//     if (chunks != NULL) {
//         free(chunks);
//     }


//     return 1;
// }