#ifndef RS_CODING_H
#define RS_CODING_H

#include <stdint.h>

extern int N, K;
extern uint8_t *data;
extern uint8_t *parity;

void init_galois();
void set_params(int n, int k);
void read_file(const char *filename);
void rs_encode();
void rs_decode(int missing_index);
void write_chunks();
void cleanup();

#endif
