#ifndef ENDEFS_H
#define ENDEFS_H
#include <stdint.h>
#include <openssl/bn.h>
#include "sharedTypes.h"

#define AUDIT_INDICATOR  "AUDITX"
#define ENCODE_INDICATOR "ENCODE"
#define PARITY_INDICATOR "PARITY"

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

extern File files[MAX_FILES];

extern PorSK porSK;

extern uint8_t dh_sharedKey[64];

#endif