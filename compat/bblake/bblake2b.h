#ifndef BLAKE2B_H
#define BLAKE2B_H

#include <stddef.h>

#if !defined(LIB_PUBLIC)
#define LIB_PUBLIC
#endif

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct blake2b_state_t {
	unsigned char opaque[256];
} blake2b_state;

/* incremental */
LIB_PUBLIC void bblake2b_init(blake2b_state *S);
LIB_PUBLIC void bblake2b_keyed_init(blake2b_state *S, const unsigned char *key, size_t keylen);
LIB_PUBLIC void bblake2b_update(blake2b_state *S, const unsigned char *in, size_t inlen);
LIB_PUBLIC void bblake2b_final(blake2b_state *S, unsigned char *hash);

/* one-shot */
LIB_PUBLIC void bblake2b(unsigned char *hash, const unsigned char *in, size_t inlen);
LIB_PUBLIC void bblake2b_keyed(unsigned char *hash, const unsigned char *in, size_t inlen, const unsigned char *key, size_t keylen);

LIB_PUBLIC int bblake2b_startup(void);

#if defined(UTILITIES)
void blake2b_fuzz(void);
void blake2b_bench(void);
#endif

#if defined(__cplusplus)
}
#endif

#endif /* BLAKE2B_H */

