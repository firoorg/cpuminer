//
//
//#pragma once 


#include "mtp.h"
//#include "sha3/sph_blake.h"
#include <stdlib.h>
#ifdef _MSC_VER
#include <windows.h>
#include <winbase.h> /* For SecureZeroMemory */
#define _ALIGN(x) __attribute__ ((aligned(x)))
#endif

#include <ios>
#include <stdio.h>
#include <iostream>
#if defined __STDC_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <emmintrin.h> 
#include <immintrin.h>
#include <cstdint>

#include "compat/bblake/bblake2b.h"

#ifndef INLINE
#ifdef __GNUC__
#if (__GNUC__ > 3) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 1))
#define INLINE         __inline__ __attribute__((always_inline))
#else
#define INLINE         __inline__
#endif
#elif defined(_MSC_VER)
#define INLINE __forceinline
#elif (defined(__BORLANDC__) || defined(__WATCOMC__))
#define INLINE __inline
#else
#define INLINE 
#endif
#endif


#define memcost 4*1024*1024
static const unsigned int d_mtp = 1;
static const uint8_t L = 64;
static const unsigned int memory_cost = memcost;


static const unsigned char blake2b_sigma[12][16] =
{
	{ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
	{ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
	{ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
	{ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
	{ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
	{ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

static  const uint64_t blakeIV_[8] = {
	0x6a09e667f3bcc908UL,
	0xbb67ae8584caa73bUL,
	0x3c6ef372fe94f82bUL,
	0xa54ff53a5f1d36f1UL,
	0x510e527fade682d1UL,
	0x9b05688c2b3e6c1fUL,
	0x1f83d9abfb41bd6bUL,
	0x5be0cd19137e2179UL
};
static inline uint64_t ROTR64X(const uint64_t x2, const int y) {
	return (x2 >> y) | (x2 << (64 - y));
}

static inline uint64_t eorswap64(uint64_t u, uint64_t v)
{
	return ROTR64X(u^v, 32);
}

static inline int blake2b_compress2_256(uint64_t *hash, const uint64_t *hzcash, const  uint64_t *block, const uint32_t len)
{
	uint64_t m[16];
	uint64_t v[16];


	for (int i = 0; i < 16; ++i)
		m[i] = block[i];

	for (int i = 0; i < 8; ++i)
		v[i] = hzcash[i];

	v[8] = blakeIV_[0];
	v[9] = blakeIV_[1];
	v[10] = blakeIV_[2];
	v[11] = blakeIV_[3];
	v[12] = blakeIV_[4];
	v[12] ^= len;
	v[13] = blakeIV_[5];
	v[14] = ~blakeIV_[6];
	v[15] = blakeIV_[7];


#define G(r,i,a,b,c,d) \
   { \
     v[a] +=   v[b] + (m[blake2b_sigma[r][2*i+0]]); \
     v[d] = eorswap64(v[d] , v[a]); \
     v[c] += v[d]; \
     v[b] = ROTR64X(v[b] ^ v[c], 24); \
     v[a] += v[b] + (m[blake2b_sigma[r][2*i+1]]); \
     v[d] = ROTR64X(v[d] ^ v[a], 16); \
     v[c] += v[d]; \
     v[b] = ROTR64X(v[b] ^ v[c], 63); \
  } 

#define ROUND(r)  \
  { \
    G(r,0, 0,4,8,12); \
    G(r,1, 1,5,9,13); \
    G(r,2, 2,6,10,14); \
    G(r,3, 3,7,11,15); \
    G(r,4, 0,5,10,15); \
    G(r,5, 1,6,11,12); \
    G(r,6, 2,7,8,13); \
    G(r,7, 3,4,9,14); \
  } 

	ROUND(0);
	ROUND(1);
	ROUND(2);
	ROUND(3);
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);

	for (int i = 0; i < 4; ++i)
		hash[i] = hzcash[i] ^ v[i] ^ v[i + 8];

#undef G
#undef ROUND
	return 0;
}


static inline int blake2b_compress2b_new(uint64_t *hzcash, const  uint64_t *  block, const  uint64_t *  block0, const uint32_t len, int last)
{

	uint64_t m[16];
	uint64_t v[16];


	for (int i = 0; i < 4; ++i)
		m[i] = block0[i];


	for (int i = 4; i < 16; ++i)
		m[i] = block[i - 4];


	for (int i = 0; i < 8; ++i)
		v[i] = hzcash[i];


	v[8] = blakeIV_[0];
	v[9] = blakeIV_[1];
	v[10] = blakeIV_[2];
	v[11] = blakeIV_[3];
	v[12] = blakeIV_[4];
	v[12] ^= len;
	v[13] = blakeIV_[5];
	v[14] = last ? ~blakeIV_[6] : blakeIV_[6];
	v[15] = blakeIV_[7];


#define G(r,i,a,b,c,d) \
   { \
     v[a] +=   v[b] + (m[blake2b_sigma[r][2*i+0]]); \
     v[d] = eorswap64(v[d] , v[a]); \
     v[c] += v[d]; \
     v[b] = ROTR64X(v[b] ^ v[c], 24); \
     v[a] += v[b] + (m[blake2b_sigma[r][2*i+1]]); \
     v[d] = ROTR64X(v[d] ^ v[a], 16); \
     v[c] += v[d]; \
     v[b] = ROTR64X(v[b] ^ v[c], 63); \
  } 
#define ROUND(r)  \
  { \
    G(r,0, 0,4,8,12); \
    G(r,1, 1,5,9,13); \
    G(r,2, 2,6,10,14); \
    G(r,3, 3,7,11,15); \
    G(r,4, 0,5,10,15); \
    G(r,5, 1,6,11,12); \
    G(r,6, 2,7,8,13); \
    G(r,7, 3,4,9,14); \
  } 

	ROUND(0);
	ROUND(1);
	ROUND(2);
	ROUND(3);
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);

	for (int i = 0; i < 8; ++i)
		hzcash[i] ^= v[i] ^ v[i + 8];

#undef G
#undef ROUND
	return 0;
}



uint32_t index_beta(const argon2_instance_t *instance,
	const argon2_position_t *position, uint32_t pseudo_rand,
	int same_lane) {
	
	uint32_t reference_area_size;
	uint64_t relative_position;
	uint32_t start_position, absolute_position;

	if (0 == position->pass) {
		/* First pass */
		if (0 == position->slice) {
			/* First slice */
			reference_area_size =
				position->index - 1; /* all but the previous */
		}
		else {
			if (same_lane) {
				/* The same lane => add current segment */
				reference_area_size =
					position->slice * instance->segment_length +
					position->index - 1;
			}
			else {
				reference_area_size =
					position->slice * instance->segment_length +
					((position->index == 0) ? (-1) : 0);
			}
		}
	}
	else {
		/* Second pass */
		if (same_lane) {
			reference_area_size = instance->lane_length -
				instance->segment_length + position->index -
				1;
		}
		else {
			reference_area_size = instance->lane_length -
				instance->segment_length +
				((position->index == 0) ? (-1) : 0);
		}
	}

	/* 1.2.4. Mapping pseudo_rand to 0..<reference_area_size-1> and produce
	* relative position */
	relative_position = pseudo_rand;
	relative_position = relative_position * relative_position >> 32;
	relative_position = reference_area_size - 1 -
		(reference_area_size * relative_position >> 32);

	/* 1.2.5 Computing starting position */
	start_position = 0;

	if (0 != position->pass) {
		start_position = (position->slice == ARGON2_SYNC_POINTS - 1)
			? 0
			: (position->slice + 1) * instance->segment_length;
	}

	/* 1.2.6. Computing absolute position */
	absolute_position = (start_position + relative_position) %
		instance->lane_length; /* absolute position */
	return absolute_position;
}

void StoreBlock(void *output, const block *src)
{
	for (unsigned i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
		store64(static_cast<uint8_t*>(output)
			+ (i * sizeof(src->v[i])), src->v[i]);
	}
}


void compute_blake2b(const block& input,
	uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B])
{
	ablake2b_state state;
	ablake2b_init(&state, MERKLE_TREE_ELEMENT_SIZE_B);
	ablake2b4rounds_update(&state, input.v, ARGON2_BLOCK_SIZE);
	ablake2b4rounds_final(&state, digest, MERKLE_TREE_ELEMENT_SIZE_B);
}


void getblockindex(uint32_t ij, argon2_instance_t *instance, uint32_t *out_ij_prev, uint32_t *out_computed_ref_block)
{
	uint32_t ij_prev = 0;
	if (ij%instance->lane_length == 0)
		ij_prev = ij + instance->lane_length - 1;
	else
		ij_prev = ij - 1;

	if (ij % instance->lane_length == 1)
		ij_prev = ij - 1;

	uint64_t prev_block_opening = instance->memory[ij_prev].v[0];
	uint32_t ref_lane = (uint32_t)((prev_block_opening >> 32) % instance->lanes);

	uint32_t pseudo_rand = (uint32_t)(prev_block_opening & 0xFFFFFFFF);

	uint32_t Lane = ((ij) / instance->lane_length);
	uint32_t Slice = (ij - (Lane * instance->lane_length)) / instance->segment_length;
	uint32_t posIndex = ij - Lane * instance->lane_length - Slice * instance->segment_length;


	uint32_t rec_ij = Slice*instance->segment_length + Lane *instance->lane_length + (ij % instance->segment_length);

	if (Slice == 0)
		ref_lane = Lane;


	argon2_position_t position = { 0, Lane , (uint8_t)Slice, posIndex };

	uint32_t ref_index = index_beta(instance, &position, pseudo_rand, ref_lane == position.lane);

	uint32_t computed_ref_block = instance->lane_length * ref_lane + ref_index;

	*out_ij_prev = ij_prev;
	*out_computed_ref_block = computed_ref_block;
}




unsigned int trailing_zeros(char str[64]) {


    unsigned int i, d;
    d = 0;
    for (i = 63; i > 0; i--) {
        if (str[i] == '0') {
            d++;
        }
        else {
            break;
        }
    }
    return d;
}


unsigned int trailing_zeros_little_endian(char str[64]) {
	unsigned int i, d;
	d = 0;
	for (i = 0; i < 64; i++) {
		if (str[i] == '0') {
			d++;
		}
		else {
			break;
		}
	}
	return d;
}

unsigned int trailing_zeros_little_endian_uint256(uint256 hash) {
	unsigned int i, d;
	std::string temp = hash.GetHex();
	d = 0;
	for (i = 0; i < temp.size(); i++) {
		if (temp[i] == '0') {
			d++;
		}
		else {
			break;
		}
	}
	return d;
}


static void store_block(void *output, const block *src) {
    unsigned i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
        store64((uint8_t *)output + i * sizeof(src->v[i]), src->v[i]);
    }
}


void fill_block(__m128i *state, const block *ref_block, block *next_block, int with_xor) {
    __m128i block_XY[ARGON2_OWORDS_IN_BLOCK];
    unsigned int i;

    if (with_xor) {
        for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
            state[i] = _mm_xor_si128(
                    state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
            block_XY[i] = _mm_xor_si128(
                    state[i], _mm_loadu_si128((const __m128i *)next_block->v + i));
        }
    }
    else {
        for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
            block_XY[i] = state[i] = _mm_xor_si128(
                    state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
        }
    }

    for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
                     state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
                     state[8 * i + 6], state[8 * i + 7]);
    }

    for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
                     state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
                     state[8 * 6 + i], state[8 * 7 + i]);
    }

    for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
        state[i] = _mm_xor_si128(state[i], block_XY[i]);
        _mm_storeu_si128((__m128i *)next_block->v + i, state[i]);
    }
}

void fill_block2(__m128i *state, const block *ref_block, block *next_block, int with_xor, uint32_t block_header[4]) {
	__m128i block_XY[ARGON2_OWORDS_IN_BLOCK];
	unsigned int i;

	if (with_xor) {
		for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
			state[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
			block_XY[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)next_block->v + i));
		}
	}
	else {
		for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
			block_XY[i] = state[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
		}
	}

	memcpy(&state[8], block_header, sizeof(__m128i));

	for (i = 0; i < 8; ++i) {
		BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
			state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
			state[8 * i + 6], state[8 * i + 7]);
	}

	for (i = 0; i < 8; ++i) {
		BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
			state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
			state[8 * 6 + i], state[8 * 7 + i]);
	}

	for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
		state[i] = _mm_xor_si128(state[i], block_XY[i]);
		_mm_storeu_si128((__m128i *)next_block->v + i, state[i]);
	}
}

void fill_block2_withIndex(__m128i *state, const block *ref_block, block *next_block, int with_xor, uint32_t block_header[8], uint64_t blockIndex) {
	__m128i block_XY[ARGON2_OWORDS_IN_BLOCK];
	unsigned int i;
    uint64_t TheIndex[2]={0,blockIndex};
	if (with_xor) {
		for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
			state[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
			block_XY[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)next_block->v + i));
		}
	}
	else {
		for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
			block_XY[i] = state[i] = _mm_xor_si128(
				state[i], _mm_loadu_si128((const __m128i *)ref_block->v + i));
		}
	}
	memcpy(&state[7], TheIndex, sizeof(__m128i));
	memcpy(&state[8], block_header, sizeof(__m128i));
	memcpy(&state[9], block_header + 4, sizeof(__m128i));
	for (i = 0; i < 8; ++i) {
		BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
			state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
			state[8 * i + 6], state[8 * i + 7]);
	}

	for (i = 0; i < 8; ++i) {
		BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
			state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
			state[8 * 6 + i], state[8 * 7 + i]);
	}

	for (i = 0; i < ARGON2_OWORDS_IN_BLOCK; i++) {
		state[i] = _mm_xor_si128(state[i], block_XY[i]);
		_mm_storeu_si128((__m128i *)next_block->v + i, state[i]);
	}
}



void copy_block(block *dst, const block *src) {
	memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
}
void copy_blockS(blockS *dst, const blockS *src) {
	memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
}
void copy_blockS(blockS *dst, const block *src) {
	memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
}


#define VC_GE_2005(version) (version >= 1400)

void  secure_wipe_memory(void *v, size_t n) {
#if defined(_MSC_VER) && VC_GE_2005(_MSC_VER)
	SecureZeroMemory(v, n);
#elif defined memset_s
	memset_s(v, n, 0, n);
#elif defined(__OpenBSD__)
	explicit_bzero(v, n);
#else
	static void *(*const volatile memset_sec)(void *, int, size_t) = &memset;
	memset_sec(v, 0, n);
#endif
}

/* Memory clear flag defaults to true. */

void clear_internal_memory(void *v, size_t n) {
	if (FLAG_clear_internal_memory && v) {
		secure_wipe_memory(v, n);
	}
}


void free_memory(const argon2_context *context, uint8_t *memory,
	size_t num, size_t size) {
	size_t memory_size = num*size;
	clear_internal_memory(memory, memory_size);
	if (context->free_cbk) {
		(context->free_cbk)(memory, memory_size);
	}
	else {
		free(memory);
	}
}

argon2_context init_argon2d_param(const char* input) {

#define TEST_OUTLEN 32
#define TEST_PWDLEN 80
#define TEST_SALTLEN 80
#define TEST_SECRETLEN 0
#define TEST_ADLEN 0
    argon2_context context;
    argon2_context *pContext = &context;

    unsigned char out[TEST_OUTLEN];

    const allocate_fptr myown_allocator = NULL;
    const deallocate_fptr myown_deallocator = NULL;

    unsigned t_cost = 1;
    unsigned m_cost =  memcost; //2*1024*1024; //*1024; //+896*1024; //32768*1;
	
    unsigned lanes = 4;

    memset(pContext,0,sizeof(argon2_context));
    memset(&out[0], 0, sizeof(out));
    context.out = out;
    context.outlen = TEST_OUTLEN;
    context.version = ARGON2_VERSION_NUMBER;
    context.pwd = (uint8_t*)input;
    context.pwdlen = TEST_PWDLEN;
    context.salt = (uint8_t*)input;
    context.saltlen = TEST_SALTLEN;
    context.secret = NULL;
    context.secretlen = TEST_SECRETLEN;
    context.ad = NULL;
    context.adlen = TEST_ADLEN;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = lanes;
    context.threads = lanes;
    context.allocate_cbk = myown_allocator;
    context.free_cbk = myown_deallocator;
    context.flags = ARGON2_DEFAULT_FLAGS;

#undef TEST_OUTLEN
#undef TEST_PWDLEN
#undef TEST_SALTLEN
#undef TEST_SECRETLEN
#undef TEST_ADLEN

    return context;
}





int mtp_solver(uint32_t TheNonce, argon2_instance_t *instance,
	uint64_t nBlockMTP[MTP_BLOCK_PROOF_SIZE * 2][128] /*[72 * 2][128]*/, unsigned char* nProofMTP, unsigned char* resultMerkleRoot, unsigned char* mtpHashValue,
	MerkleTree TheTree, uint32_t* input, uint256 hashTarget) {



	if (instance != NULL) {
		//		input[19]=0x01000000;
		uint256 Y;
		//		std::string proof_blocks[L * 3];
		memset(&Y, 0, sizeof(Y));

		ablake2b_state BlakeHash;
		ablake2b_init(&BlakeHash, 32);


		ablake2b_update(&BlakeHash, (unsigned char*)&input[0], 80);
		ablake2b_update(&BlakeHash, (unsigned char*)&resultMerkleRoot[0], 16);
		ablake2b_update(&BlakeHash, &TheNonce, sizeof(unsigned int));
		ablake2b_final(&BlakeHash, (unsigned char*)&Y, 32);


		///////////////////////////////
		bool init_blocks = false;
		bool unmatch_block = false;

		for (int j = 1; j <= L; j++) {

			uint32_t ij = (((uint32_t*)(&Y))[0]) % (instance->context_ptr->m_cost);

			uint32_t except_index = (uint32_t)(instance->context_ptr->m_cost / instance->context_ptr->lanes);
			if (ij %except_index == 0 || ij%except_index == 1) {
				init_blocks = true;
				break;
			}

			uint32_t prev_index = 0;
			uint32_t ref_index = 0;
			getblockindex(ij, instance, &prev_index, &ref_index);




				for (int i = 0; i<128; i++)
					nBlockMTP[j*2-2][i] = instance->memory[prev_index].v[i];
				for (int i = 0; i<128; i++)
					nBlockMTP[j * 2 - 1][i] = instance->memory[ref_index].v[i];

			block blockhash;
			uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
			copy_block(&blockhash, &instance->memory[ij]);


			store_block(&blockhash_bytes, &blockhash);

			ablake2b_state BlakeHash2;
			ablake2b_init(&BlakeHash2, 32);
			ablake2b_update(&BlakeHash2, &Y, sizeof(uint256));
			ablake2b_update(&BlakeHash2, blockhash_bytes, ARGON2_BLOCK_SIZE);
			ablake2b_final(&BlakeHash2, (unsigned char*)&Y, 32);
			////////////////////////////////////////////////////////////////
			// current block


			block blockhash_curr;
			uint8_t blockhash_curr_bytes[ARGON2_BLOCK_SIZE];
			copy_block(&blockhash_curr, &instance->memory[ij]);
			store_block(&blockhash_curr_bytes, &blockhash_curr);
			ablake2b_state state_curr;
			ablake2b_init(&state_curr, MERKLE_TREE_ELEMENT_SIZE_B);
			ablake2b4rounds_update(&state_curr, blockhash_curr_bytes, ARGON2_BLOCK_SIZE);
			uint8_t digest_curr[MERKLE_TREE_ELEMENT_SIZE_B];
			ablake2b4rounds_final(&state_curr, digest_curr, sizeof(digest_curr));
			MerkleTree::Buffer hash_curr = MerkleTree::Buffer(digest_curr, digest_curr + sizeof(digest_curr));
			clear_internal_memory(blockhash_curr.v, ARGON2_BLOCK_SIZE);
			clear_internal_memory(blockhash_curr_bytes, ARGON2_BLOCK_SIZE);


			std::deque<std::vector<uint8_t>> zProofMTP = TheTree.getProofOrdered(hash_curr, ij + 1);

			nProofMTP[(j * 3 - 3) * 353] = (unsigned char)(zProofMTP.size());

			int k1 = 0;
			for (const std::vector<uint8_t> &mtpData : zProofMTP) {
				std::copy(mtpData.begin(), mtpData.end(), nProofMTP + ((j * 3 - 3) * 353 + 1 + k1 * mtpData.size()));
				k1++;
			}

			//prev proof

			block blockhash_prev;
			uint8_t blockhash_prev_bytes[ARGON2_BLOCK_SIZE];
			copy_block(&blockhash_prev, &instance->memory[prev_index]);
			store_block(&blockhash_prev_bytes, &blockhash_prev);
			ablake2b_state state_prev;
			ablake2b_init(&state_prev, MERKLE_TREE_ELEMENT_SIZE_B);
			ablake2b4rounds_update(&state_prev, blockhash_prev_bytes, ARGON2_BLOCK_SIZE);
			uint8_t digest_prev[MERKLE_TREE_ELEMENT_SIZE_B];


			ablake2b4rounds_final(&state_prev, digest_prev, sizeof(digest_prev));


			MerkleTree::Buffer hash_prev = MerkleTree::Buffer(digest_prev, digest_prev + sizeof(digest_prev));
			clear_internal_memory(blockhash_prev.v, ARGON2_BLOCK_SIZE);
			clear_internal_memory(blockhash_prev_bytes, ARGON2_BLOCK_SIZE);

			 zProofMTP = TheTree.getProofOrdered(hash_prev, prev_index + 1);

			nProofMTP[(j * 3 - 2) * 353] = (unsigned char)(zProofMTP.size());

			int k2 = 0;
			for (const std::vector<uint8_t> &mtpData : zProofMTP) {
				std::copy(mtpData.begin(), mtpData.end(), nProofMTP + ((j * 3 - 2) * 353 + 1 + k2 * mtpData.size()));
				k2++;
			}


			//ref proof

			block blockhash_ref;
			uint8_t blockhash_ref_bytes[ARGON2_BLOCK_SIZE];
			copy_block(&blockhash_ref, &instance->memory[ref_index]);
			store_block(&blockhash_ref_bytes, &blockhash_ref);
			ablake2b_state state_ref;
			ablake2b_init(&state_ref, MERKLE_TREE_ELEMENT_SIZE_B);
			ablake2b4rounds_update(&state_ref, blockhash_ref_bytes, ARGON2_BLOCK_SIZE);
			uint8_t digest_ref[MERKLE_TREE_ELEMENT_SIZE_B];
			ablake2b4rounds_final(&state_ref, digest_ref, sizeof(digest_ref));
			MerkleTree::Buffer hash_ref = MerkleTree::Buffer(digest_ref, digest_ref + sizeof(digest_ref));
			clear_internal_memory(blockhash_ref.v, ARGON2_BLOCK_SIZE);
			clear_internal_memory(blockhash_ref_bytes, ARGON2_BLOCK_SIZE);

			/* std::deque<std::vector<uint8_t>> */ zProofMTP = TheTree.getProofOrdered(hash_ref, ref_index + 1);

			nProofMTP[(j * 3 - 1) * 353] = (unsigned char)(zProofMTP.size());

			int k3 = 0;
			for (const std::vector<uint8_t> &mtpData : zProofMTP) {
				std::copy(mtpData.begin(), mtpData.end(), nProofMTP + ((j * 3 - 1) * 353 + 1 + k3 * mtpData.size()));
				k3++;
			}

		}

		if (init_blocks) {

			return 0;
		}


		char hex_tmp[64];

		if (Y > hashTarget) {

		}
		else {
			for (int i = 0; i<32; i++)
				mtpHashValue[i] = (((unsigned char*)(&Y))[i]);

			// Found a solution
//			printf("Found a solution. Nonce=%08x Hash:", TheNonce);
//			printf("\n");
			return 1;


		}

	}


	return 0;
}


int mtp_solver_nowriting(uint32_t TheNonce, argon2_instance_t *instance,
	unsigned char* resultMerkleRoot, uint32_t* input, uint256 hashTarget) {

	if (instance != NULL) {
		uint256 Y; 
//		memset(&Y, 0, sizeof(Y));

		ablake2b_state BlakeHash;
		ablake2b_init(&BlakeHash, 32);
		ablake2b_update(&BlakeHash, (unsigned char*)&input[0], 80);
		ablake2b_update(&BlakeHash, (unsigned char*)&resultMerkleRoot[0], 16);
		ablake2b_update(&BlakeHash, &TheNonce, sizeof(unsigned int));
		ablake2b_final(&BlakeHash, (unsigned char*)&Y, 32);

		///////////////////////////////
		bool init_blocks = false;
		bool unmatch_block = false;


		for (uint8_t j = 1; j <= L; j++) {

			uint32_t ij = (((uint32_t*)(&Y))[0]) % (instance->context_ptr->m_cost);

			uint32_t except_index = (uint32_t)(instance->context_ptr->m_cost / instance->context_ptr->lanes);
			if (ij %except_index == 0 || ij%except_index == 1) {
				init_blocks = true;
				break;
			}

			unsigned char TheBlock[1024];
			memcpy(TheBlock, instance->memory[ij].v,1024);
			ablake2b_init(&BlakeHash, 32);
			ablake2b_update(&BlakeHash, &Y, sizeof(uint256));
			ablake2b_update(&BlakeHash, TheBlock, ARGON2_BLOCK_SIZE);
			ablake2b_final(&BlakeHash, (unsigned char*)&Y, 32);

		}

		if (init_blocks) 
					return 0;

		if (Y <= hashTarget) 
					return 1;

	}
	return 0;
}


//---------------------------------------------------------------------
// fast copy for different sizes
//---------------------------------------------------------------------
static INLINE void memcpy_avx_16(void *dst, const void *src) {
#if 1
	__m128i m0 = _mm_loadu_si128(((const __m128i*)src) + 0);
	_mm_storeu_si128(((__m128i*)dst) + 0, m0);
#else
	*((uint64_t*)((char*)dst + 0)) = *((uint64_t*)((const char*)src + 0));
	*((uint64_t*)((char*)dst + 8)) = *((uint64_t*)((const char*)src + 8));
#endif
}

static INLINE void memcpy_avx_32(void *dst, const void *src) {
	__m256i m0 = _mm256_loadu_si256(((const __m256i*)src) + 0);
	_mm256_storeu_si256(((__m256i*)dst) + 0, m0);
}

static INLINE void memcpy_avx_64(void *dst, const void *src) {
	__m256i m0 = _mm256_loadu_si256(((const __m256i*)src) + 0);
	__m256i m1 = _mm256_loadu_si256(((const __m256i*)src) + 1);
	_mm256_storeu_si256(((__m256i*)dst) + 0, m0);
	_mm256_storeu_si256(((__m256i*)dst) + 1, m1);
}

static INLINE void memcpy_avx_128(void *dst, const void *src) {
	__m256i m0 = _mm256_loadu_si256(((const __m256i*)src) + 0);
	__m256i m1 = _mm256_loadu_si256(((const __m256i*)src) + 1);
	__m256i m2 = _mm256_loadu_si256(((const __m256i*)src) + 2);
	__m256i m3 = _mm256_loadu_si256(((const __m256i*)src) + 3);
	_mm256_storeu_si256(((__m256i*)dst) + 0, m0);
	_mm256_storeu_si256(((__m256i*)dst) + 1, m1);
	_mm256_storeu_si256(((__m256i*)dst) + 2, m2);
	_mm256_storeu_si256(((__m256i*)dst) + 3, m3);
}

static INLINE void memcpy_avx_256(void *dst, const void *src) {
	__m256i m0 = _mm256_loadu_si256(((const __m256i*)src) + 0);
	__m256i m1 = _mm256_loadu_si256(((const __m256i*)src) + 1);
	__m256i m2 = _mm256_loadu_si256(((const __m256i*)src) + 2);
	__m256i m3 = _mm256_loadu_si256(((const __m256i*)src) + 3);
	__m256i m4 = _mm256_loadu_si256(((const __m256i*)src) + 4);
	__m256i m5 = _mm256_loadu_si256(((const __m256i*)src) + 5);
	__m256i m6 = _mm256_loadu_si256(((const __m256i*)src) + 6);
	__m256i m7 = _mm256_loadu_si256(((const __m256i*)src) + 7);
	_mm256_storeu_si256(((__m256i*)dst) + 0, m0);
	_mm256_storeu_si256(((__m256i*)dst) + 1, m1);
	_mm256_storeu_si256(((__m256i*)dst) + 2, m2);
	_mm256_storeu_si256(((__m256i*)dst) + 3, m3);
	_mm256_storeu_si256(((__m256i*)dst) + 4, m4);
	_mm256_storeu_si256(((__m256i*)dst) + 5, m5);
	_mm256_storeu_si256(((__m256i*)dst) + 6, m6);
	_mm256_storeu_si256(((__m256i*)dst) + 7, m7);
}


//---------------------------------------------------------------------
// tiny memory copy with jump table optimized
//---------------------------------------------------------------------
static INLINE void *memcpy_tiny(void *dst, const void *src, size_t size) {
	unsigned char *dd = ((unsigned char*)dst) + size;
	const unsigned char *ss = ((const unsigned char*)src) + size;

	switch (size) {
	case 128: memcpy_avx_128(dd - 128, ss - 128);
	case 0:  break;
	case 129: memcpy_avx_128(dd - 129, ss - 129);
	case 1: dd[-1] = ss[-1]; break;
	case 130: memcpy_avx_128(dd - 130, ss - 130);
	case 2: *((uint16_t*)(dd - 2)) = *((uint16_t*)(ss - 2)); break;
	case 131: memcpy_avx_128(dd - 131, ss - 131);
	case 3: *((uint16_t*)(dd - 3)) = *((uint16_t*)(ss - 3)); dd[-1] = ss[-1]; break;
	case 132: memcpy_avx_128(dd - 132, ss - 132);
	case 4: *((uint32_t*)(dd - 4)) = *((uint32_t*)(ss - 4)); break;
	case 133: memcpy_avx_128(dd - 133, ss - 133);
	case 5: *((uint32_t*)(dd - 5)) = *((uint32_t*)(ss - 5)); dd[-1] = ss[-1]; break;
	case 134: memcpy_avx_128(dd - 134, ss - 134);
	case 6: *((uint32_t*)(dd - 6)) = *((uint32_t*)(ss - 6)); *((uint16_t*)(dd - 2)) = *((uint16_t*)(ss - 2)); break;
	case 135: memcpy_avx_128(dd - 135, ss - 135);
	case 7: *((uint32_t*)(dd - 7)) = *((uint32_t*)(ss - 7)); *((uint32_t*)(dd - 4)) = *((uint32_t*)(ss - 4)); break;
	case 136: memcpy_avx_128(dd - 136, ss - 136);
	case 8: *((uint64_t*)(dd - 8)) = *((uint64_t*)(ss - 8)); break;
	case 137: memcpy_avx_128(dd - 137, ss - 137);
	case 9: *((uint64_t*)(dd - 9)) = *((uint64_t*)(ss - 9)); dd[-1] = ss[-1]; break;
	case 138: memcpy_avx_128(dd - 138, ss - 138);
	case 10: *((uint64_t*)(dd - 10)) = *((uint64_t*)(ss - 10)); *((uint16_t*)(dd - 2)) = *((uint16_t*)(ss - 2)); break;
	case 139: memcpy_avx_128(dd - 139, ss - 139);
	case 11: *((uint64_t*)(dd - 11)) = *((uint64_t*)(ss - 11)); *((uint32_t*)(dd - 4)) = *((uint32_t*)(ss - 4)); break;
	case 140: memcpy_avx_128(dd - 140, ss - 140);
	case 12: *((uint64_t*)(dd - 12)) = *((uint64_t*)(ss - 12)); *((uint32_t*)(dd - 4)) = *((uint32_t*)(ss - 4)); break;
	case 141: memcpy_avx_128(dd - 141, ss - 141);
	case 13: *((uint64_t*)(dd - 13)) = *((uint64_t*)(ss - 13)); *((uint64_t*)(dd - 8)) = *((uint64_t*)(ss - 8)); break;
	case 142: memcpy_avx_128(dd - 142, ss - 142);
	case 14: *((uint64_t*)(dd - 14)) = *((uint64_t*)(ss - 14)); *((uint64_t*)(dd - 8)) = *((uint64_t*)(ss - 8)); break;
	case 143: memcpy_avx_128(dd - 143, ss - 143);
	case 15: *((uint64_t*)(dd - 15)) = *((uint64_t*)(ss - 15)); *((uint64_t*)(dd - 8)) = *((uint64_t*)(ss - 8)); break;
	case 144: memcpy_avx_128(dd - 144, ss - 144);
	case 16: memcpy_avx_16(dd - 16, ss - 16); break;
	case 145: memcpy_avx_128(dd - 145, ss - 145);
	case 17: memcpy_avx_16(dd - 17, ss - 17); dd[-1] = ss[-1]; break;
	case 146: memcpy_avx_128(dd - 146, ss - 146);
	case 18: memcpy_avx_16(dd - 18, ss - 18); *((uint16_t*)(dd - 2)) = *((uint16_t*)(ss - 2)); break;
	case 147: memcpy_avx_128(dd - 147, ss - 147);
	case 19: memcpy_avx_16(dd - 19, ss - 19); *((uint32_t*)(dd - 4)) = *((uint32_t*)(ss - 4)); break;
	case 148: memcpy_avx_128(dd - 148, ss - 148);
	case 20: memcpy_avx_16(dd - 20, ss - 20); *((uint32_t*)(dd - 4)) = *((uint32_t*)(ss - 4)); break;
	case 149: memcpy_avx_128(dd - 149, ss - 149);
	case 21: memcpy_avx_16(dd - 21, ss - 21); *((uint64_t*)(dd - 8)) = *((uint64_t*)(ss - 8)); break;
	case 150: memcpy_avx_128(dd - 150, ss - 150);
	case 22: memcpy_avx_16(dd - 22, ss - 22); *((uint64_t*)(dd - 8)) = *((uint64_t*)(ss - 8)); break;
	case 151: memcpy_avx_128(dd - 151, ss - 151);
	case 23: memcpy_avx_16(dd - 23, ss - 23); *((uint64_t*)(dd - 8)) = *((uint64_t*)(ss - 8)); break;
	case 152: memcpy_avx_128(dd - 152, ss - 152);
	case 24: memcpy_avx_16(dd - 24, ss - 24); *((uint64_t*)(dd - 8)) = *((uint64_t*)(ss - 8)); break;
	case 153: memcpy_avx_128(dd - 153, ss - 153);
	case 25: memcpy_avx_16(dd - 25, ss - 25); memcpy_avx_16(dd - 16, ss - 16); break;
	case 154: memcpy_avx_128(dd - 154, ss - 154);
	case 26: memcpy_avx_16(dd - 26, ss - 26); memcpy_avx_16(dd - 16, ss - 16); break;
	case 155: memcpy_avx_128(dd - 155, ss - 155);
	case 27: memcpy_avx_16(dd - 27, ss - 27); memcpy_avx_16(dd - 16, ss - 16); break;
	case 156: memcpy_avx_128(dd - 156, ss - 156);
	case 28: memcpy_avx_16(dd - 28, ss - 28); memcpy_avx_16(dd - 16, ss - 16); break;
	case 157: memcpy_avx_128(dd - 157, ss - 157);
	case 29: memcpy_avx_16(dd - 29, ss - 29); memcpy_avx_16(dd - 16, ss - 16); break;
	case 158: memcpy_avx_128(dd - 158, ss - 158);
	case 30: memcpy_avx_16(dd - 30, ss - 30); memcpy_avx_16(dd - 16, ss - 16); break;
	case 159: memcpy_avx_128(dd - 159, ss - 159);
	case 31: memcpy_avx_16(dd - 31, ss - 31); memcpy_avx_16(dd - 16, ss - 16); break;
	case 160: memcpy_avx_128(dd - 160, ss - 160);
	case 32: memcpy_avx_32(dd - 32, ss - 32); break;
	case 161: memcpy_avx_128(dd - 161, ss - 161);
	case 33: memcpy_avx_32(dd - 33, ss - 33); dd[-1] = ss[-1]; break;
	case 162: memcpy_avx_128(dd - 162, ss - 162);
	case 34: memcpy_avx_32(dd - 34, ss - 34); *((uint16_t*)(dd - 2)) = *((uint16_t*)(ss - 2)); break;
	case 163: memcpy_avx_128(dd - 163, ss - 163);
	case 35: memcpy_avx_32(dd - 35, ss - 35); *((uint32_t*)(dd - 4)) = *((uint32_t*)(ss - 4)); break;
	case 164: memcpy_avx_128(dd - 164, ss - 164);
	case 36: memcpy_avx_32(dd - 36, ss - 36); *((uint32_t*)(dd - 4)) = *((uint32_t*)(ss - 4)); break;
	case 165: memcpy_avx_128(dd - 165, ss - 165);
	case 37: memcpy_avx_32(dd - 37, ss - 37); *((uint64_t*)(dd - 8)) = *((uint64_t*)(ss - 8)); break;
	case 166: memcpy_avx_128(dd - 166, ss - 166);
	case 38: memcpy_avx_32(dd - 38, ss - 38); *((uint64_t*)(dd - 8)) = *((uint64_t*)(ss - 8)); break;
	case 167: memcpy_avx_128(dd - 167, ss - 167);
	case 39: memcpy_avx_32(dd - 39, ss - 39); *((uint64_t*)(dd - 8)) = *((uint64_t*)(ss - 8)); break;
	case 168: memcpy_avx_128(dd - 168, ss - 168);
	case 40: memcpy_avx_32(dd - 40, ss - 40); *((uint64_t*)(dd - 8)) = *((uint64_t*)(ss - 8)); break;
	case 169: memcpy_avx_128(dd - 169, ss - 169);
	case 41: memcpy_avx_32(dd - 41, ss - 41); memcpy_avx_16(dd - 16, ss - 16); break;
	case 170: memcpy_avx_128(dd - 170, ss - 170);
	case 42: memcpy_avx_32(dd - 42, ss - 42); memcpy_avx_16(dd - 16, ss - 16); break;
	case 171: memcpy_avx_128(dd - 171, ss - 171);
	case 43: memcpy_avx_32(dd - 43, ss - 43); memcpy_avx_16(dd - 16, ss - 16); break;
	case 172: memcpy_avx_128(dd - 172, ss - 172);
	case 44: memcpy_avx_32(dd - 44, ss - 44); memcpy_avx_16(dd - 16, ss - 16); break;
	case 173: memcpy_avx_128(dd - 173, ss - 173);
	case 45: memcpy_avx_32(dd - 45, ss - 45); memcpy_avx_16(dd - 16, ss - 16); break;
	case 174: memcpy_avx_128(dd - 174, ss - 174);
	case 46: memcpy_avx_32(dd - 46, ss - 46); memcpy_avx_16(dd - 16, ss - 16); break;
	case 175: memcpy_avx_128(dd - 175, ss - 175);
	case 47: memcpy_avx_32(dd - 47, ss - 47); memcpy_avx_16(dd - 16, ss - 16); break;
	case 176: memcpy_avx_128(dd - 176, ss - 176);
	case 48: memcpy_avx_32(dd - 48, ss - 48); memcpy_avx_16(dd - 16, ss - 16); break;
	case 177: memcpy_avx_128(dd - 177, ss - 177);
	case 49: memcpy_avx_32(dd - 49, ss - 49); memcpy_avx_32(dd - 32, ss - 32); break;
	case 178: memcpy_avx_128(dd - 178, ss - 178);
	case 50: memcpy_avx_32(dd - 50, ss - 50); memcpy_avx_32(dd - 32, ss - 32); break;
	case 179: memcpy_avx_128(dd - 179, ss - 179);
	case 51: memcpy_avx_32(dd - 51, ss - 51); memcpy_avx_32(dd - 32, ss - 32); break;
	case 180: memcpy_avx_128(dd - 180, ss - 180);
	case 52: memcpy_avx_32(dd - 52, ss - 52); memcpy_avx_32(dd - 32, ss - 32); break;
	case 181: memcpy_avx_128(dd - 181, ss - 181);
	case 53: memcpy_avx_32(dd - 53, ss - 53); memcpy_avx_32(dd - 32, ss - 32); break;
	case 182: memcpy_avx_128(dd - 182, ss - 182);
	case 54: memcpy_avx_32(dd - 54, ss - 54); memcpy_avx_32(dd - 32, ss - 32); break;
	case 183: memcpy_avx_128(dd - 183, ss - 183);
	case 55: memcpy_avx_32(dd - 55, ss - 55); memcpy_avx_32(dd - 32, ss - 32); break;
	case 184: memcpy_avx_128(dd - 184, ss - 184);
	case 56: memcpy_avx_32(dd - 56, ss - 56); memcpy_avx_32(dd - 32, ss - 32); break;
	case 185: memcpy_avx_128(dd - 185, ss - 185);
	case 57: memcpy_avx_32(dd - 57, ss - 57); memcpy_avx_32(dd - 32, ss - 32); break;
	case 186: memcpy_avx_128(dd - 186, ss - 186);
	case 58: memcpy_avx_32(dd - 58, ss - 58); memcpy_avx_32(dd - 32, ss - 32); break;
	case 187: memcpy_avx_128(dd - 187, ss - 187);
	case 59: memcpy_avx_32(dd - 59, ss - 59); memcpy_avx_32(dd - 32, ss - 32); break;
	case 188: memcpy_avx_128(dd - 188, ss - 188);
	case 60: memcpy_avx_32(dd - 60, ss - 60); memcpy_avx_32(dd - 32, ss - 32); break;
	case 189: memcpy_avx_128(dd - 189, ss - 189);
	case 61: memcpy_avx_32(dd - 61, ss - 61); memcpy_avx_32(dd - 32, ss - 32); break;
	case 190: memcpy_avx_128(dd - 190, ss - 190);
	case 62: memcpy_avx_32(dd - 62, ss - 62); memcpy_avx_32(dd - 32, ss - 32); break;
	case 191: memcpy_avx_128(dd - 191, ss - 191);
	case 63: memcpy_avx_32(dd - 63, ss - 63); memcpy_avx_32(dd - 32, ss - 32); break;
	case 192: memcpy_avx_128(dd - 192, ss - 192);
	case 64: memcpy_avx_64(dd - 64, ss - 64); break;
	case 193: memcpy_avx_128(dd - 193, ss - 193);
	case 65: memcpy_avx_64(dd - 65, ss - 65); dd[-1] = ss[-1]; break;
	case 194: memcpy_avx_128(dd - 194, ss - 194);
	case 66: memcpy_avx_64(dd - 66, ss - 66); *((uint16_t*)(dd - 2)) = *((uint16_t*)(ss - 2)); break;
	case 195: memcpy_avx_128(dd - 195, ss - 195);
	case 67: memcpy_avx_64(dd - 67, ss - 67); *((uint32_t*)(dd - 4)) = *((uint32_t*)(ss - 4)); break;
	case 196: memcpy_avx_128(dd - 196, ss - 196);
	case 68: memcpy_avx_64(dd - 68, ss - 68); *((uint32_t*)(dd - 4)) = *((uint32_t*)(ss - 4)); break;
	case 197: memcpy_avx_128(dd - 197, ss - 197);
	case 69: memcpy_avx_64(dd - 69, ss - 69); *((uint64_t*)(dd - 8)) = *((uint64_t*)(ss - 8)); break;
	case 198: memcpy_avx_128(dd - 198, ss - 198);
	case 70: memcpy_avx_64(dd - 70, ss - 70); *((uint64_t*)(dd - 8)) = *((uint64_t*)(ss - 8)); break;
	case 199: memcpy_avx_128(dd - 199, ss - 199);
	case 71: memcpy_avx_64(dd - 71, ss - 71); *((uint64_t*)(dd - 8)) = *((uint64_t*)(ss - 8)); break;
	case 200: memcpy_avx_128(dd - 200, ss - 200);
	case 72: memcpy_avx_64(dd - 72, ss - 72); *((uint64_t*)(dd - 8)) = *((uint64_t*)(ss - 8)); break;
	case 201: memcpy_avx_128(dd - 201, ss - 201);
	case 73: memcpy_avx_64(dd - 73, ss - 73); memcpy_avx_16(dd - 16, ss - 16); break;
	case 202: memcpy_avx_128(dd - 202, ss - 202);
	case 74: memcpy_avx_64(dd - 74, ss - 74); memcpy_avx_16(dd - 16, ss - 16); break;
	case 203: memcpy_avx_128(dd - 203, ss - 203);
	case 75: memcpy_avx_64(dd - 75, ss - 75); memcpy_avx_16(dd - 16, ss - 16); break;
	case 204: memcpy_avx_128(dd - 204, ss - 204);
	case 76: memcpy_avx_64(dd - 76, ss - 76); memcpy_avx_16(dd - 16, ss - 16); break;
	case 205: memcpy_avx_128(dd - 205, ss - 205);
	case 77: memcpy_avx_64(dd - 77, ss - 77); memcpy_avx_16(dd - 16, ss - 16); break;
	case 206: memcpy_avx_128(dd - 206, ss - 206);
	case 78: memcpy_avx_64(dd - 78, ss - 78); memcpy_avx_16(dd - 16, ss - 16); break;
	case 207: memcpy_avx_128(dd - 207, ss - 207);
	case 79: memcpy_avx_64(dd - 79, ss - 79); memcpy_avx_16(dd - 16, ss - 16); break;
	case 208: memcpy_avx_128(dd - 208, ss - 208);
	case 80: memcpy_avx_64(dd - 80, ss - 80); memcpy_avx_16(dd - 16, ss - 16); break;
	case 209: memcpy_avx_128(dd - 209, ss - 209);
	case 81: memcpy_avx_64(dd - 81, ss - 81); memcpy_avx_32(dd - 32, ss - 32); break;
	case 210: memcpy_avx_128(dd - 210, ss - 210);
	case 82: memcpy_avx_64(dd - 82, ss - 82); memcpy_avx_32(dd - 32, ss - 32); break;
	case 211: memcpy_avx_128(dd - 211, ss - 211);
	case 83: memcpy_avx_64(dd - 83, ss - 83); memcpy_avx_32(dd - 32, ss - 32); break;
	case 212: memcpy_avx_128(dd - 212, ss - 212);
	case 84: memcpy_avx_64(dd - 84, ss - 84); memcpy_avx_32(dd - 32, ss - 32); break;
	case 213: memcpy_avx_128(dd - 213, ss - 213);
	case 85: memcpy_avx_64(dd - 85, ss - 85); memcpy_avx_32(dd - 32, ss - 32); break;
	case 214: memcpy_avx_128(dd - 214, ss - 214);
	case 86: memcpy_avx_64(dd - 86, ss - 86); memcpy_avx_32(dd - 32, ss - 32); break;
	case 215: memcpy_avx_128(dd - 215, ss - 215);
	case 87: memcpy_avx_64(dd - 87, ss - 87); memcpy_avx_32(dd - 32, ss - 32); break;
	case 216: memcpy_avx_128(dd - 216, ss - 216);
	case 88: memcpy_avx_64(dd - 88, ss - 88); memcpy_avx_32(dd - 32, ss - 32); break;
	case 217: memcpy_avx_128(dd - 217, ss - 217);
	case 89: memcpy_avx_64(dd - 89, ss - 89); memcpy_avx_32(dd - 32, ss - 32); break;
	case 218: memcpy_avx_128(dd - 218, ss - 218);
	case 90: memcpy_avx_64(dd - 90, ss - 90); memcpy_avx_32(dd - 32, ss - 32); break;
	case 219: memcpy_avx_128(dd - 219, ss - 219);
	case 91: memcpy_avx_64(dd - 91, ss - 91); memcpy_avx_32(dd - 32, ss - 32); break;
	case 220: memcpy_avx_128(dd - 220, ss - 220);
	case 92: memcpy_avx_64(dd - 92, ss - 92); memcpy_avx_32(dd - 32, ss - 32); break;
	case 221: memcpy_avx_128(dd - 221, ss - 221);
	case 93: memcpy_avx_64(dd - 93, ss - 93); memcpy_avx_32(dd - 32, ss - 32); break;
	case 222: memcpy_avx_128(dd - 222, ss - 222);
	case 94: memcpy_avx_64(dd - 94, ss - 94); memcpy_avx_32(dd - 32, ss - 32); break;
	case 223: memcpy_avx_128(dd - 223, ss - 223);
	case 95: memcpy_avx_64(dd - 95, ss - 95); memcpy_avx_32(dd - 32, ss - 32); break;
	case 224: memcpy_avx_128(dd - 224, ss - 224);
	case 96: memcpy_avx_64(dd - 96, ss - 96); memcpy_avx_32(dd - 32, ss - 32); break;
	case 225: memcpy_avx_128(dd - 225, ss - 225);
	case 97: memcpy_avx_64(dd - 97, ss - 97); memcpy_avx_64(dd - 64, ss - 64); break;
	case 226: memcpy_avx_128(dd - 226, ss - 226);
	case 98: memcpy_avx_64(dd - 98, ss - 98); memcpy_avx_64(dd - 64, ss - 64); break;
	case 227: memcpy_avx_128(dd - 227, ss - 227);
	case 99: memcpy_avx_64(dd - 99, ss - 99); memcpy_avx_64(dd - 64, ss - 64); break;
	case 228: memcpy_avx_128(dd - 228, ss - 228);
	case 100: memcpy_avx_64(dd - 100, ss - 100); memcpy_avx_64(dd - 64, ss - 64); break;
	case 229: memcpy_avx_128(dd - 229, ss - 229);
	case 101: memcpy_avx_64(dd - 101, ss - 101); memcpy_avx_64(dd - 64, ss - 64); break;
	case 230: memcpy_avx_128(dd - 230, ss - 230);
	case 102: memcpy_avx_64(dd - 102, ss - 102); memcpy_avx_64(dd - 64, ss - 64); break;
	case 231: memcpy_avx_128(dd - 231, ss - 231);
	case 103: memcpy_avx_64(dd - 103, ss - 103); memcpy_avx_64(dd - 64, ss - 64); break;
	case 232: memcpy_avx_128(dd - 232, ss - 232);
	case 104: memcpy_avx_64(dd - 104, ss - 104); memcpy_avx_64(dd - 64, ss - 64); break;
	case 233: memcpy_avx_128(dd - 233, ss - 233);
	case 105: memcpy_avx_64(dd - 105, ss - 105); memcpy_avx_64(dd - 64, ss - 64); break;
	case 234: memcpy_avx_128(dd - 234, ss - 234);
	case 106: memcpy_avx_64(dd - 106, ss - 106); memcpy_avx_64(dd - 64, ss - 64); break;
	case 235: memcpy_avx_128(dd - 235, ss - 235);
	case 107: memcpy_avx_64(dd - 107, ss - 107); memcpy_avx_64(dd - 64, ss - 64); break;
	case 236: memcpy_avx_128(dd - 236, ss - 236);
	case 108: memcpy_avx_64(dd - 108, ss - 108); memcpy_avx_64(dd - 64, ss - 64); break;
	case 237: memcpy_avx_128(dd - 237, ss - 237);
	case 109: memcpy_avx_64(dd - 109, ss - 109); memcpy_avx_64(dd - 64, ss - 64); break;
	case 238: memcpy_avx_128(dd - 238, ss - 238);
	case 110: memcpy_avx_64(dd - 110, ss - 110); memcpy_avx_64(dd - 64, ss - 64); break;
	case 239: memcpy_avx_128(dd - 239, ss - 239);
	case 111: memcpy_avx_64(dd - 111, ss - 111); memcpy_avx_64(dd - 64, ss - 64); break;
	case 240: memcpy_avx_128(dd - 240, ss - 240);
	case 112: memcpy_avx_64(dd - 112, ss - 112); memcpy_avx_64(dd - 64, ss - 64); break;
	case 241: memcpy_avx_128(dd - 241, ss - 241);
	case 113: memcpy_avx_64(dd - 113, ss - 113); memcpy_avx_64(dd - 64, ss - 64); break;
	case 242: memcpy_avx_128(dd - 242, ss - 242);
	case 114: memcpy_avx_64(dd - 114, ss - 114); memcpy_avx_64(dd - 64, ss - 64); break;
	case 243: memcpy_avx_128(dd - 243, ss - 243);
	case 115: memcpy_avx_64(dd - 115, ss - 115); memcpy_avx_64(dd - 64, ss - 64); break;
	case 244: memcpy_avx_128(dd - 244, ss - 244);
	case 116: memcpy_avx_64(dd - 116, ss - 116); memcpy_avx_64(dd - 64, ss - 64); break;
	case 245: memcpy_avx_128(dd - 245, ss - 245);
	case 117: memcpy_avx_64(dd - 117, ss - 117); memcpy_avx_64(dd - 64, ss - 64); break;
	case 246: memcpy_avx_128(dd - 246, ss - 246);
	case 118: memcpy_avx_64(dd - 118, ss - 118); memcpy_avx_64(dd - 64, ss - 64); break;
	case 247: memcpy_avx_128(dd - 247, ss - 247);
	case 119: memcpy_avx_64(dd - 119, ss - 119); memcpy_avx_64(dd - 64, ss - 64); break;
	case 248: memcpy_avx_128(dd - 248, ss - 248);
	case 120: memcpy_avx_64(dd - 120, ss - 120); memcpy_avx_64(dd - 64, ss - 64); break;
	case 249: memcpy_avx_128(dd - 249, ss - 249);
	case 121: memcpy_avx_64(dd - 121, ss - 121); memcpy_avx_64(dd - 64, ss - 64); break;
	case 250: memcpy_avx_128(dd - 250, ss - 250);
	case 122: memcpy_avx_64(dd - 122, ss - 122); memcpy_avx_64(dd - 64, ss - 64); break;
	case 251: memcpy_avx_128(dd - 251, ss - 251);
	case 123: memcpy_avx_64(dd - 123, ss - 123); memcpy_avx_64(dd - 64, ss - 64); break;
	case 252: memcpy_avx_128(dd - 252, ss - 252);
	case 124: memcpy_avx_64(dd - 124, ss - 124); memcpy_avx_64(dd - 64, ss - 64); break;
	case 253: memcpy_avx_128(dd - 253, ss - 253);
	case 125: memcpy_avx_64(dd - 125, ss - 125); memcpy_avx_64(dd - 64, ss - 64); break;
	case 254: memcpy_avx_128(dd - 254, ss - 254);
	case 126: memcpy_avx_64(dd - 126, ss - 126); memcpy_avx_64(dd - 64, ss - 64); break;
	case 255: memcpy_avx_128(dd - 255, ss - 255);
	case 127: memcpy_avx_64(dd - 127, ss - 127); memcpy_avx_64(dd - 64, ss - 64); break;
	case 256: memcpy_avx_256(dd - 256, ss - 256); break;
	}

	return dst;
}


//---------------------------------------------------------------------
// main routine
//---------------------------------------------------------------------
static void* memcpy_fast(void *destination, const void *source, size_t size)
{
	unsigned char *dst = (unsigned char*)destination;
	const unsigned char *src = (const unsigned char*)source;
	static size_t cachesize = 0x200000; // L3-cache size
	size_t padding;

	// small memory copy
	if (size <= 256) {
		memcpy_tiny(dst, src, size);
		_mm256_zeroupper();
		return destination;
	}

	// align destination to 16 bytes boundary
	padding = (32 - (((size_t)dst) & 31)) & 31;

#if 1
	if (padding > 0) {
		__m256i head = _mm256_loadu_si256((const __m256i*)src);
		_mm256_storeu_si256((__m256i*)dst, head);
		dst += padding;
		src += padding;
		size -= padding;
	}
#else
	__m256i head = _mm256_loadu_si256((const __m256i*)src);
	_mm256_storeu_si256((__m256i*)dst, head);
	dst += padding;
	src += padding;
	size -= padding;
#endif

	// medium size copy
	if (size <= cachesize) {
		__m256i c0, c1, c2, c3, c4, c5, c6, c7;

		for (; size >= 256; size -= 256) {
			c0 = _mm256_loadu_si256(((const __m256i*)src) + 0);
			c1 = _mm256_loadu_si256(((const __m256i*)src) + 1);
			c2 = _mm256_loadu_si256(((const __m256i*)src) + 2);
			c3 = _mm256_loadu_si256(((const __m256i*)src) + 3);
			c4 = _mm256_loadu_si256(((const __m256i*)src) + 4);
			c5 = _mm256_loadu_si256(((const __m256i*)src) + 5);
			c6 = _mm256_loadu_si256(((const __m256i*)src) + 6);
			c7 = _mm256_loadu_si256(((const __m256i*)src) + 7);
			_mm_prefetch((const char*)(src + 512), _MM_HINT_NTA);
			src += 256;
			_mm256_storeu_si256((((__m256i*)dst) + 0), c0);
			_mm256_storeu_si256((((__m256i*)dst) + 1), c1);
			_mm256_storeu_si256((((__m256i*)dst) + 2), c2);
			_mm256_storeu_si256((((__m256i*)dst) + 3), c3);
			_mm256_storeu_si256((((__m256i*)dst) + 4), c4);
			_mm256_storeu_si256((((__m256i*)dst) + 5), c5);
			_mm256_storeu_si256((((__m256i*)dst) + 6), c6);
			_mm256_storeu_si256((((__m256i*)dst) + 7), c7);
			dst += 256;
		}
	}
	else {		// big memory copy
		__m256i c0, c1, c2, c3, c4, c5, c6, c7;
		/* __m256i c0, c1, c2, c3, c4, c5, c6, c7; */

		_mm_prefetch((const char*)(src), _MM_HINT_NTA);

		if ((((size_t)src) & 31) == 0) {	// source aligned
			for (; size >= 256; size -= 256) {
				c0 = _mm256_load_si256(((const __m256i*)src) + 0);
				c1 = _mm256_load_si256(((const __m256i*)src) + 1);
				c2 = _mm256_load_si256(((const __m256i*)src) + 2);
				c3 = _mm256_load_si256(((const __m256i*)src) + 3);
				c4 = _mm256_load_si256(((const __m256i*)src) + 4);
				c5 = _mm256_load_si256(((const __m256i*)src) + 5);
				c6 = _mm256_load_si256(((const __m256i*)src) + 6);
				c7 = _mm256_load_si256(((const __m256i*)src) + 7);
				_mm_prefetch((const char*)(src + 512), _MM_HINT_NTA);
				src += 256;
				_mm256_stream_si256((((__m256i*)dst) + 0), c0);
				_mm256_stream_si256((((__m256i*)dst) + 1), c1);
				_mm256_stream_si256((((__m256i*)dst) + 2), c2);
				_mm256_stream_si256((((__m256i*)dst) + 3), c3);
				_mm256_stream_si256((((__m256i*)dst) + 4), c4);
				_mm256_stream_si256((((__m256i*)dst) + 5), c5);
				_mm256_stream_si256((((__m256i*)dst) + 6), c6);
				_mm256_stream_si256((((__m256i*)dst) + 7), c7);
				dst += 256;
			}
		}
		else {							// source unaligned
			for (; size >= 256; size -= 256) {
				c0 = _mm256_loadu_si256(((const __m256i*)src) + 0);
				c1 = _mm256_loadu_si256(((const __m256i*)src) + 1);
				c2 = _mm256_loadu_si256(((const __m256i*)src) + 2);
				c3 = _mm256_loadu_si256(((const __m256i*)src) + 3);
				c4 = _mm256_loadu_si256(((const __m256i*)src) + 4);
				c5 = _mm256_loadu_si256(((const __m256i*)src) + 5);
				c6 = _mm256_loadu_si256(((const __m256i*)src) + 6);
				c7 = _mm256_loadu_si256(((const __m256i*)src) + 7);
				_mm_prefetch((const char*)(src + 512), _MM_HINT_NTA);
				src += 256;
				_mm256_stream_si256((((__m256i*)dst) + 0), c0);
				_mm256_stream_si256((((__m256i*)dst) + 1), c1);
				_mm256_stream_si256((((__m256i*)dst) + 2), c2);
				_mm256_stream_si256((((__m256i*)dst) + 3), c3);
				_mm256_stream_si256((((__m256i*)dst) + 4), c4);
				_mm256_stream_si256((((__m256i*)dst) + 5), c5);
				_mm256_stream_si256((((__m256i*)dst) + 6), c6);
				_mm256_stream_si256((((__m256i*)dst) + 7), c7);
				dst += 256;
			}
		}
		_mm_sfence();
	}

	memcpy_tiny(dst, src, size);
	_mm256_zeroupper();

	return destination;
}


static void memcpy_fast2(void *destination, const void *source, size_t size)
{
	unsigned char *dst = (unsigned char*)destination;
	const unsigned char *src = (const unsigned char*)source;
	static size_t cachesize = 0x200000; // L3-cache size
	size_t padding;



	// align destination to 16 bytes boundary
	padding = (32 - (((size_t)dst) & 31)) & 31;

/*
#if 1
	if (padding > 0) {
		__m256i head = _mm256_loadu_si256((const __m256i*)src);
		_mm256_storeu_si256((__m256i*)dst, head);
		dst += padding;
		src += padding;
		size -= padding;
	}
#else
	__m256i head = _mm256_loadu_si256((const __m256i*)src);
	_mm256_storeu_si256((__m256i*)dst, head);
	dst += padding;
	src += padding;
	size -= padding;
#endif
*/
	// medium size copy

//		__m256i c0, c1, c2, c3, c4, c5, c6, c7;
		
//		for (; size >= 256; size -= 256) {
/*
			c0 = _mm256_loadu_si256(((const __m256i*)src) + 0);
			c1 = _mm256_loadu_si256(((const __m256i*)src) + 1);
			c2 = _mm256_loadu_si256(((const __m256i*)src) + 2);
			c3 = _mm256_loadu_si256(((const __m256i*)src) + 3);
			c4 = _mm256_loadu_si256(((const __m256i*)src) + 4);
			c5 = _mm256_loadu_si256(((const __m256i*)src) + 5);
			c6 = _mm256_loadu_si256(((const __m256i*)src) + 6);
			c7 = _mm256_loadu_si256(((const __m256i*)src) + 7);
*/
			for (int i=0;i<32;i++)
			_mm256_storeu_si256((((__m256i*)dst) + i), _mm256_loadu_si256(((const __m256i*)src) + i));
/*
			_mm256_storeu_si256((((__m256i*)dst) + 1), _mm256_loadu_si256(((const __m256i*)src) + 1));
			_mm256_storeu_si256((((__m256i*)dst) + 2), _mm256_loadu_si256(((const __m256i*)src) + 2));
			_mm256_storeu_si256((((__m256i*)dst) + 3), _mm256_loadu_si256(((const __m256i*)src) + 3));
			_mm256_storeu_si256((((__m256i*)dst) + 4), _mm256_loadu_si256(((const __m256i*)src) + 4));
			_mm256_storeu_si256((((__m256i*)dst) + 5), _mm256_loadu_si256(((const __m256i*)src) + 5));
			_mm256_storeu_si256((((__m256i*)dst) + 6), _mm256_loadu_si256(((const __m256i*)src) + 6));
			_mm256_storeu_si256((((__m256i*)dst) + 7), _mm256_loadu_si256(((const __m256i*)src) + 7));
			_mm_prefetch((const char*)(src + 512), _MM_HINT_NTA);
			dst += 256;			
			src += 256;
*/
//		}
	
//	memcpy_tiny(dst, src, size);
	_mm256_zeroupper();

//	return destination;
}



#define Number 1

uint32_t mtp_solver_nowriting_multi(uint32_t TheNonce, argon2_instance_t *instance,
	unsigned char* resultMerkleRoot, uint32_t* input, uint256 hashTarget) {

	/*alignas(128) */unsigned char	 TheBlock[Number][ARGON2_BLOCK_SIZE];

	if (instance != NULL) {
		uint256 Y[Number];
		//		memset(&Y, 0, sizeof(Y));
	
		blake2b_state BlakeHash[Number];
for (int i = 0; i < Number; i++) {
		uint32_t ThatNonce = TheNonce + i;
		bblake2b_init(&BlakeHash[i]);
		bblake2b_update(&BlakeHash[i], (unsigned char*)&input[0], 80);
		bblake2b_update(&BlakeHash[i], (unsigned char*)&resultMerkleRoot[0], 16);
		bblake2b_update(&BlakeHash[i], (unsigned char*)&ThatNonce, sizeof(unsigned int));
		bblake2b_final(&BlakeHash[i], (unsigned char*)&Y[i]); //, 32);
}
		///////////////////////////////
		bool init_blocks = false;
		bool unmatch_block = false;
		uint32_t ij[Number];

		for (uint8_t j = 1; j <= L; j++) {

		for (int i = 0; i < Number; i++) {
			ij[i] = (((uint32_t*)(&Y[i]))[0]) % (instance->context_ptr->m_cost);
//			memcpy(TheBlock[i], (unsigned char*)&Y[i], 32);
			memcpy(TheBlock[i], instance->memory[ij[i]].v, ARGON2_BLOCK_SIZE);
		}
//                blake2b_state BlakeHash2[Number];
			for (int i = 0; i < Number; i++)
			{	
                blake2b_state BlakeHash2;
			bblake2b_init(&BlakeHash2); //, 32);
			bblake2b_update(&BlakeHash2, (unsigned char*)&Y[i], sizeof(uint256));
			bblake2b_update(&BlakeHash2, /*&(instance->memory[ij[i]].v) */ (unsigned char*)&TheBlock[i], ARGON2_BLOCK_SIZE);
			bblake2b_final(&BlakeHash2, (unsigned char*)&Y[i]); //, 32);
			}

		}

		if (init_blocks)
			return 0;
		for (int i = 0; i < Number; i++) {
				
				if (Y[i] <= hashTarget) {
					return TheNonce + i ;
				}
		}
	}
	return 0;
}



void mtp_init( argon2_instance_t *instance,uint8_t  *elements) {

	printf("Step 1 : Compute F(I) and store its T blocks X[1], X[2], ..., X[T] in the memory \n");

	if (instance != NULL) {
		printf("Step 2 : Compute the root Φ of the Merkle hash tree \n");

		for (long int i = 0; i < instance->memory_blocks; ++i) {
			uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B];
			compute_blake2b(instance->memory[i], digest);
//			elements->emplace_back(digest, digest + sizeof(digest));
			memcpy(elements + i*MERKLE_TREE_ELEMENT_SIZE_B,digest, MERKLE_TREE_ELEMENT_SIZE_B);
		}
		printf("end Step 2 : Compute the root Φ of the Merkle hash tree \n");
	}

}

void mtp_init_parallel(int nthread, int thr_id,argon2_instance_t *instance, uint8_t  *elements) {

	printf("Step 1 : Compute F(I) and store its T blocks X[1], X[2], ..., X[T] in the memory \n");

	if (instance != NULL) {
		printf("Step 2 : Compute the root Φ of the Merkle hash tree \n");

int chunk_up  = (nthread!=thr_id+1)?  (instance->memory_blocks /nthread) * (thr_id+1) : instance->memory_blocks;
int chunk_low = (instance->memory_blocks/nthread) * thr_id;
		for (long int i = chunk_low; i < chunk_up; ++i) {
			uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B];
			compute_blake2b(instance->memory[i], digest);
			//			elements->emplace_back(digest, digest + sizeof(digest));
			memcpy(elements + i*MERKLE_TREE_ELEMENT_SIZE_B, digest, MERKLE_TREE_ELEMENT_SIZE_B);
		}
		printf("end Step 2 : Compute the root Φ of the Merkle hash tree \n");
	}

}


MerkleTree::Elements   mtp_init2(argon2_instance_t *instance) {

	MerkleTree::Elements  elements;
	printf("Step 1 : Compute F(I) and store its T blocks X[1], X[2], ..., X[T] in the memory \n");
	//	MerkleTree::Elements elements;
	if (instance != NULL) {
		printf("Step 2 : Compute the root Φ of the Merkle hash tree \n");
		uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B];
		for (int i = 0; i < instance->memory_blocks/2; ++i) {
			memset(digest,0,MERKLE_TREE_ELEMENT_SIZE_B);
			compute_blake2b(instance->memory[2*i], digest);
			elements.emplace_back(digest, digest + sizeof(digest));
			memset(digest, 0, MERKLE_TREE_ELEMENT_SIZE_B);
			compute_blake2b(instance->memory[2*i+1], digest);
			elements.emplace_back(digest, digest + sizeof(digest));
//			elements->push_back(digest, digest + sizeof(digest));
		}

		printf("end Step 2 : Compute the root Φ of the Merkle hash tree \n");
		return elements;
	}

}

//
void mtp_hash(char* output, const char* input, unsigned int d,uint32_t TheNonce) {
    argon2_context context = init_argon2d_param(input);
    argon2_instance_t instance;
    argon2_ctx_from_mtp(&context, &instance);
//    mtp_prover(TheNonce, &instance, d, output);
//    free_memory(&context, (uint8_t *)instance.memory, instance.memory_blocks, sizeof(block));

}
