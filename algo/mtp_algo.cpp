

//#include "argon2ref/argon2.h"
#include "merkletree/mtp.h"

#include <unistd.h>

#if defined(__cplusplus)
extern "C"
{
#include "miner.h"
}
#endif

#define MAXCPU 32

#define memcost 4*1024*1024

#define HASHLEN 32
#define SALTLEN 16
#define PWD "password"

static uint32_t JobId = 0;
static  MerkleTree::Elements TheElements;
static MerkleTree ordered_tree;
static  unsigned char TheMerkleRoot[16];
static  argon2_context context;
static  argon2_instance_t instance;
static  MerkleTree::Buffer root;



int scanhash_mtp(pthread_mutex_t work_lock,int thr_id, struct work* work, uint32_t max_nonce, uint64_t *hashes_done, struct mtp* mtp)
{


	struct timeval tv_start, tv_end, timediff;
//	unsigned char TheMerkleRoot[16];
	unsigned char mtpHashValue[32];

	//MerkleTree::Elements TheElements; // = new MerkleTree;

	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];


	uint32_t TheNonce;

	uint32_t StartNonce = ((uint32_t*)pdata)[19];
	uint32_t _ALIGN(128) endiandata[32];

	((uint32_t*)pdata)[19] = pdata[20]; //    0x00100000; // mtp version not the actual nonce

	for (int k = 0; k < 21; k++) {
		endiandata[k] = pdata[k];}
	pdata[19] = first_nonce;

	if (work_restart[thr_id].restart == 1)
		return 0;

	pthread_mutex_lock(&work_lock);
	gettimeofday(&tv_start, NULL);

	if (JobId != work->data[17]) {

		if (JobId != 0)
			free_memory(&context, (unsigned char *)instance.memory, instance.memory_blocks, sizeof(block));

		JobId = work->data[17];
		context = init_argon2d_param((const char*)endiandata);
		argon2_ctx_from_mtp(&context, &instance);	
		TheElements = mtp_init2(&instance);
		ordered_tree = MerkleTree(TheElements, true);
		root = ordered_tree.getRoot();
		std::copy(root.begin(), root.end(), TheMerkleRoot);
	
		}


	gettimeofday(&tv_end, NULL);
	pthread_mutex_unlock(&work_lock);	
	timeval_subtract(&timediff, &tv_end, &tv_start);
	if (timediff.tv_usec || timediff.tv_sec) {
		printf("******************************timediff %f time diff %d sec %d microsec \n",  (timediff.tv_sec + timediff.tv_usec * 1e-6), timediff.tv_sec, timediff.tv_usec);
	}



	gettimeofday(&tv_start, NULL);
	uint32_t throughput = 1;
	uint32_t foundNonce = first_nonce;


	do {
		int order = 0;

		if (foundNonce != UINT32_MAX && work_restart[thr_id].restart != 1)
		{

			uint256 TheUint256Target[1];
			TheUint256Target[0] = ((uint256*)ptarget)[0];

			uint32_t is_sol = mtp_solver_nowriting(foundNonce, &instance,(TheMerkleRoot), endiandata, TheUint256Target[0]);


			if (is_sol == 1 && !work_restart[thr_id].restart) {
				gettimeofday(&tv_end, NULL);
				uint64_t nBlockMTP[MTP_L * 2][128];
				unsigned char nProofMTP[MTP_L * 3 * 353];

				mtp_solver(foundNonce, &instance, nBlockMTP, nProofMTP, TheMerkleRoot, mtpHashValue, ordered_tree, endiandata, TheUint256Target[0]);

				int res = 1;
				//	work_set_target_ratio(work, vhash64);		


				pdata[19] = foundNonce;

				/// fill mtp structure
				mtp->MTPVersion = 0x1000;
				for (int i = 0; i<16; i++)
					mtp->MerkleRoot[i] = TheMerkleRoot[i];
				for (int i = 0; i<32; i++)
					mtp->mtpHashValue[i] = mtpHashValue[i];

				for (int j = 0; j<(MTP_L * 2); j++)
					for (int i = 0; i<128; i++)
						mtp->nBlockMTP[j][i] = nBlockMTP[j][i];

				memcpy(mtp->nProofMTP, nProofMTP, sizeof(unsigned char)* MTP_L * 3 * 353);

				printf("found a solution thr_id %d\n", thr_id);
//				compare_height(curl, work);
//				free_memory(&context, (unsigned char *)instance.memory, instance.memory_blocks, sizeof(block));
				*hashes_done = foundNonce - first_nonce;
				/////////////////

				timeval_subtract(&timediff, &tv_end, &tv_start);
				if (timediff.tv_usec || timediff.tv_sec) {
					printf("timediff %f time diff %d sec %d microsec \n", (foundNonce - first_nonce) / (timediff.tv_sec + timediff.tv_usec * 1e-6), timediff.tv_sec, timediff.tv_usec);
				}

				/////////////////

				return res;

			}// else {foundNonce++;}

			foundNonce += throughput;
			StartNonce += throughput;
		}

	} while (!work_restart[thr_id].restart && StartNonce<0xffffffff);

	*hashes_done = StartNonce - first_nonce;

	return 0;
}




