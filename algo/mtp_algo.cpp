

//#include "argon2ref/argon2.h"
#include "merkletree/mtp.h"

#include <unistd.h>

#if defined(__cplusplus)
extern "C"
{
#include "miner.h"
}
#endif



#define memcost 4*1024*1024

#define HASHLEN 32
#define SALTLEN 16
#define PWD "password"



int scanhash_mtp(int thr_id, struct work* work, uint32_t max_nonce, uint64_t *hashes_done, struct mtp* mtp)
{

	CURL *curl;
	curl = curl_easy_init();
	//	compare_height(curl,work);

	struct timeval tv_start, tv_end, timediff;
	unsigned char TheMerkleRoot[16];
	unsigned char mtpHashValue[32];

	MerkleTree::Elements TheElements; // = new MerkleTree;

	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];

	//	if (opt_benchmark)
	//		ptarget[7] = 0x00ff;

	uint32_t diff = 5;
	uint32_t TheNonce;

	uint32_t StartNonce = ((uint32_t*)pdata)[19];
	uint32_t _ALIGN(128) endiandata[20];
	((uint32_t*)pdata)[19] = 0x00100000; // mtp version not the actual nonce
	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	if (work_restart[thr_id].restart == 1)
		return 0;


	//	((uint32_t*)pdata)[19] = 0;
	argon2_context context = init_argon2d_param((const char*)endiandata);
	argon2_instance_t instance;
	argon2_ctx_from_mtp(&context, &instance);
	if (work_restart[thr_id].restart == 1) {
		free_memory(&context, (unsigned char *)instance.memory, instance.memory_blocks, sizeof(block));
		return 0;
	}
	TheElements = mtp_init(&instance);
	if (work_restart[thr_id].restart == 1) {
		free_memory(&context, (unsigned char *)instance.memory, instance.memory_blocks, sizeof(block));
		return 0;
	}
	MerkleTree ordered_tree(TheElements, true);
	if (work_restart[thr_id].restart == 1) {
		free_memory(&context, (unsigned char *)instance.memory, instance.memory_blocks, sizeof(block));
		return 0;
	}
	MerkleTree::Buffer root = ordered_tree.getRoot();
	if (work_restart[thr_id].restart == 1) {
		free_memory(&context, (unsigned char *)instance.memory, instance.memory_blocks, sizeof(block));
		return 0;
	}
	std::copy(root.begin(), root.end(), TheMerkleRoot);
	if (work_restart[thr_id].restart == 1) {
		free_memory(&context, (unsigned char *)instance.memory, instance.memory_blocks, sizeof(block));
		return 0;
	}



	gettimeofday(&tv_start, NULL);

	uint32_t throughput = 1;
	uint32_t foundNonce = StartNonce /*- first_nonce*/;
	printf("first nonce %08x thread id %d \n", foundNonce, thr_id);

	do {
		int order = 0;


		//		*hashes_done = StartNonce -  first_nonce /*+ throughput*/;

		//		foundNonce = 0; //mtp_cpu_hash_32(thr_id, throughput, pdata[19]);
		//		foundNonce = /*pdata[19] -*/ first_nonce + throughput;

		if (foundNonce != UINT32_MAX && work_restart[thr_id].restart != 1)
		{
			//			if (work_restart[thr_id].restart == 1)				
			//				printf("work restart is 1 on thread %d", thr_id);
			uint256 TheUint256Target[1];
			TheUint256Target[0] = ((uint256*)ptarget)[0];

			uint32_t is_sol = mtp_solver_nowriting(foundNonce, &instance, TheMerkleRoot, endiandata, TheUint256Target[0]);


			if (is_sol == 1 && !work_restart[thr_id].restart) {
				gettimeofday(&tv_end, NULL);
				uint64_t nBlockMTP[MTP_L * 2][128];
				unsigned char nProofMTP[MTP_L * 3 * 353];

				mtp_solver(foundNonce, &instance, nBlockMTP, nProofMTP, TheMerkleRoot, mtpHashValue, ordered_tree, endiandata, TheUint256Target[0]);

				int res = 1;
				//	work_set_target_ratio(work, vhash64);		
				printf("work restart status %d threadId %d\n", work_restart[thr_id].restart, thr_id);
				/*
				if (!compare_height(curl,work))
				{
				free_memory(&context, (unsigned char *)instance.memory, instance.memory_blocks, sizeof(block));
				*hashes_done = StartNonce - first_nonce;
				//	delete TheTree;
				//				ordered_tree.~MerkleTree();
				TheElements.clear();
				return 0;
				}
				*/

				pdata[19] = swab32(foundNonce);

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
				compare_height(curl, work);
				free_memory(&context, (unsigned char *)instance.memory, instance.memory_blocks, sizeof(block));
				*hashes_done = foundNonce - first_nonce;
				/////////////////

				timeval_subtract(&timediff, &tv_end, &tv_start);
				if (timediff.tv_usec || timediff.tv_sec) {
					printf("timediff %f time diff %d sec %d microsec \n", (foundNonce - first_nonce) / (timediff.tv_sec + timediff.tv_usec * 1e-6), timediff.tv_sec, timediff.tv_usec);
				}

				/////////////////
				printf("hashes done %d thr_id %d\n", hashes_done[0], thr_id);
				return res;

			}// else {foundNonce++;}

			foundNonce += throughput;
			StartNonce += throughput;
		}

	} while (!work_restart[thr_id].restart && StartNonce<0xffffffff);

	free_memory(&context, (unsigned char *)instance.memory, instance.memory_blocks, sizeof(block));
	*hashes_done = StartNonce - first_nonce;

	TheElements.clear();

	return 0;
}




