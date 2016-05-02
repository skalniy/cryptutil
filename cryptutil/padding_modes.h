#pragma once

#include "cryptutil.h"
#include <time.h>



class Padding
{
public:
	static void pkcs7(byte *block, const size_t block_size, const size_t filled_blocks) 
	{
		byte n = static_cast<byte>(block_size - filled_blocks);
		for (size_t i = filled_blocks; i < block_size; i++)
			block[i] = n;

		return;
	}

	static void ansi_x923(byte *block, const size_t block_size, const size_t filled_blocks)
	{
		byte n = static_cast<byte>(block_size - filled_blocks);
		for (size_t i = filled_blocks; i < block_size - 1; i++)
			block[i] = 0;
		block[block_size - 1] = n;

		return;
	}

	static void iso10126(byte *block, const size_t block_size, const size_t filled_blocks)
	{
		byte n = static_cast<byte>(block_size - filled_blocks);
		for (size_t i = filled_blocks; i < block_size - 1; i++) {
			srand((unsigned)time(NULL));
			block[i] = static_cast<byte>(rand());
		}
		block[block_size - 1] = n;

		return;
	}
};