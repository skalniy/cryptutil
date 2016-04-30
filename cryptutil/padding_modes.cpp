#include "padding_modes.h"
#include <stdlib.h>
#include <time.h>



void pkcs7(byte *block, size_t block_size, size_t filled_blocks) {
	byte n = static_cast<byte>(block_size - filled_blocks);
	for (size_t i = filled_blocks; i < block_size; i++)
		block[i] = n;

	return;
}


void ansi_x923(byte *block, size_t block_size, size_t filled_blocks) {
	byte n = static_cast<byte>(block_size - filled_blocks);
	for (size_t i = filled_blocks; i < block_size - 1; i++)
		block[i] = 0;
	block[block_size - 1] = n;

	return;
}


void iso10126(byte *block, size_t block_size, size_t filled_blocks) {
	byte n = static_cast<byte>(block_size - filled_blocks);
	for (size_t i = filled_blocks; i < block_size - 1; i++) {
		srand((unsigned)time(NULL));
		block[i] = static_cast<byte>(rand());
	}
	block[block_size - 1] = n;

	return;
}