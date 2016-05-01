#pragma once
#include <iostream>
#include "cryptutil.h"
#include "padding_modes.h"


using namespace std;

void ecb(istream& ist, ostream& ost, size_t block_size, vector<byte>& key, byte* (*cipher)(byte* block, size_t block_size, vector<byte>& key), void (*padding)(byte *block, size_t block_size, size_t filled_blocks))
{
	byte *block = new byte[block_size+1];
	block[block_size] = '\0';
	byte *new_block;
	//byte init_vector[] = { 'm', 'i', 'r', '\0' };

	while (ist)
	{
		ist.read(block, block_size);
		if (ist.gcount() != block_size)
			padding(block, block_size, ist.gcount());
		new_block = cipher(block, block_size, key);
		ost.write(new_block, block_size);
	}


	delete[] block;
	delete[] new_block;
}