#pragma once
#include <iostream>
#include "cryptutil.h"
#include "padding_modes.h"


using namespace std;

void ecb(istream& ist, ostream& ost, size_t block_size, vector<byte>& key, byte* init_vector, byte* (*cipher)(byte* block, size_t block_size, vector<byte>& key), void (*padding)(byte *block, size_t block_size, size_t filled_blocks))
{
	byte *block = new byte[block_size+1];
	block[block_size] = '\0';
	byte *encrypted;

	while (ist)
	{
		ist.read(block, block_size);
		if (ist.gcount() != block_size)
			padding(block, block_size, ist.gcount());
		encrypted = cipher(block, block_size, key);
		ost.write(encrypted, block_size);
	}


	delete[] block;
	delete[] encrypted;
}


void cfb(istream& ist, ostream& ost, size_t block_size, vector<byte>& key, const byte* init_vector, byte* (*cipher)(byte* block, size_t block_size, vector<byte>& key), void(*padding)(byte *block, size_t block_size, size_t filled_blocks))
{
	byte *block = new byte[block_size + 1];
	block[block_size] = '\0';
	byte *encrypted = new byte[block_size + 1];
	encrypted[block_size] = '\0';

	memcpy(encrypted, init_vector, block_size+1);
	encrypted = cipher(block, block_size, key);

	while (ist)
	{
		ist.read(block, block_size);
		if (ist.gcount() != block_size)
			padding(block, block_size, ist.gcount());
		for (size_t i = 0; i < block_size; i++)
			encrypted[i] ^= block[i];
		ost.write(encrypted, block_size);
	}


	delete[] block;
	delete[] encrypted;
}