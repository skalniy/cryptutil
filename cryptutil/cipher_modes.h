#pragma once
#include <iostream>
#include "cryptutil.h"
#include "padding_modes.h"


using namespace std;

void ecb(istream& ist, ostream& ost, size_t block_size, vector<byte>& key, byte* init_vector, byte* (*cipher)(const byte* block, size_t block_size, vector<byte>& key), void (*padding)(byte *block, size_t block_size, size_t filled_blocks))
{
	byte *block = new byte[block_size+1];
	block[block_size] = '\0';
	byte *encrypted;

	while (ist)
	{
		ist.read(block, block_size);
		if (ist.gcount() != static_cast<streamsize>(block_size))
			padding(block, block_size, static_cast<size_t>(ist.gcount()));
		encrypted = cipher(block, block_size, key);
		ost.write(encrypted, block_size);
	}


	delete[] block;
	delete[] encrypted;
}


void cfb_encrypt(istream& ist, ostream& ost, size_t block_size, vector<byte>& key, const byte* init_vector, 
	byte* (*cipher)(const byte* block, size_t block_size, vector<byte>& key), 
	void(*padding)(byte *block, size_t block_size, size_t filled_blocks))
{
	byte *IV = new byte[block_size + 1];
	memcpy(IV, init_vector, block_size);
	IV[block_size] = '\0';

	byte *block = new byte[block_size + 1];
	block[block_size] = '\0';


	while (!ist.eof())	{
		ist.read(block, static_cast<streamsize>(block_size));
		if (ist.gcount()) {
			if (ist.gcount() != static_cast<streamsize>(block_size))
				padding(block, block_size, static_cast<size_t>(ist.gcount()));
			byte *encrypted = cipher(IV, block_size, key);
			for (size_t i = 0; i < block_size; i++)
				encrypted[i] ^= block[i];
			ost.write(encrypted, static_cast<streamsize>(block_size));
			memmove(IV, encrypted, block_size);
		}
	}
}


void cfb_decrypt(istream& ist, ostream& ost, size_t block_size, vector<byte>& key, const byte* init_vector, byte* (*cipher)(const byte* block, size_t block_size, vector<byte>& key), void(*padding)(byte *block, size_t block_size, size_t filled_blocks))
{
	byte* decrypted;
	byte* encrypted = new byte[block_size + 1];
	encrypted[block_size] = '\0';
	byte* block = new byte[block_size + 1];
	block[block_size] = '\0';

	ist.read(block, block_size);

	while (ist) {
		ist.read(encrypted, block_size);
		decrypted = cipher(encrypted, block_size, key);
		for (size_t i = 0; i < block_size; i++)
			decrypted[i] ^= block[i];
		ost.write(decrypted, block_size);
		delete[] decrypted;
		memmove(block, encrypted, block_size);
	}

	decrypted = cipher(init_vector, block_size, key);
	for (size_t i = 0; i < block_size; i++)
		decrypted[i] ^= block[i];
	ost.write(decrypted, block_size);

}