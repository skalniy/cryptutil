#pragma once
#include <iostream>
#include <vector>
#include "cryptutil.h"
#include "padding_modes.h"



using namespace std;


template<class Cipher>
class OperationMode
{
public:
	virtual void encrypt(
		istream& ist, ostream& ost,
		const size_t block_size, const vector<byte>& key, const byte *init_vector,
		void (pad)(byte *block, const size_t block_size, const size_t filled_blocks)
		) = 0;


	virtual void decrypt(
		istream& ist, ostream& ost,
		const size_t block_size, const vector<byte>& key, const byte *init_vector,
		void (pad)(byte *block, const size_t block_size, const size_t filled_blocks)
		) = 0;
};


template <class Cipher>
class ECB : OperationMode<Cipher>
{
public:
	static void encrypt(
		istream& ist, ostream& ost,
		const size_t block_size, const vector<byte>& key, const byte *init_vector,
		void (pad)(byte *block, const size_t block_size, const size_t filled_blocks)
		) 
	{
		byte *block = new byte[block_size + 1];
		block[block_size] = '\0';

		while (ist)
		{
			ist.read(block, block_size);
			if (ist.gcount()) {
				if (ist.gcount() != static_cast<streamsize>(block_size))
					pad(block, block_size, static_cast<size_t>(ist.gcount()));
				byte *encrypted = Cipher::encrypt(block, block_size, key);
				ost.write(encrypted, block_size);
				delete[] encrypted;
			}
		}

		delete[] block;
		return;
	}


	static void decrypt(
		istream& ist, ostream& ost,
		const size_t block_size, const vector<byte>& key, const byte *init_vector,
		void (pad)(byte *block, const size_t block_size, const size_t filled_blocks)
		)
	{
		byte *block = new byte[block_size + 1];
		block[block_size] = '\0';

		while (ist)
		{
			ist.read(block, block_size);
			if (ist.gcount()) {
				if (ist.gcount() != static_cast<streamsize>(block_size))
					pad(block, block_size, static_cast<size_t>(ist.gcount()));
				byte *decrypted = Cipher::decrypt(block, block_size, key);
				ost.write(decrypted, block_size);
				delete[] decrypted;
			}
		}

		delete[] block;
		return;
	}
};


void cfb_encrypt(istream& ist, ostream& ost, size_t block_size,
	vector<byte>& key, const byte* init_vector,
	byte* (*cipher)(const byte* block, const size_t block_size, const vector<byte>& key),
	void(*padding)(byte *block, const size_t block_size, const size_t filled_blocks));


void cfb_decrypt(istream& ist, ostream& ost, size_t block_size,
	vector<byte>& key, const byte* init_vector,
	byte* (*cipher)(const byte* block, const size_t block_size, const vector<byte>& key),
	void(*padding)(byte *block, const size_t block_size, const size_t filled_blocks));


void ofb_encrypt(istream& ist, ostream& ost, size_t block_size,
	vector<byte>& key, byte* init_vector,
	byte* (*cipher)(const byte* block, const size_t block_size, const vector<byte>& key),
	void(*padding)(byte *block, const size_t block_size, const size_t filled_blocks));


void ofb_decrypt(istream& ist, ostream& ost, size_t block_size,
	vector<byte>& key, const byte* init_vector,
	byte* (*cipher)(const byte* block, const size_t block_size, const vector<byte>& key),
	void(*padding)(byte *block, const size_t block_size, const size_t filled_blocks));


void cbc_encrypt(istream& ist, ostream& ost, size_t block_size,
	vector<byte>& key, byte* init_vector,
	byte* (*cipher)(const byte* block, const size_t block_size, const vector<byte>& key),
	void(*padding)(byte *block, const size_t block_size, const size_t filled_blocks));


void cbc_decrypt(istream& ist, ostream& ost, size_t block_size,
	vector<byte>& key, const byte* init_vector,
	byte* (*cipher)(const byte* block, const size_t block_size, const vector<byte>& key),
	void(*padding)(byte *block, const size_t block_size, const size_t filled_blocks));