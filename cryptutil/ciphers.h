#pragma once
#include "cryptutil.h"
#include <vector>


byte* transposition_encrypt(const byte* block, size_t block_size, std::vector<byte>& key) {
	byte* result = new byte[block_size + 1];
	result[block_size] = '\0';

	for (size_t i = 0; i < block_size; i++)
		result[key[i]] = block[i];

	return result;
}


byte* transposition_decrypt(const byte* block, size_t block_size, std::vector<byte>& key) {
	byte* result = new byte[block_size + 1];
	result[block_size] = '\0';

	for (size_t i = 0; i < block_size; i++)
		result[i] = block[key[i]];

	return result;
}


byte* vigenere_encrypt(const byte* block, size_t block_size, std::vector<byte>& key) {
	byte* result = new byte[block_size + 1];
	result[block_size] = '\0';
	
	for (size_t i = 0; i < block_size; i++)
		result[i] = (block[i] + key[i]) % 256;

	return result;
}


byte* vigenere_decrypt(const byte* block, size_t block_size, std::vector<byte>& key) {
	byte* result = new byte[block_size + 1];
	result[block_size] = '\0';

	for (size_t i = 0; i < block_size; i++)
		result[i] = (block[i] - key[i] + 256) % 256;

	return result;
}


byte* hill_encrypt(const byte* block, size_t block_size, std::vector<byte>& key) {
	byte* result = new byte[block_size + 1];
	result[block_size] = '\0';
	for (size_t i = 0; i < block_size; i++)
		result[i] = 0;

	for (size_t i = 0; i < block_size; i++)
		for (size_t j = 0; j < block_size; j++)
			result[i] += key[i*block_size + j] * block[j] % 257;

	return result;
}


byte* hill_decrypt(const byte* block, size_t block_size, std::vector<byte>& key) {
	byte* result = new byte[block_size + 1];
	result[block_size] = '\0';

	

	return result;
}