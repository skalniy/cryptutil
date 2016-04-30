#pragma once
#include "cryptutil.h"
#include <vector>


byte* transposition(byte* block, size_t block_size, std::vector<size_t>& route) {
	byte* result;
	result = static_cast<byte*>(calloc(block_size, sizeof(byte)));

	byte temp;
	for (size_t i = 0; i < block_size; i++)
		result[route[i]] = block[i];

	return result;
}