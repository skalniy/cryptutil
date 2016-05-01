#pragma once
#include <iostream>
#include <vector>
#include "cryptutil.h"
#include "padding_modes.h"


using namespace std;

void ecb_encrypt(istream& ist, ostream& ost, size_t block_size, 
	vector<byte>& key, byte* init_vector, 
	byte* (*cipher)(const byte* block, size_t block_size, vector<byte>& key), 
	void(*padding)(byte *block, size_t block_size, size_t filled_blocks));


void cfb_encrypt(istream& ist, ostream& ost, size_t block_size,
	vector<byte>& key, const byte* init_vector,
	byte *(*cipher)(const byte* block, size_t block_size, vector<byte>& key),
	void(*padding)(byte *block, size_t block_size, size_t filled_blocks));


void cfb_decrypt(istream& ist, ostream& ost, size_t block_size,
	vector<byte>& key, const byte* init_vector,
	byte *(*cipher)(const byte* block, size_t block_size, vector<byte>& key),
	void(*padding)(byte *block, size_t block_size, size_t filled_blocks));


void ofb_encrypt(istream& ist, ostream& ost, size_t block_size,
	vector<byte>& key, byte* init_vector,
	byte* (*cipher)(const byte* block, size_t block_size, vector<byte>& key),
	void(*padding)(byte *block, size_t block_size, size_t filled_blocks));


void ofb_decrypt(istream& ist, ostream& ost, size_t block_size,
	vector<byte>& key, const byte* init_vector,
	byte *(*cipher)(const byte* block, size_t block_size, vector<byte>& key),
	void(*padding)(byte *block, size_t block_size, size_t filled_blocks));


void cfb_encrypt(istream& ist, ostream& ost, size_t block_size,
	vector<byte>& key, byte* init_vector,
	byte* (*cipher)(const byte* block, size_t block_size, vector<byte>& key),
	void(*padding)(byte *block, size_t block_size, size_t filled_blocks));


void cbc_decrypt(istream& ist, ostream& ost, size_t block_size,
	vector<byte>& key, const byte* init_vector,
	byte *(*cipher)(const byte* block, size_t block_size, vector<byte>& key),
	void(*padding)(byte *block, size_t block_size, size_t filled_blocks));