#pragma once
#include "cryptutil.h"
#include "cipher_modes.h"
#include "ciphers.h"


template <class TCipher>
crypto_algorithm get_encrypt_algorithm(OperationMode::mode mode) {

	switch (mode)
	{
	case OperationMode::ECB:
		return TCipher::encrypt;
	case OperationMode::CFB:
		return TCipher::encrypt;
	case OperationMode::OFB:
		return TCipher::encrypt;
	case OperationMode::CBC:
		return TCipher::encrypt;
	}
}


template <class TCipher>
crypto_algorithm get_decrypt_algorithm(OperationMode::mode mode) {

	switch (mode)
	{
	case OperationMode::ECB:
		return TCipher::decrypt;
	case OperationMode::CFB:
		return TCipher::encrypt;
	case OperationMode::OFB:
		return TCipher::encrypt;
	case OperationMode::CBC:
		return TCipher::decrypt;
	}
}


class Pattern
{
public:
	Pattern(string _name, string cipher,
		TKey _key, const byte* init_vector,
		OperationMode::mode _op_mode = OperationMode::ECB, 
		Padding::mode _pad_mode = Padding::ANSI_X923)
		: name(_name), key(_key), op_mode(_op_mode)  
	{
		if (cipher == "transposition") {
			encrypt_algorithm = get_encrypt_algorithm<Transposition>(op_mode);
			decrypt_algorithm = get_decrypt_algorithm<Transposition>(op_mode);
			block_size = key.size();
		} else if (cipher == "hill") {
			encrypt_algorithm = get_encrypt_algorithm<Hill>(op_mode);
			decrypt_algorithm = get_decrypt_algorithm<Hill>(op_mode);
			block_size = static_cast<size_t>(sqrt(key.size()));
		} else if (cipher == "vigenere") {
			encrypt_algorithm = get_encrypt_algorithm<Vigenere>(op_mode);
			decrypt_algorithm = get_decrypt_algorithm<Vigenere>(op_mode);
			block_size = key.size();
		}
		initialization_vector = new byte[block_size];
		memcpy(initialization_vector, init_vector, block_size);
		pad_mode = Padding::get_padding_algorithm(_pad_mode);
	}


	~Pattern() {
		delete[] initialization_vector;
	}

	void encrypt(istream& ist, ostream& ost) {
		switch (op_mode)
		{
		case OperationMode::ECB:
			ECB::encrypt(ist, ost, block_size, key, initialization_vector, encrypt_algorithm, pad_mode);
			break;
		}
	}
private:
	string name;
	OperationMode::mode op_mode;
	padding_algorithm pad_mode;
	crypto_algorithm encrypt_algorithm;
	crypto_algorithm decrypt_algorithm;
	TKey key;
	size_t block_size;
	byte* initialization_vector;
};