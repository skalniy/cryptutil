#pragma once
#include <fstream>
#include <string>
#include "cryptutil.h"
#include "cipher_modes.h"
#include "ciphers.h"
#include "padding_modes.h"



using namespace std;


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
	Pattern(Cipher::algorithm _cipher = Cipher::algorithm::VIGENERE,
		TKey _key = TKey(), const byte* init_vector = nullptr,
		OperationMode::mode _op_mode = OperationMode::ECB, 
		Padding::mode _pad_mode = Padding::ANSI_X923)
		: cipher(_cipher), key(_key), op_mode(_op_mode)  
	{
		switch (cipher)
		{
		case Cipher::algorithm::TRANSPOSITION:
			encrypt_algorithm = get_encrypt_algorithm<Transposition>(op_mode);
			decrypt_algorithm = get_decrypt_algorithm<Transposition>(op_mode);
			break;
		case Cipher::algorithm::VIGENERE:
			encrypt_algorithm = get_encrypt_algorithm<Vigenere>(op_mode);
			decrypt_algorithm = get_decrypt_algorithm<Vigenere>(op_mode);
			break;
		case Cipher::algorithm::HILL:
			encrypt_algorithm = get_encrypt_algorithm<Hill>(op_mode);
			decrypt_algorithm = get_decrypt_algorithm<Hill>(op_mode);
			break;
		}
		block_size = Cipher::get_block_size(key.size(), cipher);

		initialization_vector = new byte[block_size];
		memcpy(initialization_vector, init_vector, block_size);
		pad_mode = _pad_mode;
	}


	~Pattern() {
		delete[] initialization_vector;
	}


	void encrypt(string fin, string fout) {
		switch (op_mode)
		{
		case OperationMode::ECB:
			ECB::encrypt(fin, fout, block_size, key, initialization_vector, encrypt_algorithm, Padding::get_padding_algorithm(pad_mode));
			break;
		case OperationMode::CFB:
			CFB::encrypt(fin, fout, block_size, key, initialization_vector, encrypt_algorithm, Padding::get_padding_algorithm(pad_mode));
			break;
		case OperationMode::OFB:
			OFB::encrypt(fin, fout, block_size, key, initialization_vector, encrypt_algorithm, Padding::get_padding_algorithm(pad_mode));
			break;
		case OperationMode::CBC:
			CBC::encrypt(fin, fout, block_size, key, initialization_vector, encrypt_algorithm, Padding::get_padding_algorithm(pad_mode));
			break;
		}

		history.push_back(HistoryElement(fin, fout, "encrypt"));
	}


	void decrypt(string fin, string fout) {
		switch (op_mode)
		{
		case OperationMode::ECB:
			ECB::decrypt(fin, fout, block_size, key, initialization_vector, decrypt_algorithm, Padding::get_padding_algorithm(pad_mode));
			break;
		case OperationMode::CFB:
			CFB::decrypt(fin, fout, block_size, key, initialization_vector, decrypt_algorithm, Padding::get_padding_algorithm(pad_mode));
			break;
		case OperationMode::OFB:
			OFB::decrypt(fin, fout, block_size, key, initialization_vector, decrypt_algorithm, Padding::get_padding_algorithm(pad_mode));
			break;
		case OperationMode::CBC:
			CBC::decrypt(fin, fout, block_size, key, initialization_vector, decrypt_algorithm, Padding::get_padding_algorithm(pad_mode));
			break;
		}

		history.push_back(HistoryElement(fin, fout, "decrypt"));
	}

	void show_history() {
		for (auto i : history)
			cout << i.mode << ": " <<
			i.iname << " -> " << i.oname << endl;

		return;
	}

	friend ostream& operator<<(ostream& fout, const Pattern& rhs)
	{
		fout << rhs.cipher << "\t"
			<< rhs.op_mode << "\t"
			<< rhs.pad_mode << endl;

		for (auto b : rhs.key)
			fout << b;
		fout << endl;

		for (size_t i = 0; i < rhs.block_size; i++)
			fout << rhs.initialization_vector[i];
		fout << endl;

		return fout;
	}


	friend istream& operator>>(istream& fin, Pattern& rhs) {
		char foo;
		int fee;

		fin >> fee;
		rhs.cipher = static_cast<Cipher::algorithm>(fee);
		fin >> fee;
		rhs.op_mode = static_cast<OperationMode::mode>(fee);
		fin >> fee;
		rhs.pad_mode = static_cast<Padding::mode>(fee);

		string _key;
		getline(fin, _key);
		getline(fin, _key);
		rhs.key.clear();
		for (unsigned i = 0; i < _key.length(); i++)
			rhs.key.push_back(static_cast<byte>(_key[i]));

		rhs.block_size = Cipher::get_block_size(rhs.key.size(), rhs.cipher);

		delete[] rhs.initialization_vector;
		rhs.initialization_vector = new byte[rhs.block_size];
		fin.read(rhs.initialization_vector, rhs.block_size);

		return fin;
	}

private:
	TKey key;
	byte* initialization_vector;
	Cipher::algorithm cipher;
	OperationMode::mode op_mode;
	Padding::mode pad_mode;
	crypto_algorithm encrypt_algorithm;
	crypto_algorithm decrypt_algorithm;
	size_t block_size;

	struct HistoryElement
	{
		string iname;
		string oname;
		string mode;
		HistoryElement(string _iname, string _oname, string _mode)
		: iname(_iname), oname(_oname), mode(_mode) {}
	};
	list<HistoryElement> history;
};