#include <fstream>
#include <iostream>
#include <string>
#include "cryptutil.h"
#include "ciphers.h"
#include "cipher_modes.h"

using namespace std;


int main()
{
	vector<byte> key;
	key.push_back(2);
	key.push_back(0);
	key.push_back(1);
	byte init_vector[] = { 'm', 'i', 'r', '\0' };

	string cmd;
	do
	{
		cin >> cmd;
		if (cmd == "dec") {
			
			ifstream ost("out.txt", ios::binary);
			ofstream d("dec.txt", ios::binary);
			cbc_decrypt(ost, d, 3, key, init_vector, transposition_decrypt, ansi_x923);
			ost.close();
			d.close();
		}
		else if (cmd == "enc") {
			ifstream ist("in.txt", ios::binary);
			ofstream ost("out.txt", ios::binary);
			cbc_encrypt(ist, ost, 3, key, init_vector, transposition_encrypt, ansi_x923);
			ost.close();
			ist.close();
		}
	} while (cmd != "quit");

	

	return 0;
}