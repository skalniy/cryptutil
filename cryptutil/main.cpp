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
	ifstream ist("in.txt", ios::binary);
	if (!ist) return -1;
	ofstream ost("out.txt", ios::binary);
	string cmd;
	do
	{
		cin >> cmd;
		if (cmd == "cfb")
			cfb_encrypt(ist, ost, 3, key, init_vector, transposition, ansi_x923);
	} while (cmd != "quit");
	
	ist.close();
	ost.close();

	return 0;
}