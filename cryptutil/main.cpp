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
	ifstream ist("in.txt", ios::binary);
	if (!ist) return -1;
	//ofstream ost("out.txt", ios::binary);
	string cmd;
	do
	{
		cin >> cmd;
		if (cmd == "ecb")
			ecb(ist, cout, 3, key, transposition);
	} while (cmd != "quit");
	return 0;
}