#include <fstream>
#include <iostream>
#include <string>
#include "cryptutil.h"
#include "cipher_modes.h"
#include "ciphers.h"
#include "padding_modes.h"
#include "Pattern.h"
#include <map>


using namespace std;


int main()
{
	TKey key;
	key.push_back(2);
	key.push_back(0);
	key.push_back(1);
	byte init_vector[] = { 'm', 'i', 'r', '\0' };

	Pattern& p = Pattern(
		"check", Cipher::algorithm::VIGENERE, 
		key, init_vector, 
		OperationMode::CBC, Padding::ISO10126);

	map<string, Pattern> patterns;
	patterns["check"] = p;
	string cmd;
	do
	{
		cin >> cmd;
		if (cmd == "dec") {
			ifstream ost("out.txt", ios::binary);
			ofstream d("dec.txt", ios::binary);  
			patterns["check"].decrypt(ost, d);
			ost.close();
			d.close();
		} else if (cmd == "enc") {
			/*int n;
			for (int i = 0; i < 9; i++) {
				cin >> n;
				key.push_back(n);
			}*/
			ifstream ist("in.txt", ios::binary);
			ofstream ost("out.txt", ios::binary);
			patterns["check"].encrypt(ist, ost);
			ost.close();
			ist.close();
		} else if (cmd == "print") {
			ofstream ost("data.txt", ios::app);
			ost << p;
			ost.close();
		} else if (cmd == "import") {
			string fname;
			cin >> fname;
			ifstream ist(fname);
			ist >> patterns[fname];
			ist.close();
		}
	} while (cmd != "quit");

	

	return 0;
}