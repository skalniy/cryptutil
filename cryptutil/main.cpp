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

	map<string, Pattern> patterns;
	string cmd;
	do
	{
		cout << "cryptutil > ";
		cin >> cmd;

		if (cmd == "save") {
			string name;
			cin >> name;
			ofstream ost(name+".crut");
			ost << patterns[name];
			ost.close();

		} else if (cmd == "import") {
			string fname;
			cin >> fname;
			ifstream ist(fname + ".crut");
			ist >> patterns[fname];
			ist.close();
		} else if (cmd == "create") {
			string name;
			cin >> name;
			patterns.erase(name);

		} else if (cmd == "erase") {
			string name;
			cin >> name;
			patterns.erase(name);

		} else if (patterns.count(cmd)) {
			string mode, fin, fout;
			cin >> mode >> fin >> fout;
			
			if (mode == "d")
				patterns[cmd].decrypt(fin, fout);
			else if (mode == "e")
				patterns[cmd].encrypt(fin, fout);
		} else	{
			cout << "unknown command" << endl;
		}
	} while (cmd != "quit");

	
	patterns.clear();
	return 0;
}