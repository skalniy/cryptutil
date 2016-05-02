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
		/*if (cmd == "dec") {
			ifstream ost("out.txt", ios::binary);
			ofstream d("dec.txt", ios::binary);  
			patterns["check"].decrypt(ost, d);
			ost.close();
			d.close();
		} else if (cmd == "enc") {
			ifstream ist("in.txt", ios::binary);
			ofstream ost("out.txt", ios::binary);
			patterns["check"].encrypt(ist, ost);
			ost.close();
			ist.close();*/

		if (cmd == "save") {
			string name;
			cin >> name;
			ofstream ost(name+".crut");
			ost << patterns[name];
			ost.close();

		} else if (cmd == "import") {
			string fname;
			cin >> fname;
			ifstream ist(fname+".crut");
			ist >> patterns[fname];
			ist.close();
		} else	{
			cout << "unknown command" << endl;
		}
	} while (cmd != "quit");

	
	patterns.clear();
	return 0;
}