#include <sstream>
#include <fstream>
#include <iostream>
#include <time.h>
#include <string>
#include "cryptutil.h"
#include "Pattern.h"
#include <map>


using namespace std;


int main()
{
	map<string, Pattern> patterns;
	map<string, TChain> chains;

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
			cin >> patterns[name];
		} else if (cmd == "chain") {
			string name;
			cin >> name;
			string args;
			getline(cin, args);
			TChain chain;
			stringstream ss;
			ss << args;
			while (ss) {
				string arg;
				ss >> arg;
				if (arg != "")
					chain.push_back(arg);
			}
			chains[name] = chain;

		} else if (cmd == "erase") {
			string name;
			cin >> name;
			patterns.erase(name);
			chains.erase(name);

		} else if (patterns.count(cmd)) {
			string mode;
			string fin, fout;
			cin >> mode >> fin >> fout;
			
			if (mode == "d")
				patterns[cmd].decrypt(fin, fout);
			else if (mode == "e")
				patterns[cmd].encrypt(fin, fout);

		} else if (chains.count(cmd)) {
			string mode;
			string fin, fout, _fin, _fout;
			cin >> mode >> fin >> fout;
	
			_fin = fin;
			if (mode == "e") {
				for (TChain::iterator it = chains[cmd].begin(); it != chains[cmd].end(); it++) {
					srand((unsigned)time(NULL));
					_fout = to_string(rand());
					patterns[*it].encrypt(_fin, _fout);
					_fin = _fout;
				}
				rename(_fout.c_str(), fout.c_str());
			} else if (mode == "d") {
				for (TChain::reverse_iterator it = chains[cmd].rbegin(); it != chains[cmd].rend(); it++) {
					srand((unsigned)time(NULL));
					_fout = to_string(rand());
					patterns[*it].decrypt(_fin, _fout);
					_fin = _fout;
				}
				rename(_fout.c_str(), fout.c_str());
			}

		} else	{
			cout << "unknown command" << endl;
		}
	} while (cmd != "quit");

	
	patterns.clear();
	return 0;
}