#include <sstream>
#include <fstream>
#include <iostream>
#include <time.h>
#include <string>
#include "cryptutil.h"
#include "Pattern.h"
#include <map>



using namespace std;


map<string, Pattern> patterns;
map<string, TChain> chains;
enum States { OK, EXIT };


States cmdProc(istream& cmd_stream);


int main()
{
	string cmd;

	do {
		cout << "cryptutil > ";
	} while (cmdProc(cin) != EXIT);

	patterns.clear();
	chains.clear();
	return 0;
}


States cmdProc(istream& ist) try {
	string full_command;
	getline(ist, full_command);

	stringstream cmd_stream;
	cmd_stream << full_command;

	string cmd;
	cmd_stream >> cmd;

	if (cmd == "quit") {
		return EXIT;

	} else if (patterns.count(cmd)) {
		string mode;
		string ifname, ofname;
		cmd_stream >> mode;
		cmd_stream >> ifname >> ofname;

		if (mode == "e") patterns[cmd].encrypt(ifname, ofname);
		else if (mode == "d") patterns[cmd].decrypt(ifname, ofname);

	} else if (chains.count(cmd)) {
		string mode;
		string ifname, ofname, _ifname, _ofname;
		cmd_stream >> mode;
		cmd_stream >> ifname >> ofname;

		_ifname = ifname;
		if (mode == "e")
			for (TChain::iterator it = chains[cmd].begin(); it != chains[cmd].end(); it++) {
				srand((unsigned)time(NULL));
				_sleep(1000);
				_ofname = to_string(rand());
				patterns[*it].encrypt(_ifname, _ofname);
				if (_ifname != ifname)
					remove(_ifname.c_str());
				_ifname = _ofname;
			}
		else if (mode == "d")
			for (TChain::reverse_iterator it = chains[cmd].rbegin(); it != chains[cmd].rend(); it++) {
				srand((unsigned)time(NULL));
				_sleep(1000);
				_ofname = to_string(rand());
				patterns[*it].decrypt(_ifname, _ofname);
				if (_ifname != ifname)
					remove(_ifname.c_str());
				_ifname = _ofname;
			}
		rename(_ofname.c_str(), ofname.c_str());

	} else if (cmd == "create") {
		string name;
		cmd_stream >> name;
		cmd_stream >> patterns[name];

	} else if (cmd == "erase") {
		string name;
		cmd_stream >> name;
		patterns.erase(name);
		chains.erase(name);

	} else if (cmd == "chain") {
		TChain chain;
		string cname;
		string pname;
		cmd_stream >> cname;

		while (cmd_stream) {
			cmd_stream >> pname;
			if (pname != "")
				chain.push_back(pname);
		}
		chains[cname] = chain;

	} else if (cmd == "hist") {
		string name;
		cmd_stream >> name;
		patterns[name].show_history();

	} else if (cmd == "save") {
		string ofname;
		cmd_stream >> ofname;
		ofstream ost(ofname + ".crut");
		ost << patterns[ofname];
		ost.close();

	} else if (cmd == "import") {
		string ifname;
		cmd_stream >> ifname;
		ifstream ist(ifname + ".crut");
		if (!ist.good()) throw FileNotFound(ifname + ".crut");
		ist >> patterns[ifname];
		ist.close();

	} else if (cmd == "run") {
		string ifname;
		cmd_stream >> ifname;
		ifstream ist(ifname + ".crus");
		if (!ist.good()) throw FileNotFound(ifname + ".crus");
		int state = OK;
		while (!ist.eof()) {
			state = cmdProc(ist);
			if (state == EXIT) {
				ist.close();
				return EXIT;
			}
		}
		ist.close();

	} else {
		throw UnknownCommand(cmd);
	}

	return OK;
} catch (exception& e) {
	cerr << e.what() << endl;
}