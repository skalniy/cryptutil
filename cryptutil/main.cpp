#include <iostream>
#include <string>
#include "cryptutil.h"
#include "ciphers.h"

using namespace std;


int main()
{
	string cmd;
	do
	{
		cin >> cmd;
	} while (cmd != "quit");
	return 0;
}