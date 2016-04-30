#include "cryptutil.h"
#include "padding_modes.h"


using namespace std;


int main()
{
	byte *test;
	test = (byte *) calloc(5, sizeof(byte));
	test[0] = 65;
	x923(test, 4, 1);

	string cmd;
	do
	{
		cin >> cmd;
	} while (cmd != "quit");
	return 0;
}