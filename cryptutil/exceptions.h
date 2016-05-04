#pragma once
#include <stdexcept>



using namespace std;


class UnknownCommand : public invalid_argument {
public:
	UnknownCommand(string cmd) : invalid_argument("unknown command: " + cmd) {};
};


class FileNotFound : public invalid_argument {
public:
	FileNotFound(string fname) : invalid_argument("file not found: " + fname) {};
};


class InvalidKeySize : public invalid_argument {
public:
	InvalidKeySize() : invalid_argument("invalid key size") {};
};