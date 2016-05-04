#pragma once
#include <vector>
#include <list>
#include "exceptions.h"



using namespace std;


typedef char byte;
typedef vector<byte> TKey;
typedef byte* (*crypto_algorithm)(const byte *, const size_t, const TKey&);
typedef void (*padding_algorithm)(byte *, const size_t, const size_t);
typedef list<string> TChain;