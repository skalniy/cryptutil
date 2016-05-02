#pragma once
#include <vector>

typedef char byte;
typedef std::vector<byte> TKey;
typedef byte* (*crypto_algorithm)(const byte*, const size_t, const TKey&);
typedef void(*padding_algorithm)(byte *, const size_t, const size_t);