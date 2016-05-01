#pragma once

#include "cryptutil.h"



void pkcs7(byte *block, const size_t block_size, const size_t filled_blocks);


void ansi_x923(byte *block, const size_t block_size, const size_t filled_blocks);


void iso10126(byte *block, const size_t block_size, const size_t filled_blocks);