#pragma once

#include "cryptutil.h"


enum PaddingMode
{ PKCS7, ANSI_X923, ISO_10126 };


void pkcs7(byte *block, size_t block_size, size_t filled_blocks);


void ansi_x923(byte *block, size_t block_size, size_t filled_blocks);


void iso10126(byte *block, size_t block_size, size_t filled_blocks);