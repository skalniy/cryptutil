#pragma once
#include "cryptutil.h"
#include "cipher_modes.h"


template <class TCipher>
crypto_algorithm get_encrypt_algorithm(OperationMode::modes mode) {

	switch (mode)
	{
	case OperationMode::ECB:
		return TCipher::encrypt;
	case OperationMode::CFB:
		return TCipher::encrypt;
	case OperationMode::OFB:
		return TCipher::encrypt;
	case OperationMode::CBC:
		return TCipher::encrypt;
	}
}


template <class TCipher>
crypto_algorithm get_decrypt_algorithm(OperationMode::modes mode) {

	switch (mode)
	{
	case OperationMode::ECB:
		return TCipher::decrypt;
	case OperationMode::CFB:
		return TCipher::encrypt;
	case OperationMode::OFB:
		return TCipher::encrypt;
	case OperationMode::CBC:
		return TCipher::decrypt;
	}
}
