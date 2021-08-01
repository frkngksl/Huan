#include "aes.hpp"
#include "Crypto.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


void randomBytes(unsigned char* output, size_t length) {
	for (int i = 0; i < length; i++) {
		output[i] = rand() % 256;
	}
}

unsigned char *paddingForInput(unsigned char *dataBuffer, size_t originalSize) {
	int paddingLength = 16-originalSize % 16;
	unsigned char* newBuffer = (unsigned char*)malloc(originalSize + paddingLength);
	memcpy(newBuffer, dataBuffer, originalSize);
	memset(newBuffer + originalSize, 0x00, paddingLength);
	return newBuffer;
}

void encryptData(unsigned char *dataBuffer,size_t dataLength, unsigned char *keyBuffer, unsigned char *IVBuffer) {
	struct AES_ctx ctx;
	randomBytes(keyBuffer, KEYSIZE);
	randomBytes(IVBuffer, 16);
	AES_init_ctx_iv(&ctx, keyBuffer, IVBuffer);
	AES_CBC_encrypt_buffer(&ctx, dataBuffer, dataLength);
}

void decryptData(unsigned char *dataBuffer, size_t dataLength, unsigned char *keyBuffer, unsigned char *IVBuffer) {
	struct AES_ctx ctx;
	AES_init_ctx_iv(&ctx, keyBuffer, IVBuffer);
	AES_CBC_decrypt_buffer(&ctx, dataBuffer, dataLength);
}