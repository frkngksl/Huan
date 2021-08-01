#pragma once

#define KEYSIZE 16
void encryptData(unsigned char* dataBuffer, size_t dataLength, unsigned char* keyBuffer, unsigned char* IVBuffer);
void decryptData(unsigned char* dataBuffer, size_t dataLength, unsigned char* keyBuffer, unsigned char* IVBuffer);
unsigned char* paddingForInput(unsigned char* dataBuffer, size_t originalSize);