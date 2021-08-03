#include <Windows.h>
#include <winnt.h>
#include <iostream>
#include <stdio.h>
#include"../Crypto.h"

int main() {
	//Get image base address from struct offsets of PEB and TEB
	unsigned char encryptKey[16];
	unsigned char IVKey[16];
	int* originalDataLength;
	int* encryptedDataLength;
	unsigned char* encryptedContent;
	unsigned char* originalContent;
	char *TEBPtr = (char *) __readgsqword(0x30);
	char *PEBPtr = *((char **) (TEBPtr + 0x060));
	char* imageBaseAddress = *(char**)(PEBPtr+0x10);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBaseAddress;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)(imageBaseAddress + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER sectionHeadersCursor = (PIMAGE_SECTION_HEADER)(((PBYTE)imageNTHeaders) + sizeof(IMAGE_NT_HEADERS));
	BYTE buf[10];
	for (unsigned int i = 1; i <= imageNTHeaders->FileHeader.NumberOfSections; i++) {
		//std::cout << sectionHeadersCursor->Name << std::endl;
		if (strncmp((const char*)sectionHeadersCursor->Name, ".huan", 5) == 0) {
			std::cout << "Bulundu" << std::endl;
			break;
		}
		sectionHeadersCursor = (PIMAGE_SECTION_HEADER)((PBYTE)sectionHeadersCursor + 0x28);
	}
	char* sectionValuePtr = imageBaseAddress + sectionHeadersCursor->VirtualAddress;
	printf("%p\n", sectionValuePtr);
	//New Section contains 4 byte original length + 4 byte encrypted length + 16 byte Key + 16 byte IV + encrypted data
	originalDataLength = (int *) sectionValuePtr;
	encryptedDataLength = (int*)(sectionValuePtr + 4);
	memcpy(encryptKey,sectionValuePtr + 8, 16);
	memcpy(IVKey,sectionValuePtr + 24, 16);
	encryptedContent = (unsigned char*) malloc(*encryptedDataLength);
	originalContent = (unsigned char*)malloc(*originalDataLength);
	memcpy(encryptedContent, sectionValuePtr + 40, *encryptedDataLength);
	decryptData(encryptedContent, *encryptedDataLength, encryptKey, IVKey);
	memcpy(originalContent, encryptedContent, *originalDataLength);

	printf("Original Content: ");
	free(encryptedContent);
	for (int i = 0; i < *originalDataLength; i++) {
		printf(" %c", originalContent[i]);
	}
	printf("\n");
	return 0;
}