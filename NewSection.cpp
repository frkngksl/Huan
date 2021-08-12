#pragma once
#include <Windows.h>
#include <iostream>
#include <winnt.h>
#include "Crypto.h"

//IMAGE_NT_HEADERS --> PE Signature + PE Header + PE Optional Header structure --> https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32
#define ntHeaders(imageBase) ((IMAGE_NT_HEADERS *)((size_t)imageBase + ((IMAGE_DOS_HEADER *)imageBase)->e_lfanew))
//Section headers are located sequentially right after the optional header in the PE file format. Each section header is 40 bytes with no padding between them. Section headers are defined as in the following structure
#define sectionHeaderArrays(imageBase) ((IMAGE_SECTION_HEADER *)((size_t)ntHeaders(imageBase) + sizeof(IMAGE_NT_HEADERS)))

#define P2ALIGNUP(size, align) ((((size) / (align)) + 1) * (align))



char* readBinary(const char* fileName,size_t *givenFileSize) {
	FILE* fileHandler = fopen(fileName, "rb+");
	char* binaryContent = NULL;
	size_t fileSize = 0;
	if (fileHandler) {
		//Move cursor to the end of executable
		fseek(fileHandler, 0, SEEK_END);
		fileSize = ftell(fileHandler);
		binaryContent = new char[fileSize+1];
		//Move cursor to the beginning
		fseek(fileHandler, 0, SEEK_SET);
		fread(binaryContent, sizeof(char), fileSize, fileHandler);
		fclose(fileHandler);
	}
	*givenFileSize = fileSize;
	return binaryContent;
}

bool saveNewPE(char* newFile, size_t lengthOfFile, const char* fileName) {
	ntHeaders(newFile)->OptionalHeader.SizeOfImage =
		sectionHeaderArrays(newFile)[ntHeaders(newFile)->FileHeader.NumberOfSections - 1].VirtualAddress +
		sectionHeaderArrays(newFile)[ntHeaders(newFile)->FileHeader.NumberOfSections - 1].Misc.VirtualSize;

	ntHeaders(newFile)->OptionalHeader.DllCharacteristics = 0x8160;
	FILE* fileHandler = fopen(fileName, "wb");
	if (fileHandler) {
		fwrite(newFile, 1, lengthOfFile, fileHandler);
		fclose(fileHandler);
		return true;
	}
	else {
		std::cout << "[!] Error on writing new content" << std::endl;
		return false;
	}
	
}

char * createNewSectionHeader(char* imageBase, unsigned char* packedContent, size_t packedLength, size_t* newFileSize){
	IMAGE_NT_HEADERS* ntHeaderOfImage = ntHeaders(imageBase);
	IMAGE_SECTION_HEADER* sectionHeaderArray = sectionHeaderArrays(imageBase);
	int numberOfSections = ntHeaderOfImage->FileHeader.NumberOfSections;
	//Area after the last section in disk
	size_t newSectionOffset = sectionHeaderArray[numberOfSections - 1].PointerToRawData + sectionHeaderArray[numberOfSections - 1].SizeOfRawData;
	//Area after the last element in the section header array
	IMAGE_SECTION_HEADER* newSectionHeader = &sectionHeaderArray[numberOfSections];
	
	//check the section header boundary with the first section --> Does new section header (get offset) overwrite the first section (.text section)?
	bool checkBoundary = ((char *) newSectionHeader + sizeof(IMAGE_SECTION_HEADER) - imageBase) < sectionHeaderArray[0].PointerToRawData;
	if (checkBoundary) {
		unsigned char keyBuffer[KEYSIZE] = { 0x00 };
		unsigned char IVBuffer[16] = { 0x00 };
		unsigned char* newBuffer;
		size_t paddedLength;
		size_t totalLengthForSection = 0;
		if (packedLength % 16) {
			newBuffer = paddingForInput(packedContent, packedLength);
			paddedLength = (packedLength / 16 + 1) * 16;
		}
		else {
			newBuffer = packedContent;
			paddedLength = packedLength;
		}
		encryptData(newBuffer, paddedLength, keyBuffer, IVBuffer);
		std::cout << "[+] Given exe is encrypted!" << std::endl;
		printf("[+] Symmetric Key: ");
		for (int i = 0; i < KEYSIZE; i++) {
			printf(" 0x%02x", keyBuffer[i]);
		}
		printf("\n");
		printf("[+] IV Key: ");
		for (int i = 0; i < 16; i++) {
			printf(" 0x%02x", IVBuffer[i]);
		}
		printf("\n");
		//We are safe
		memcpy(newSectionHeader->Name, ".huan", IMAGE_SIZEOF_SHORT_NAME);
		//KEY + IV + Encrypted Content + int size for original length + int size for encrypted length
		totalLengthForSection = KEYSIZE + 16 + paddedLength + 4 + 4;
		//In memory, sections should be multiple of page size, this alignment variable arranges this alignment.
		newSectionHeader->VirtualAddress = P2ALIGNUP(
			sectionHeaderArray[numberOfSections - 1].VirtualAddress + sectionHeaderArray[numberOfSections - 1].Misc.VirtualSize,
			ntHeaderOfImage->OptionalHeader.SectionAlignment
		);
		//File alignment for PE File, same alignment problem but this is for disk
		newSectionHeader->SizeOfRawData = P2ALIGNUP(totalLengthForSection, ntHeaderOfImage->OptionalHeader.FileAlignment);
		//Section alignment for memory
		newSectionHeader->Misc.VirtualSize = P2ALIGNUP((totalLengthForSection), ntHeaderOfImage->OptionalHeader.SectionAlignment);
		newSectionHeader->Characteristics = 0x40000040;
		//Offset for file
		newSectionHeader->PointerToRawData = newSectionOffset;
		// Section Alignment trick and put correct address wrt last section
		ntHeaderOfImage->FileHeader.NumberOfSections += 1;
		//Now it has new section size
		*newFileSize = P2ALIGNUP(totalLengthForSection, ntHeaderOfImage->OptionalHeader.FileAlignment);
		//New Section Offset is actually end of the file
		char* newExeBuffer = new char[newSectionOffset + *newFileSize];
		memcpy(newExeBuffer, imageBase, newSectionOffset);
		//New Section contains 4 byte original length + 4 byte encrypted length + 16 byte Key + 16 byte IV + encrypted data
		int* originalLength =(int *) (newExeBuffer + newSectionOffset);
		int* encryptedLength = (int*)(newExeBuffer + newSectionOffset+4);
		memcpy(newExeBuffer + newSectionOffset + 8, keyBuffer, 16);
		memcpy(newExeBuffer + newSectionOffset + 8 + 16, IVBuffer, 16);
		memcpy(newExeBuffer + newSectionOffset + 8 + 16 + 16, newBuffer, paddedLength);
		*originalLength = packedLength;
		*encryptedLength = paddedLength;
		*newFileSize += newSectionOffset;
		return newExeBuffer;
	}
	else {
		std::cout << "[!] Section Header Problem" << std::endl;
		//TODO: Is there a way to fix this boundary problem?
		return NULL;
	}
}