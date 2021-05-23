#pragma once
#include <Windows.h>
#include <iostream>
#include <winnt.h>

//IMAGE_NT_HEADERS --> PE Signature + PE Header + PE Optional Header structure --> https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32
#define ntHeaders(imageBase) ((IMAGE_NT_HEADERS *)((size_t)imageBase + ((IMAGE_DOS_HEADER *)imageBase)->e_lfanew))
//Section headers are located sequentially right after the optional header in the PE file format. Each section header is 40 bytes with no padding between them. Section headers are defined as in the following structure
#define sectionHeaderArrays(imageBase) ((IMAGE_SECTION_HEADER *)((size_t)ntHeaders(imageBase) + sizeof(IMAGE_NT_HEADERS)))

#define P2ALIGNUP(size, align) ((((size) / (align)) + 1) * (align))



char* readBinary(char* fileName,size_t *givenFileSize) {
	FILE* fileHandler = fopen(fileName, "rb+");
	char* binaryContent = NULL;
	size_t fileSize = 0;
	if (fileHandler) {
		fseek(fileHandler, 0, SEEK_END);
		fileSize = ftell(fileHandler);
		//printf("%d\n", fileSize);
		binaryContent = new char[fileSize+1];
		fseek(fileHandler, 0, SEEK_SET);
		fread(binaryContent, sizeof(char), fileSize, fileHandler);
		fclose(fileHandler);
	}
	*givenFileSize = fileSize;
	return binaryContent;
}

/*
		BYTE    Name[IMAGE_SIZEOF_SHORT_NAME]; Done
	union { Not used
			DWORD   PhysicalAddress;
			DWORD   VirtualSize;
	} Misc;
	DWORD   VirtualAddress; Done
	DWORD   SizeOfRawData; Done
	DWORD   PointerToRawData; Done
	DWORD   PointerToRelocations;
	DWORD   PointerToLinenumbers;
	WORD    NumberOfRelocations;
	WORD    NumberOfLinenumbers;
	DWORD   Characteristics; Done
	PointerToRelocations, PointerToLinenumbers, NumberOfRelocations, NumberOfLinenumbers. None of these fi elds are used in the PE file format.
	*/

void saveNewPE(char* newFile, size_t lengthOfFile, const char* fileName) {
	ntHeaders(newFile)->OptionalHeader.SizeOfImage =
		sectionHeaderArrays(newFile)[ntHeaders(newFile)->FileHeader.NumberOfSections - 1].VirtualAddress +
		sectionHeaderArrays(newFile)[ntHeaders(newFile)->FileHeader.NumberOfSections - 1].Misc.VirtualSize;

	ntHeaders(newFile)->OptionalHeader.DllCharacteristics &= ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
	FILE* fileHandler = fopen(fileName, "wb");
	fwrite(newFile, 1, lengthOfFile, fileHandler);
	fclose(fileHandler);
}

char * createNewSectionHeader(char* imageBase,size_t stubSize,size_t *newFileSize) {
	IMAGE_NT_HEADERS* ntHeaderOfImage = ntHeaders(imageBase);
	IMAGE_SECTION_HEADER* sectionHeaderArray = sectionHeaderArrays(imageBase);
	int numberOfSections = ntHeaderOfImage->FileHeader.NumberOfSections;
	//Area after the last section
	size_t newSectionOffset = sectionHeaderArray[numberOfSections - 1].PointerToRawData + sectionHeaderArray[numberOfSections - 1].SizeOfRawData;
	//Area after the last element in the section header array
	IMAGE_SECTION_HEADER* newSectionHeader = &sectionHeaderArray[numberOfSections];
	
	//check the section header boundary with the first section --> Does new header (get offset) overwrite the first section?
	bool checkBoundary = ((char *) newSectionHeader - imageBase) < sectionHeaderArray[0].PointerToRawData;
	if (checkBoundary) {
		//We are safe
		memcpy(newSectionHeader->Name, ".huan", IMAGE_SIZEOF_SHORT_NAME);
		//For memory
		newSectionHeader->VirtualAddress = P2ALIGNUP(
			sectionHeaderArray[numberOfSections - 1].VirtualAddress + sectionHeaderArray[numberOfSections - 1].Misc.VirtualSize,
			ntHeaderOfImage->OptionalHeader.SectionAlignment
		);
		//File alignment for PE File
		newSectionHeader->SizeOfRawData = P2ALIGNUP(stubSize, ntHeaderOfImage->OptionalHeader.FileAlignment);
		//Section alignment for memory
		newSectionHeader->Misc.VirtualSize = P2ALIGNUP((stubSize), ntHeaderOfImage->OptionalHeader.SectionAlignment);
		newSectionHeader->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
		newSectionHeader->PointerToRawData = newSectionOffset;
		// Section Alignment trick and put correct address wrt last section
		ntHeaderOfImage->FileHeader.NumberOfSections += 1;
		*newFileSize = P2ALIGNUP(stubSize, ntHeaderOfImage->OptionalHeader.FileAlignment);
		char* newExeBuffer = new char[newSectionOffset + *newFileSize];
		memcpy(newExeBuffer, imageBase, newSectionOffset);
		memset(newExeBuffer + newSectionOffset, 0x90, stubSize);
		*newFileSize += newSectionOffset;
		return newExeBuffer;
	}
	else {
		//TODO: Is there a way to fix this boundary problem?
		return NULL;
	}
}